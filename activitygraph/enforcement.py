"""Turning a group's blacklist into firewall rules on the gateway.

This is the only module that changes how the network behaves rather than
merely observing it, so it is built to be careful about three things.

**It owns one table and nothing else.** Everything lives in a table called
`activitygraph`, separate from the `filter` and `nat` tables the setup guide
creates. Rules are replaced by deleting that table and rebuilding it in a
single `nft` invocation, which nftables applies atomically: there is no
moment where half a ruleset is live. Nothing this module emits can affect a
rule it did not write.

**It fails open.** A monitoring tool that accidentally blocks the household
is worse than one that fails to block a distraction, so every error path
removes the table rather than leaving whatever was managed to get applied.

**It only drops forwarded traffic.** Packets addressed to the Pi itself are
never matched, so the dashboard, DNS and SSH stay reachable from a device
whose group is blocking half the internet. Locking someone out of the
machine that is doing the blocking would make it impossible to undo.

Destination addresses come from the DNS cache the detector already keeps.
The Pi is the resolver, so it learns "tiktok.com is 1.2.3.4" as devices ask,
and blocking by address rather than by name is what allows a rule to apply
to one group's devices rather than to everyone: DNS answers are shared, but
a forwarding rule can name a source.
"""
from __future__ import annotations

import subprocess
from typing import Iterable, Optional

TABLE = "activitygraph"

# A domain resolves to many addresses and they change, so a set is refreshed
# rather than rebuilt rule by rule. Beyond this size the rendering is capped:
# a runaway list should degrade, not produce a ruleset that takes seconds to
# load on every refresh.
MAX_ADDRESSES_PER_GROUP = 4096


def addresses_for_patterns(patterns: Iterable[str], dns_cache: dict,
                           whole_service: bool = False) -> list[str]:
    """Every learned address belonging to one of these domains.

    Matches a domain and its subdomains, so blocking "tiktok.com" also
    covers the CDN hosts under it.

    `whole_service` additionally covers the other domains the same service
    uses, which is what a blacklist means and a daily limit does not. A
    phone app does not visit a website: the YouTube app fetches video from
    googlevideo.com and never touches youtube.com at all, so blocking the
    domain someone typed leaves the app working and the block looking
    broken. Somebody who blocks YouTube outright means all of it. A limit
    stays narrow, because there the point is to stop the front door while
    leaving a video embedded in an article alone.
    """
    from .accounts import SERVICE_PREFIX
    from .service_rules import classify_domain

    wanted, services = set(), set()
    for raw in patterns or []:
        text = (raw or "").strip()
        if not text:
            continue
        # "service:YouTube" is what somebody meant when they said YouTube:
        # the app, the site, and whatever host the video comes from.
        if text.lower().startswith(SERVICE_PREFIX):
            services.add(text[len(SERVICE_PREFIX):])
        else:
            wanted.add(text.lower().lstrip("."))

    if whole_service:
        for domain in wanted:
            match = classify_domain(domain)
            if match:
                services.add(match.service)

    if not wanted and not services:
        return []

    found = []
    for address, hostname in dns_cache.items():
        name = (hostname or "").strip().lower().rstrip(".")
        if not name:
            continue
        hit = any(name == w or name.endswith("." + w) for w in wanted)
        if not hit and services:
            match = classify_domain(name)
            hit = match is not None and match.service in services
        if hit and address not in found:
            found.append(address)
    return sorted(found)


def _is_ipv4(address: str) -> bool:
    parts = address.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def render_ruleset(groups: Iterable[dict], device_addresses: dict,
                   dns_cache: dict) -> Optional[str]:
    """The complete nft script for every group's blacklist, or None.

    `groups` is what AccountStore.blocked_by_group returns; `device_addresses`
    maps a MAC to the addresses that device currently holds. Returns None
    when there is nothing to enforce, which the caller treats as "remove the
    table" rather than "apply an empty one".
    """
    blocks = []
    for group in groups:
        patterns = group.get("patterns") or []
        if not patterns and not group.get("quota_patterns"):
            continue

        sources = []
        for mac in group.get("device_macs") or []:
            for address in device_addresses.get(mac.upper(), []):
                if _is_ipv4(address) and address not in sources:
                    sources.append(address)
        if not sources:
            continue  # a list with no devices to apply it to blocks nothing

        # A blacklist covers the whole service; a spent daily limit covers
        # only its front door, so the two are resolved separately and then
        # merged into one set.
        resolved = set(addresses_for_patterns(patterns, dns_cache, whole_service=True))
        resolved |= set(addresses_for_patterns(
            group.get("quota_patterns") or [], dns_cache, whole_service=False))
        destinations = sorted(a for a in resolved if _is_ipv4(a))[:MAX_ADDRESSES_PER_GROUP]
        if not destinations:
            continue  # nothing resolved yet; a rule with an empty set is noise

        blocks.append((group, sorted(sources), destinations))

    if not blocks:
        return None

    lines = [
        f"add table inet {TABLE}",
        f"delete table inet {TABLE}",       # replace wholesale, atomically
        f"add table inet {TABLE}",
        # Priority -10 puts this ahead of the accept-everything forward chain
        # from the setup guide, which would otherwise let the packet through
        # before this chain ever saw it.
        f"add chain inet {TABLE} forward "
        "{ type filter hook forward priority -10 ; policy accept ; }",
    ]
    for index, (group, sources, destinations) in enumerate(blocks):
        name = f"blocked{index}"
        lines.append(f"add set inet {TABLE} {name} {{ type ipv4_addr ; }}")
        lines.append(f"add element inet {TABLE} {name} {{ {', '.join(destinations)} }}")
        lines.append(
            f"add rule inet {TABLE} forward "
            f"ip saddr {{ {', '.join(sources)} }} ip daddr @{name} drop "
            f"comment \"{group.get('username', 'group')}\""
        )
    return "\n".join(lines) + "\n"


def apply_ruleset(script: Optional[str], runner=None) -> tuple:
    """Load a ruleset, or clear ours if there is nothing to enforce.

    Returns (applied, message). Any failure clears the table instead of
    leaving part of a ruleset live, because a half-applied blacklist is a
    network fault rather than a partial feature.
    """
    run = runner or _run_nft
    if script is None:
        return clear_ruleset(runner=run)

    ok, message = run(script)
    if ok:
        return True, message
    clear_ruleset(runner=run)
    return False, message


def clear_ruleset(runner=None) -> tuple:
    """Remove our table, leaving every other rule on the machine alone."""
    run = runner or _run_nft
    # `destroy` does not error when the table is absent; older nft needs the
    # delete form, so a failure here is expected and not worth reporting.
    ok, message = run(f"delete table inet {TABLE}\n")
    return (True, "cleared") if ok else (True, "nothing to clear")


def _run_nft(script: str) -> tuple:
    try:
        result = subprocess.run(["nft", "-f", "-"], input=script, text=True,
                                capture_output=True, timeout=15)
    except FileNotFoundError:
        return False, "nft is not installed"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    if result.returncode != 0:
        return False, (result.stderr or "").strip() or "nft rejected the ruleset"
    return True, "applied"


def exhausted_services(quotas: dict, used_seconds: dict) -> list:
    """Services whose daily allowance a group has spent.

    Kept separate from the blocking so the decision can be tested and shown
    without touching a firewall: the dashboard needs to say "48 of 60
    minutes" long before anything is dropped.
    """
    spent = []
    for service, allowed in (quotas or {}).items():
        if allowed > 0 and (used_seconds or {}).get(service, 0) >= allowed:
            spent.append(service)
    return sorted(spent)


def quota_patterns(services: Iterable[str]) -> list:
    """The domains to block for services that have run out of time.

    Only front doors, so a limit on watching YouTube does not break a video
    embedded in an article or a map on a shop's contact page. A service with
    no known front door contributes nothing rather than being blocked
    broadly: failing to enforce a limit is a much smaller harm than breaking
    a page nobody meant to restrict.
    """
    from .service_rules import blockable_domains

    patterns = []
    for service in services or []:
        for domain in blockable_domains(service):
            if domain not in patterns:
                patterns.append(domain)
    return sorted(patterns)
