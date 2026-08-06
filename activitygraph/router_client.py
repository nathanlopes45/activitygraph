"""Router-sourced device discovery: ask the router itself for its client list.

The router is the one device on the network guaranteed to know about every
other device -- it's the DHCP server, so it captured each client's
self-reported hostname (DHCP Option 12) at lease time, the same data its
own admin page shows you. active_resolver.py's live queries (reverse DNS /
mDNS / NBSTAT) can only ever reach devices willing to answer a direct
probe; this reaches everything with a current lease, including phones and
other devices that stay silent on those probes.

There's no protocol shared across router vendors for this (each admin UI
is its own proprietary login + API), so this module is a small plugin
interface: `RouterClient.get_devices()` returns a vendor-neutral list, and
`create_router_client()` picks an implementation by brand name. Only
"tplink" is implemented today; add another vendor by writing a class that
satisfies the same interface and registering it in `_BACKENDS`.

Credentials are always read from a local file the caller points at (see
load_router_credentials) -- never taken as a bare CLI argument (which
would leak into shell history and process listings) and never logged.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Protocol



@dataclass
class RouterDevice:
    ip: str
    mac: str
    hostname: Optional[str] = None


class RouterClient(Protocol):
    def get_devices(self) -> list[RouterDevice]: ...


class TPLinkRouterClient:
    """Wraps the `tplinkrouterc6u` library, which already implements the
    RSA/AES-encrypted login flow TP-Link's web admin uses and auto-detects
    the right client class for the specific model/firmware -- reimplementing
    that handshake here would be slow to get right and brittle across
    firmware versions, so we lean on a maintained library instead."""

    def __init__(self, host: str, username: str, password: str, timeout: int = 30) -> None:
        try:
            from tplinkrouterc6u import TplinkRouterProvider
        except ImportError as exc:
            raise ImportError(
                "--router-brand tplink requires the 'tplinkrouterc6u' package. "
                "Install it with: pip install tplinkrouterc6u"
            ) from exc
        self._router = TplinkRouterProvider.get_client(host, password, username, timeout=timeout)
        self._router.authorize()

    def get_devices(self) -> list[RouterDevice]:
        status = self._router.get_status()
        devices = []
        for device in status.devices:
            if not device.active or not device.ipaddr or not device.macaddr:
                continue
            devices.append(RouterDevice(ip=device.ipaddr, mac=device.macaddr, hostname=device.hostname or None))
        return devices

    def close(self) -> None:
        self._router.logout()


_BACKENDS = {
    "tplink": TPLinkRouterClient,
}


def create_router_client(brand: str, host: str, username: str, password: str) -> RouterClient:
    backend = _BACKENDS.get(brand.lower())
    if backend is None:
        supported = ", ".join(sorted(_BACKENDS))
        raise ValueError(f"Unsupported router brand '{brand}'. Supported: {supported}")
    return backend(host=host, username=username, password=password)


def _warn_if_world_readable(path: Path) -> None:
    """Warn if a credentials file is readable by other users, the way ssh
    complains about loose key permissions.

    This holds a plaintext router password, so on a shared machine lax
    permissions hand out control of the network. No-op on Windows, where the
    POSIX mode bits reported by stat() don't reflect the real ACLs.
    """
    if os.name != "posix":
        return
    try:
        mode = path.stat().st_mode
    except OSError:
        return
    if mode & 0o077:
        print(
            f"[activitygraph] Warning: {path} is readable by other users "
            f"(mode {mode & 0o777:03o}). It contains a plaintext router password. "
            f"Restrict it with: chmod 600 {path}"
        )


def load_router_credentials(path: str) -> Optional[dict]:
    """Load router login details from a local JSON file:
    {"brand": "tplink", "host": "192.168.1.1", "username": "admin", "password": "..."}

    Kept in its own file (like --device-aliases) rather than passed as CLI
    arguments, so the password never ends up in shell history or a process
    listing. Returns None (with a printed warning) if the file is missing,
    malformed, or missing a required key -- never crashes the pipeline over
    a config typo, and never echoes the file's contents in the warning.
    """
    resolved = Path(path).expanduser()
    _warn_if_world_readable(resolved)
    try:
        raw = json.loads(resolved.read_text())
    except FileNotFoundError:
        print(f"[activitygraph] Warning: --router-credentials file not found: {path}")
        return None
    except (json.JSONDecodeError, AttributeError, TypeError):
        print(f"[activitygraph] Warning: --router-credentials file is not valid JSON: {path}")
        return None

    missing = [key for key in ("brand", "host", "username", "password") if not raw.get(key)]
    if missing:
        print(f"[activitygraph] Warning: --router-credentials file is missing required key(s): {', '.join(missing)}")
        return None
    return raw


def ingest_router_devices(pipeline, credentials_path: str) -> None:
    """Pull the router's own client list (IP/MAC/hostname straight from its
    DHCP lease table) and feed each device through the same registration
    path as a passively-observed ARP reply. Any failure here (bad creds,
    unreachable router, unsupported model, library not installed) prints a
    warning and moves on -- device discovery this way is a bonus, not a
    prerequisite for the rest of the pipeline."""
    creds = load_router_credentials(credentials_path)
    if creds is None:
        return

    try:
        client = create_router_client(creds["brand"], creds["host"], creds["username"], creds["password"])
    except Exception as exc:
        # Covers everything from a config typo (unsupported brand) to a
        # wrong password or an unreachable router -- all equally "can't
        # use this device list, move on" from the pipeline's perspective.
        print(f"[activitygraph] Warning: could not create router client: {exc}", file=sys.stderr)
        return

    try:
        devices = client.get_devices()
    except Exception as exc:
        print(f"[activitygraph] Warning: could not fetch device list from router: {exc}", file=sys.stderr)
        return
    finally:
        close = getattr(client, "close", None)
        if close is not None:
            try:
                close()
            except Exception:
                pass

    for device in devices:
        # Names only, for the same reason as the DHCP lease table this reads
        # from: a router's client list includes devices that are not
        # currently connected, so treating each as a sighting would show
        # them as present. They appear once they send traffic.
        pipeline.devices.remember_name(device.mac, device.hostname, source="lease")
    print(f"[activitygraph] Router reported {len(devices)} device(s); "
          "names learned. Devices appear once they send traffic.")
