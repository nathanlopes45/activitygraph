"""A richer synthetic household for the interview demo.

`activitygraph.demo_source` fabricates a tiny 3-device / 20-second stream --
just enough to prove the pipeline runs. That is the right size for a smoke
test and the wrong size for a demo: everyone lands in "Ungrouped", the
History panel is empty, and the whole thing reads as a toy.

This module fabricates a believable evening on a *household* network -- seven
devices across three people plus a couple of shared devices, a few hours of
real-looking activity, and background chatter (DNS, NTP, OS updates, ad
beacons) so the "traffic nobody chose to generate" segregation is visible.

Nothing here changes the core package. It feeds packets into the exact same
`Pipeline` the live capture uses, so every number the demo shows is computed
by the real code, not hand-authored. That is the point: an interviewer can
watch a raw TLS ClientHello with SNI `youtube.com` turn into a categorised,
per-person block of time, and it is the shipping pipeline doing it.

Two consumers share the one schedule in this file:
  * the packet generator below (`generate`), which turns today's blocks into
    a Packet stream for a one-shot `Pipeline` run, and
  * `build_demo.seed_history`, which turns the same schedule -- jittered
    across the previous 30 days -- into History rows, so "today" looks like a
    typical day in a populated trend chart rather than an outlier.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Iterator, NamedTuple

from activitygraph.models import Packet

# --- People and their devices --------------------------------------------
#
# MAC prefixes are chosen from the bundled OUI table (oui_database.py) so the
# raw vendor lookup lands on a believable brand even before the alias is
# applied -- an Apple laptop reads "Apple", a Pixel reads "Google". The alias
# is what the dashboard shows; the vendor is what device identification found
# on its own, and both being right is part of the story.


class DeviceSpec(NamedTuple):
    ip: str
    mac: str
    alias: str
    group: str


DEVICES: list[DeviceSpec] = [
    DeviceSpec("192.168.1.21", "A4:5E:60:11:2A:01", "Alice's MacBook", "Alice"),
    DeviceSpec("192.168.1.22", "BC:92:6B:11:2A:02", "Alice's iPhone", "Alice"),
    DeviceSpec("192.168.1.31", "6C:59:97:22:3B:01", "Ben's Desktop", "Ben"),
    DeviceSpec("192.168.1.32", "F4:F5:E8:22:3B:02", "Ben's Pixel", "Ben"),
    DeviceSpec("192.168.1.41", "A4:C3:61:33:4C:01", "Chloe's Galaxy", "Chloe"),
    DeviceSpec("192.168.1.51", "F0:27:2D:44:5D:01", "Living Room TV", "Shared"),
    DeviceSpec("192.168.1.52", "18:A6:F7:44:5D:02", "Sonos Speaker", "Shared"),
]

# MAC -> friendly name, exactly what --device-aliases would load.
ALIASES: dict[str, str] = {d.mac: d.alias for d in DEVICES}

# Person -> their MACs, exactly what --device-groups would load. Shared
# devices (the TV, the speaker) are a "group" of their own so the dashboard
# can show household viewing without attributing it to one person.
GROUPS: dict[str, list[str]] = {}
for _d in DEVICES:
    GROUPS.setdefault(_d.group, []).append(_d.mac)

# Category -> subcategory -> services, exactly what --taxonomy would load.
# Splits the flat "Entertainment" bucket into Music vs Video, which is the
# difference between "two hours of entertainment" and "an hour of background
# music while studying, then a film".
TAXONOMY: dict[str, dict[str, list[str]]] = {
    "Entertainment": {
        "Music": ["Spotify", "YouTube Music", "SoundCloud"],
        "Video": ["YouTube", "Netflix", "Disney+", "Prime Video", "Twitch", "Hulu", "Max"],
    },
    "Social Media": {
        "Feeds": ["Instagram", "Facebook", "TikTok", "X (Twitter)", "Snapchat"],
        "Forums": ["Reddit"],
    },
    "Study": {
        "Coursework": ["Canvas LMS", "University Portal", "Overleaf", "Turnitin"],
        "Reference": ["Wikipedia", "Google Scholar"],
        "Courses": ["Coursera", "Khan Academy", "edX"],
    },
}

# Each hostname's pretend public address. Any address off the local /24 does;
# service detection keys on the SNI/DNS name, not the IP. Distinct addresses
# per host just keep the flow table (and the "Stats for Nerds" view) honest.
_DST_IP: dict[str, str] = {
    "canvas.instructure.com": "52.63.100.10",
    "docs.google.com": "142.250.66.14",
    "www.overleaf.com": "104.18.20.50",
    "en.wikipedia.org": "103.102.166.224",
    "mail.google.com": "142.250.66.21",
    "app.slack.com": "3.89.11.201",
    "github.com": "140.82.112.3",
    "stackoverflow.com": "151.101.1.69",
    "leetcode.com": "104.16.100.20",
    "www.youtube.com": "142.250.66.238",
    "rr3---sn-video.googlevideo.com": "173.194.55.104",
    "www.netflix.com": "54.155.178.5",
    "ipv4-c001.nflxvideo.net": "45.57.40.10",
    "www.primevideo.com": "13.35.90.7",
    "www.disneyplus.com": "23.46.60.9",
    "open.spotify.com": "35.186.224.25",
    "audio-fa.scdn.co": "104.199.65.9",
    "music.youtube.com": "142.250.66.206",
    "www.instagram.com": "157.240.8.174",
    "www.tiktok.com": "23.62.100.50",
    "www.reddit.com": "151.101.65.140",
    "www.snapchat.com": "35.190.20.30",
    "x.com": "104.244.42.129",
    "web.whatsapp.com": "157.240.8.60",
    "discord.com": "162.159.128.233",
    "store.steampowered.com": "23.55.90.100",
    "steamcontent.com": "23.55.90.140",
    "www.roblox.com": "128.116.115.10",
    "www.bbc.com": "151.101.0.81",
    "www.theguardian.com": "151.101.65.111",
    "www.amazon.com.au": "54.240.193.20",
    "chatgpt.com": "104.18.32.115",
    # Background / infrastructure destinations
    "pool.ntp.org": "162.159.200.1",
    "www.msftconnecttest.com": "13.107.4.52",
    "swcdn.apple.com": "17.253.21.204",
    "doubleclick.net": "142.250.66.34",
}


class Block(NamedTuple):
    """One run of activity: a device talking to one service for a while.

    `start_ago` / `end_ago` are minutes before "now", so the whole evening is
    anchored to whenever the demo is run and nothing lands in the future.
    `packets` x `avg_bytes` sets the volume; the timestamps are stretched
    across the window so the flow's duration is the wall-clock time, not the
    packet spacing. Volumes are representative, not literal -- a real film is
    gigabytes -- but the *proportions* (video >> music > reading) are true,
    which is what the bars actually compare.
    """

    device_ip: str
    host: str
    start_ago: int  # minutes before now the activity begins
    end_ago: int    # minutes before now it ends (end_ago < start_ago)
    packets: int
    avg_bytes: int


# The canonical evening, newest activity last. Contiguous blocks on one device
# (gap < 5 min) fold into a single session in the Activity Graph; a longer gap
# starts a new one -- so Ben's morning of coding and his evening on Steam show
# as two sessions, not one. Alice's laptop study overlaps her phone's music on
# purpose: that overlap is what makes "30 min of your time, not 60 device-min"
# demonstrable on a real number.
SCHEDULE: list[Block] = [
    # -- Sonos: background music for the house --
    Block("192.168.1.52", "open.spotify.com", 360, 250, 260, 820),
    # -- Ben: a block of coding earlier on --
    Block("192.168.1.31", "github.com", 345, 300, 90, 900),
    Block("192.168.1.31", "stackoverflow.com", 300, 278, 70, 780),
    Block("192.168.1.31", "leetcode.com", 278, 250, 60, 820),
    # -- Alice: a study session on the laptop, music on the phone alongside --
    Block("192.168.1.22", "audio-fa.scdn.co", 250, 178, 240, 800),   # phone: Spotify
    Block("192.168.1.21", "canvas.instructure.com", 248, 224, 120, 860),
    Block("192.168.1.21", "docs.google.com", 224, 205, 80, 640),
    Block("192.168.1.21", "www.overleaf.com", 205, 186, 70, 700),
    Block("192.168.1.21", "en.wikipedia.org", 186, 172, 40, 520),
    # -- Chloe: after-school video, then scrolling --
    Block("192.168.1.41", "rr3---sn-video.googlevideo.com", 212, 150, 2600, 1500),  # YouTube
    Block("192.168.1.41", "www.tiktok.com", 150, 128, 260, 900),
    # -- Living room TV: a film through the evening --
    Block("192.168.1.51", "ipv4-c001.nflxvideo.net", 170, 62, 4200, 1500),  # Netflix
    # -- Alice: an evening scroll on the phone --
    Block("192.168.1.22", "www.instagram.com", 120, 101, 150, 880),
    Block("192.168.1.22", "www.reddit.com", 101, 90, 90, 760),
    # -- Ben: messaging on the phone --
    Block("192.168.1.32", "web.whatsapp.com", 130, 119, 60, 420),
    Block("192.168.1.32", "discord.com", 119, 101, 120, 560),
    # -- Alice: catching up on mail/work --
    Block("192.168.1.21", "mail.google.com", 96, 89, 30, 460),
    Block("192.168.1.21", "app.slack.com", 89, 80, 45, 540),
    # -- Chloe: messaging --
    Block("192.168.1.41", "www.snapchat.com", 82, 66, 70, 620),
    # -- Ben: an evening of gaming --
    Block("192.168.1.31", "steamcontent.com", 70, 12, 3200, 1460),  # Steam
    # -- Chloe: settles into a show --
    Block("192.168.1.41", "www.netflix.com", 60, 16, 1900, 1480),
    # -- Living room TV: switches to Prime --
    Block("192.168.1.51", "www.primevideo.com", 55, 8, 2600, 1500),
    # -- Ben: a look at the news --
    Block("192.168.1.32", "www.bbc.com", 40, 32, 55, 700),
    # -- Alice: a question for the assistant, then some shopping --
    Block("192.168.1.22", "chatgpt.com", 30, 22, 40, 620),
    Block("192.168.1.21", "www.amazon.com.au", 20, 12, 60, 820),
]

# Background chatter: real traffic nobody chose to generate. Each lands in a
# System/Infrastructure/Ads category, so it is kept out of the headline "where
# did the time go" panels and reported separately instead. Included so that
# segregation is visible rather than theoretical.
BACKGROUND: list[Block] = [
    Block("192.168.1.21", "swcdn.apple.com", 300, 298, 20, 1400),        # macOS update check
    Block("192.168.1.31", "www.msftconnecttest.com", 200, 199, 4, 300),  # Windows connectivity
    Block("192.168.1.32", "pool.ntp.org", 160, 160, 2, 90),              # clock sync
    Block("192.168.1.41", "doubleclick.net", 149, 148, 12, 400),         # ad beacon on a page
    Block("192.168.1.51", "swcdn.apple.com", 90, 89, 8, 1200),
]


def _mac_for(ip: str) -> str:
    for d in DEVICES:
        if d.ip == ip:
            return d.mac
    raise KeyError(ip)


def _emit_block(block: Block, now: datetime, rng: random.Random) -> Iterator[Packet]:
    """One block -> a DNS lookup and a single TCP flow carrying its SNI.

    The flow is one 5-tuple (fixed source port), so the Flow Processor keeps
    it as one flow and its start/end become the block's real time window. The
    SNI rides only the first packet, exactly as a TLS ClientHello does; the
    Service Detector caches domain->IP from the DNS answer so the reply
    direction would resolve too.
    """
    device_mac = _mac_for(block.device_ip)
    dst_ip = _DST_IP[block.host]
    start = now - timedelta(minutes=block.start_ago)
    end = now - timedelta(minutes=block.end_ago)
    span = (end - start).total_seconds()

    # DNS query + answer just before the connection opens.
    q_port = rng.randint(40000, 60000)
    yield Packet(timestamp=start - timedelta(seconds=1), src_ip=block.device_ip,
                 dst_ip="192.168.1.1", proto="UDP", length=74, src_port=q_port,
                 dst_port=53, src_mac=device_mac, dns_query=block.host)
    yield Packet(timestamp=start - timedelta(milliseconds=700), src_ip="192.168.1.1",
                 dst_ip=block.device_ip, proto="UDP", length=90, src_port=53,
                 dst_port=q_port, dns_query=block.host, dns_answers=[dst_ip])

    # The TCP flow itself: one fixed 5-tuple, timestamps stretched across the
    # window so duration reflects wall-clock time rather than packet spacing.
    sport = rng.randint(40000, 60000)
    n = max(1, block.packets)
    for i in range(n):
        frac = i / n
        ts = start + timedelta(seconds=span * frac)
        length = max(64, int(rng.gauss(block.avg_bytes, block.avg_bytes * 0.18)))
        yield Packet(timestamp=ts, src_ip=block.device_ip, dst_ip=dst_ip, proto="TCP",
                     length=length, src_port=sport, dst_port=443, src_mac=device_mac,
                     tls_sni=block.host if i == 0 else None)


def generate(now: datetime | None = None, seed: int = 7) -> Iterator[Packet]:
    """The full demo packet stream for "today".

    Deterministic given `seed`, so the dashboard looks the same every run
    (an interview is not the place for a demo that reshuffles itself). ARP
    first, so every device is identified with a vendor before its traffic
    arrives, then the scheduled activity and background chatter in time order.
    """
    now = now or datetime.now(timezone.utc)
    rng = random.Random(seed)

    # 1. ARP announce for each device, a few minutes before anything else, so
    #    device identification (IP<->MAC<->vendor) has run first.
    base = now - timedelta(minutes=370)
    for d in DEVICES:
        yield Packet(timestamp=base, src_ip=d.ip, dst_ip="192.168.1.1", proto="ARP",
                     length=42, src_mac=d.mac, arp_sender_ip=d.ip, arp_sender_mac=d.mac)
        base += timedelta(seconds=rng.uniform(0.2, 1.2))

    # 2. All activity, foreground and background, in timestamp order.
    packets: list[Packet] = []
    for block in SCHEDULE + BACKGROUND:
        packets.extend(_emit_block(block, now, rng))
    packets.sort(key=lambda p: p.timestamp)
    yield from packets
