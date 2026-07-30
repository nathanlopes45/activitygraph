"""Rule-based service & category detection.

This is the deterministic, fast first pass in the pipeline (Service Detection
in the architecture diagram) that runs *before* anything touches the local
LLM. Cheap regex/suffix matching handles the 90% of well-known traffic;
only the long tail of unrecognized domains needs to go to the AI classifier.
"""
from __future__ import annotations

import re
from typing import Optional

from .models import ServiceMatch

# Ordered from most specific to least specific. Each entry is
# (regex-matching-the-domain-suffix, service_name, category).
# Matching is done against the registrable domain (e.g. "example.edu.au"),
# so subdomains like "canvas.example.edu.au" match via suffix.
DOMAIN_RULES: list[tuple[str, str, str]] = [
    # --- Education ---
    (r"(^|\.)instructure\.com$", "Canvas LMS", "Study"),
    (r"\.edu\.au$", "University Portal", "Study"),
    (r"\.edu$", "Educational Institution", "Study"),
    (r"(^|\.)coursera\.org$", "Coursera", "Study"),
    (r"(^|\.)khanacademy\.org$", "Khan Academy", "Study"),

    # --- Productivity / Work ---
    (r"(^|\.)docs\.google\.com$", "Google Docs", "Productivity"),
    (r"(^|\.)drive\.google\.com$", "Google Drive", "Productivity"),
    (r"(^|\.)mail\.google\.com$", "Gmail", "Communication"),
    (r"(^|\.)gmail\.com$", "Gmail", "Communication"),
    (r"(^|\.)outlook\.(com|office\.com|office365\.com)$", "Outlook", "Communication"),
    (r"(^|\.)notion\.so$", "Notion", "Productivity"),
    (r"(^|\.)slack\.com$", "Slack", "Communication"),
    (r"(^|\.)zoom\.us$", "Zoom", "Communication"),
    (r"(^|\.)teams\.microsoft\.com$", "Microsoft Teams", "Communication"),
    (r"(^|\.)github\.com$", "GitHub", "Software Development"),
    (r"(^|\.)gitlab\.com$", "GitLab", "Software Development"),
    (r"(^|\.)stackoverflow\.com$", "Stack Overflow", "Software Development"),
    (r"(^|\.)atlassian\.net$", "Atlassian (Jira/Confluence)", "Productivity"),
    (r"(^|\.)dropbox\.com$", "Dropbox", "Productivity"),

    # --- Entertainment / Streaming ---
    # music.youtube.com must precede the general youtube.com rule: the
    # detector tries the full hostname before the registrable domain, so
    # listening and watching stay distinguishable (Music vs Video).
    (r"(^|\.)music\.youtube\.com$", "YouTube Music", "Entertainment"),
    (r"(^|\.)youtube\.com$", "YouTube", "Entertainment"),
    (r"(^|\.)youtubei\.googleapis\.com$", "YouTube", "Entertainment"),
    (r"(^|\.)netflix\.com$", "Netflix", "Entertainment"),
    (r"(^|\.)nflxvideo\.net$", "Netflix", "Entertainment"),
    (r"(^|\.)spotify\.com$", "Spotify", "Entertainment"),
    (r"(^|\.)twitch\.tv$", "Twitch", "Entertainment"),
    (r"(^|\.)disneyplus\.com$", "Disney+", "Entertainment"),
    (r"(^|\.)primevideo\.com$", "Prime Video", "Entertainment"),
    (r"(^|\.)steamcommunity\.com$", "Steam", "Gaming"),
    (r"(^|\.)steampowered\.com$", "Steam", "Gaming"),
    (r"(^|\.)epicgames\.com$", "Epic Games", "Gaming"),
    (r"(^|\.)xboxlive\.com$", "Xbox Live", "Gaming"),

    # --- Social ---
    (r"(^|\.)facebook\.com$", "Facebook", "Social Media"),
    (r"(^|\.)instagram\.com$", "Instagram", "Social Media"),
    (r"(^|\.)tiktok\.com$", "TikTok", "Social Media"),
    (r"(^|\.)twitter\.com$", "X (Twitter)", "Social Media"),
    (r"(^|\.)x\.com$", "X (Twitter)", "Social Media"),
    (r"(^|\.)reddit\.com$", "Reddit", "Social Media"),
    (r"(^|\.)linkedin\.com$", "LinkedIn", "Social Media"),
    (r"(^|\.)snapchat\.com$", "Snapchat", "Social Media"),
    (r"(^|\.)whatsapp\.com$", "WhatsApp", "Communication"),
    (r"(^|\.)messenger\.com$", "Messenger", "Communication"),
    (r"(^|\.)discord\.com$", "Discord", "Communication"),
    (r"(^|\.)discord\.gg$", "Discord", "Communication"),

    # --- Shopping ---
    (r"(^|\.)amazon\.(com|com\.au)$", "Amazon", "Shopping"),
    (r"(^|\.)ebay\.(com|com\.au)$", "eBay", "Shopping"),

    # --- Infra / General web ---
    (r"(^|\.)google\.com$", "Google Search", "Web Browsing"),
    (r"(^|\.)googleapis\.com$", "Google Services", "Infrastructure"),
    (r"(^|\.)gstatic\.com$", "Google Services", "Infrastructure"),
    (r"(^|\.)apple\.com$", "Apple Services", "Infrastructure"),
    (r"(^|\.)icloud\.com$", "iCloud", "Productivity"),
    (r"(^|\.)akamai(edge|hd)?\.net$", "CDN (Akamai)", "Infrastructure"),
    (r"(^|\.)cloudflare\.com$", "CDN (Cloudflare)", "Infrastructure"),
    (r"(^|\.)windowsupdate\.com$", "Windows Update", "System"),
    (r"(^|\.)ntp\.org$", "Time Sync (NTP)", "System"),
]

_COMPILED_DOMAIN_RULES = [(re.compile(pattern, re.IGNORECASE), svc, cat) for pattern, svc, cat in DOMAIN_RULES]

# Fallback classification purely by well-known port, used when there's no
# domain/SNI available at all (e.g. raw non-HTTP(S) traffic).
PORT_RULES: dict[int, tuple[str, str]] = {
    22: ("SSH", "Remote Access"),
    23: ("Telnet", "Remote Access"),
    25: ("SMTP", "Communication"),
    53: ("DNS", "Infrastructure"),
    67: ("DHCP", "Infrastructure"),
    68: ("DHCP", "Infrastructure"),
    80: ("HTTP", "Web Browsing"),
    123: ("NTP", "System"),
    143: ("IMAP", "Communication"),
    179: ("BGP", "Infrastructure"),
    194: ("IRC", "Communication"),
    443: ("HTTPS", "Web Browsing"),
    445: ("SMB", "File Sharing"),
    465: ("SMTPS", "Communication"),
    587: ("SMTP (Submission)", "Communication"),
    993: ("IMAPS", "Communication"),
    995: ("POP3S", "Communication"),
    1935: ("RTMP", "Entertainment"),
    3389: ("RDP", "Remote Access"),
    3478: ("STUN/TURN (VoIP)", "Communication"),
    5060: ("SIP (VoIP)", "Communication"),
    5222: ("XMPP", "Communication"),
    5353: ("mDNS", "Infrastructure"),
    8080: ("HTTP (alt)", "Web Browsing"),
    8443: ("HTTPS (alt)", "Web Browsing"),
}


def registrable_domain(hostname: str) -> str:
    """Very small heuristic to approximate the registrable domain.

    Not a full public-suffix-list implementation, but handles the common
    ccSLD cases (e.g. .edu.au, .co.uk) well enough for local classification.
    """
    labels = hostname.lower().strip(".").split(".")
    if len(labels) <= 2:
        return hostname.lower()
    two_part_suffixes = {"edu.au", "com.au", "gov.au", "org.au", "co.uk", "org.uk", "gov.uk", "ac.uk"}
    last_two = ".".join(labels[-2:])
    if last_two in two_part_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def classify_domain(hostname: Optional[str]) -> Optional[ServiceMatch]:
    if not hostname:
        return None
    for pattern, service, category in _COMPILED_DOMAIN_RULES:
        if pattern.search(hostname):
            return ServiceMatch(domain=hostname, service=service, category=category, confidence=1.0)
    return None


def classify_port(port: Optional[int]) -> Optional[ServiceMatch]:
    if port is None:
        return None
    hit = PORT_RULES.get(port)
    if not hit:
        return None
    service, category = hit
    return ServiceMatch(domain=None, service=service, category=category, confidence=0.4)
