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
    (r"(^|\.)edx\.org$", "edX", "Study"),
    (r"(^|\.)udemy\.com$", "Udemy", "Study"),
    (r"(^|\.)duolingo\.com$", "Duolingo", "Study"),
    (r"(^|\.)quizlet\.com$", "Quizlet", "Study"),
    (r"(^|\.)chegg\.com$", "Chegg", "Study"),
    (r"(^|\.)wikipedia\.org$", "Wikipedia", "Study"),
    (r"(^|\.)wikimedia\.org$", "Wikipedia", "Study"),
    (r"(^|\.)scholar\.google\.com$", "Google Scholar", "Study"),
    (r"(^|\.)overleaf\.com$", "Overleaf", "Study"),
    (r"(^|\.)turnitin\.com$", "Turnitin", "Study"),

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
    (r"(^|\.)onedrive\.(com|live\.com)$", "OneDrive", "Productivity"),
    (r"(^|\.)1drv\.(ms|com)$", "OneDrive", "Productivity"),
    (r"(^|\.)sharepoint\.com$", "SharePoint", "Productivity"),
    (r"(^|\.)office(365)?\.com$", "Microsoft 365", "Productivity"),
    (r"(^|\.)canva\.com$", "Canva", "Productivity"),
    (r"(^|\.)figma\.com$", "Figma", "Productivity"),
    (r"(^|\.)adobe\.(com|io)$", "Adobe", "Productivity"),
    (r"(^|\.)trello\.com$", "Trello", "Productivity"),
    (r"(^|\.)asana\.com$", "Asana", "Productivity"),
    (r"(^|\.)bitbucket\.org$", "Bitbucket", "Software Development"),
    (r"(^|\.)githubusercontent\.com$", "GitHub", "Software Development"),
    (r"(^|\.)npmjs\.(com|org)$", "npm", "Software Development"),
    (r"(^|\.)pypi\.org$", "PyPI", "Software Development"),
    (r"(^|\.)pythonhosted\.org$", "PyPI", "Software Development"),
    (r"(^|\.)docker\.(com|io)$", "Docker Hub", "Software Development"),
    (r"(^|\.)leetcode\.com$", "LeetCode", "Software Development"),
    (r"(^|\.)hackerrank\.com$", "HackerRank", "Software Development"),
    (r"(^|\.)kaggle\.com$", "Kaggle", "Software Development"),
    (r"(^|\.)readthedocs\.(io|org)$", "Read the Docs", "Software Development"),
    (r"(^|\.)mozilla\.(org|net)$", "Firefox", "System"),

    # --- Finance ---
    (r"(^|\.)paypal\.com$", "PayPal", "Finance"),
    (r"(^|\.)stripe\.com$", "Stripe", "Finance"),
    (r"(^|\.)commbank\.com\.au$", "Commonwealth Bank", "Finance"),
    (r"(^|\.)nab\.com\.au$", "NAB", "Finance"),
    (r"(^|\.)anz\.com(\.au)?$", "ANZ", "Finance"),
    (r"(^|\.)westpac\.com\.au$", "Westpac", "Finance"),

    # --- Entertainment / Streaming ---
    # music.youtube.com must precede the general youtube.com rule: the
    # detector tries the full hostname before the registrable domain, so
    # listening and watching stay distinguishable (Music vs Video).
    (r"(^|\.)music\.youtube\.com$", "YouTube Music", "Entertainment"),
    (r"(^|\.)youtube\.com$", "YouTube", "Entertainment"),
    (r"(^|\.)youtubei\.googleapis\.com$", "YouTube", "Entertainment"),
    # Almost all YouTube *bytes* arrive from googlevideo.com, not
    # youtube.com: the page is one request, the video is the rest of the
    # session. Without this rule the traffic that actually represents
    # watching time goes unrecognised.
    (r"(^|\.)googlevideo\.com$", "YouTube", "Entertainment"),
    (r"(^|\.)ytimg\.com$", "YouTube", "Entertainment"),
    (r"(^|\.)ggpht\.com$", "YouTube", "Entertainment"),
    (r"(^|\.)netflix\.com$", "Netflix", "Entertainment"),
    (r"(^|\.)nflxvideo\.net$", "Netflix", "Entertainment"),
    (r"(^|\.)nflxso\.net$", "Netflix", "Entertainment"),
    (r"(^|\.)nflximg\.net$", "Netflix", "Entertainment"),
    (r"(^|\.)spotify\.com$", "Spotify", "Entertainment"),
    (r"(^|\.)scdn\.co$", "Spotify", "Entertainment"),
    (r"(^|\.)spotifycdn\.com$", "Spotify", "Entertainment"),
    (r"(^|\.)twitch\.tv$", "Twitch", "Entertainment"),
    (r"(^|\.)ttvnw\.net$", "Twitch", "Entertainment"),
    (r"(^|\.)jtvnw\.net$", "Twitch", "Entertainment"),
    (r"(^|\.)disneyplus\.com$", "Disney+", "Entertainment"),
    (r"(^|\.)dssott\.com$", "Disney+", "Entertainment"),
    (r"(^|\.)primevideo\.com$", "Prime Video", "Entertainment"),
    (r"(^|\.)aiv-cdn\.net$", "Prime Video", "Entertainment"),
    (r"(^|\.)hulu\.com$", "Hulu", "Entertainment"),
    (r"(^|\.)(hbo)?max\.com$", "Max", "Entertainment"),
    (r"(^|\.)paramountplus\.com$", "Paramount+", "Entertainment"),
    (r"(^|\.)soundcloud\.com$", "SoundCloud", "Entertainment"),
    (r"(^|\.)pandora\.com$", "Pandora", "Entertainment"),
    (r"(^|\.)vimeo\.com$", "Vimeo", "Entertainment"),
    (r"(^|\.)steamcommunity\.com$", "Steam", "Gaming"),
    (r"(^|\.)steampowered\.com$", "Steam", "Gaming"),
    (r"(^|\.)steamstatic\.com$", "Steam", "Gaming"),
    (r"(^|\.)steamcontent\.com$", "Steam", "Gaming"),
    (r"(^|\.)epicgames\.com$", "Epic Games", "Gaming"),
    (r"(^|\.)xboxlive\.com$", "Xbox Live", "Gaming"),
    (r"(^|\.)playstation\.(net|com)$", "PlayStation Network", "Gaming"),
    (r"(^|\.)nintendo\.(net|com)$", "Nintendo", "Gaming"),
    (r"(^|\.)riotgames\.com$", "Riot Games", "Gaming"),
    (r"(^|\.)battle\.net$", "Battle.net", "Gaming"),
    (r"(^|\.)roblox\.com$", "Roblox", "Gaming"),
    (r"(^|\.)minecraft\.net$", "Minecraft", "Gaming"),

    # --- Social ---
    # Instagram's CDN sits under a Facebook-owned domain, so the more
    # specific Instagram patterns must come before the fbcdn catch-all
    # below or photo traffic would be filed as Facebook.
    (r"(^|\.)instagram\.com$", "Instagram", "Social Media"),
    (r"(^|\.)cdninstagram\.com$", "Instagram", "Social Media"),
    (r"(^|\.)facebook\.com$", "Facebook", "Social Media"),
    (r"(^|\.)facebook\.net$", "Facebook", "Social Media"),
    (r"(^|\.)fbcdn\.net$", "Facebook", "Social Media"),
    (r"(^|\.)tiktok\.com$", "TikTok", "Social Media"),
    (r"(^|\.)tiktokcdn(-us)?\.com$", "TikTok", "Social Media"),
    (r"(^|\.)byteoversea\.com$", "TikTok", "Social Media"),
    (r"(^|\.)twitter\.com$", "X (Twitter)", "Social Media"),
    (r"(^|\.)x\.com$", "X (Twitter)", "Social Media"),
    (r"(^|\.)twimg\.com$", "X (Twitter)", "Social Media"),
    (r"(^|\.)reddit\.com$", "Reddit", "Social Media"),
    (r"(^|\.)redd\.it$", "Reddit", "Social Media"),
    (r"(^|\.)redditstatic\.com$", "Reddit", "Social Media"),
    (r"(^|\.)redditmedia\.com$", "Reddit", "Social Media"),
    (r"(^|\.)linkedin\.com$", "LinkedIn", "Social Media"),
    (r"(^|\.)licdn\.com$", "LinkedIn", "Social Media"),
    (r"(^|\.)snapchat\.com$", "Snapchat", "Social Media"),
    (r"(^|\.)sc-cdn\.net$", "Snapchat", "Social Media"),
    (r"(^|\.)pinterest\.(com|ca)$", "Pinterest", "Social Media"),
    (r"(^|\.)pinimg\.com$", "Pinterest", "Social Media"),
    (r"(^|\.)tumblr\.com$", "Tumblr", "Social Media"),
    (r"(^|\.)whatsapp\.(com|net)$", "WhatsApp", "Communication"),
    (r"(^|\.)messenger\.com$", "Messenger", "Communication"),
    (r"(^|\.)discord\.(com|gg|media)$", "Discord", "Communication"),
    (r"(^|\.)discordapp\.(com|net)$", "Discord", "Communication"),
    (r"(^|\.)telegram\.org$", "Telegram", "Communication"),
    (r"(^|\.)signal\.org$", "Signal", "Communication"),
    (r"(^|\.)skype\.com$", "Skype", "Communication"),

    # --- AI assistants ---
    (r"(^|\.)openai\.com$", "ChatGPT", "AI Assistants"),
    (r"(^|\.)chatgpt\.com$", "ChatGPT", "AI Assistants"),
    (r"(^|\.)claude\.ai$", "Claude", "AI Assistants"),
    (r"(^|\.)anthropic\.com$", "Claude", "AI Assistants"),
    (r"(^|\.)gemini\.google\.com$", "Gemini", "AI Assistants"),
    (r"(^|\.)perplexity\.ai$", "Perplexity", "AI Assistants"),
    (r"(^|\.)copilot\.microsoft\.com$", "Microsoft Copilot", "AI Assistants"),

    # --- Shopping ---
    (r"(^|\.)amazon\.(com|com\.au|co\.uk)$", "Amazon", "Shopping"),
    (r"(^|\.)media-amazon\.com$", "Amazon", "Shopping"),
    (r"(^|\.)ebay\.(com|com\.au|co\.uk)$", "eBay", "Shopping"),
    (r"(^|\.)ebayimg\.com$", "eBay", "Shopping"),
    (r"(^|\.)aliexpress\.com$", "AliExpress", "Shopping"),
    (r"(^|\.)etsy\.com$", "Etsy", "Shopping"),
    (r"(^|\.)woolworths\.com\.au$", "Woolworths", "Shopping"),
    (r"(^|\.)coles\.com\.au$", "Coles", "Shopping"),

    # --- Ads and tracking ---
    # Broken out from general browsing because it is traffic nobody chose
    # to generate. Lumping it in inflates whichever site triggered it.
    (r"(^|\.)doubleclick\.net$", "Google Ads", "Ads and Tracking"),
    (r"(^|\.)googlesyndication\.com$", "Google Ads", "Ads and Tracking"),
    (r"(^|\.)googleadservices\.com$", "Google Ads", "Ads and Tracking"),
    (r"(^|\.)google-analytics\.com$", "Google Analytics", "Ads and Tracking"),
    (r"(^|\.)googletagmanager\.com$", "Google Tag Manager", "Ads and Tracking"),
    (r"(^|\.)scorecardresearch\.com$", "Analytics", "Ads and Tracking"),
    (r"(^|\.)adnxs\.com$", "AppNexus", "Ads and Tracking"),
    (r"(^|\.)criteo\.(com|net)$", "Criteo", "Ads and Tracking"),

    # --- Search engines ---
    (r"(^|\.)google\.(com|com\.au|co\.uk)$", "Google Search", "Web Browsing"),
    (r"(^|\.)bing\.com$", "Bing", "Web Browsing"),
    (r"(^|\.)duckduckgo\.com$", "DuckDuckGo", "Web Browsing"),
    (r"(^|\.)ecosia\.org$", "Ecosia", "Web Browsing"),

    # --- Infrastructure and OS background traffic ---
    # Everything below is machine-initiated: updates, telemetry, push
    # notifications, CDN edges. It is deliberately kept out of the
    # behavioural categories so it cannot be mistaken for time a person
    # chose to spend.
    (r"(^|\.)googleapis\.com$", "Google Services", "Infrastructure"),
    (r"(^|\.)gstatic\.com$", "Google Services", "Infrastructure"),
    (r"(^|\.)googleusercontent\.com$", "Google Services", "Infrastructure"),
    (r"(^|\.)gvt[12]\.com$", "Google Update", "System"),
    # Google's reverse-DNS domain. Only ever seen via a PTR lookup, and it
    # identifies the operator rather than the product, so it stays generic.
    (r"(^|\.)1e100\.net$", "Google (unidentified)", "Infrastructure"),
    (r"(^|\.)apple\.com$", "Apple Services", "Infrastructure"),
    (r"(^|\.)aaplimg\.com$", "Apple Services", "Infrastructure"),
    (r"(^|\.)mzstatic\.com$", "Apple Services", "Infrastructure"),
    (r"(^|\.)push\.apple\.com$", "Apple Push Notifications", "System"),
    (r"(^|\.)icloud\.com$", "iCloud", "Productivity"),
    (r"(^|\.)akamai(edge|hd|zed)?\.net$", "CDN (Akamai)", "Infrastructure"),
    (r"(^|\.)akamaitechnologies\.com$", "CDN (Akamai)", "Infrastructure"),
    (r"(^|\.)cloudflare\.(com|net)$", "CDN (Cloudflare)", "Infrastructure"),
    (r"(^|\.)cloudfront\.net$", "CDN (CloudFront)", "Infrastructure"),
    (r"(^|\.)fastly\.net$", "CDN (Fastly)", "Infrastructure"),
    (r"(^|\.)amazonaws\.com$", "Amazon Web Services", "Infrastructure"),
    (r"(^|\.)windowsupdate\.com$", "Windows Update", "System"),
    (r"(^|\.)msftconnecttest\.com$", "Windows Connectivity Check", "System"),
    (r"(^|\.)msedge\.net$", "Microsoft Services", "System"),
    (r"(^|\.)microsoft\.com$", "Microsoft Services", "System"),
    (r"(^|\.)ubuntu\.com$", "Ubuntu Updates", "System"),
    (r"(^|\.)debian\.org$", "Debian Updates", "System"),
    (r"(^|\.)raspberrypi\.(org|com)$", "Raspberry Pi OS", "System"),
    (r"(^|\.)ntp\.org$", "Time Sync (NTP)", "System"),
    (r"(^|\.)speedtest\.net$", "Speedtest", "System"),
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
