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
    # --- Browsers and their background chatter ---
    # Every browser phones home constantly for extension manifests, safe
    # browsing lists and telemetry. It is not something anyone chose to do,
    # so it belongs with the other machine traffic rather than in a
    # behavioural category.
    (r"(^|\.)mozilla\.(org|net|com)$", "Firefox", "System"),
    (r"(^|\.)brave\.com$", "Brave", "System"),
    (r"(^|\.)brave\.software$", "Brave", "System"),
    (r"(^|\.)bravesoftware\.com$", "Brave", "System"),
    (r"(^|\.)chrome\.google\.com$", "Chrome", "System"),
    (r"(^|\.)clients[0-9]*\.google\.com$", "Chrome", "System"),
    (r"(^|\.)vivaldi\.(com|net)$", "Vivaldi", "System"),
    (r"(^|\.)opera\.com$", "Opera", "System"),
    (r"(^|\.)duckduckgo-owned\.com$", "DuckDuckGo", "Web Browsing"),

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
    # The embed-only domain. Absent until blocking embeds became the
    # intention, which also left it unclassified in the dashboard.
    (r"(^|\.)youtube-nocookie\.com$", "YouTube", "Entertainment"),
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

    # --- More of the long tail ---
    # Every one of these would otherwise land in the generic HTTPS bucket,
    # which is the difference between "you browsed the web for two hours"
    # and something a person can act on.
    (r"(^|\.)whatsapp\.net$", "WhatsApp", "Communication"),
    (r"(^|\.)googleusercontent\.com$", "Google Services", "Infrastructure"),
    (r"(^|\.)substack\.com$", "Substack", "Study"),
    (r"(^|\.)medium\.com$", "Medium", "Study"),
    (r"(^|\.)nytimes\.com$", "New York Times", "News"),
    (r"(^|\.)bbc\.(co\.uk|com)$", "BBC", "News"),
    (r"(^|\.)theguardian\.com$", "The Guardian", "News"),
    (r"(^|\.)abc\.net\.au$", "ABC News", "News"),
    (r"(^|\.)news\.com\.au$", "news.com.au", "News"),
    (r"(^|\.)smh\.com\.au$", "Sydney Morning Herald", "News"),
    (r"(^|\.)reuters\.com$", "Reuters", "News"),
    (r"(^|\.)booking\.com$", "Booking.com", "Travel"),
    (r"(^|\.)airbnb\.(com|com\.au)$", "Airbnb", "Travel"),
    (r"(^|\.)uber\.com$", "Uber", "Travel"),
    (r"(^|\.)maps\.google\.com$", "Google Maps", "Travel"),
    (r"(^|\.)tripadvisor\.com$", "Tripadvisor", "Travel"),
    (r"(^|\.)strava\.com$", "Strava", "Health"),
    (r"(^|\.)myfitnesspal\.com$", "MyFitnessPal", "Health"),
    (r"(^|\.)headspace\.com$", "Headspace", "Health"),
    (r"(^|\.)calm\.com$", "Calm", "Health"),

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
    # Apple fronts most of its services through Akamai, and the name that
    # survives is a hyphenated variant rather than apple.com itself. These
    # are reached after unwrapping the CDN suffix: see unwrap_cdn_hostname.
    (r"(^|\.)itunes-apple\.com", "Apple Services", "Infrastructure"),
    (r"(^|\.)apple-cloudkit\.com", "iCloud", "Productivity"),
    (r"(^|\.)apple-dns\.net", "Apple Services", "Infrastructure"),
    (r"(^|\.)cdn-apple\.com", "Apple Services", "Infrastructure"),
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

# Categories nobody chose to generate. DNS lookups, DHCP renewals, clock
# sync, OS and browser update checks, ad and analytics beacons: all real
# traffic, none of it something a person did. Left in the headline panels
# they crowd out the answer to "where did my time go" with plumbing, and
# DNS in particular appears on nearly every device because it precedes
# everything else. Reported separately rather than discarded.
BACKGROUND_CATEGORIES = frozenset({"Infrastructure", "System", "Ads and Tracking"})

# The services a person can put a limit or a block on, named by the host
# they would think of as the destination.
#
# This is a list of what is *offerable*, not of what gets blocked. Blocking
# covers the whole service, every host `classify_domain` attributes to it,
# including the ones an app streams from and the ones that serve it embedded
# in somebody else's page. An earlier version blocked only the entries here,
# to keep an embedded video playing, and the effect was that a limit did
# nothing a person could see: the app used the same hosts as the embed.
#
# Deliberately conservative: a service absent from here can never be blocked
# by a quota at all, because failing to enforce a limit is a much smaller
# harm than breaking something nobody meant to restrict.
PRIMARY_DOMAINS: dict[str, tuple] = {
    "YouTube": ("youtube.com", "m.youtube.com"),
    "YouTube Music": ("music.youtube.com",),
    "Google Maps": ("maps.google.com",),
    "Netflix": ("netflix.com",),
    "TikTok": ("tiktok.com",),
    "Instagram": ("instagram.com",),
    "Facebook": ("facebook.com",),
    "X (Twitter)": ("twitter.com", "x.com"),
    "Reddit": ("reddit.com",),
    "Twitch": ("twitch.tv",),
    "Snapchat": ("snapchat.com",),
    "Pinterest": ("pinterest.com",),
    "LinkedIn": ("linkedin.com",),
    "Spotify": ("open.spotify.com", "spotify.com"),
    "Steam": ("steamcommunity.com", "store.steampowered.com"),
    "Roblox": ("roblox.com",),
    "Amazon": ("amazon.com", "amazon.com.au"),
    "eBay": ("ebay.com", "ebay.com.au"),
}


def blockable_domains(service: str) -> tuple:
    """The front doors of a service, or () if it should never be blocked."""
    return PRIMARY_DOMAINS.get(service, ())

# Fallback classification purely by well-known port, used when there's no
# domain/SNI available at all (e.g. raw non-HTTP(S) traffic).
PORT_RULES: dict[int, tuple[str, str]] = {
    22: ("SSH", "Remote Access"),
    23: ("Telnet", "Remote Access"),
    25: ("SMTP", "Communication"),
    53: ("DNS", "Infrastructure"),
    67: ("DHCP", "Infrastructure"),
    68: ("DHCP", "Infrastructure"),
    # Named so the two fallbacks are distinguishable at a glance. Reaching
    # this rule at all means no hostname was recovered, which for plain HTTP
    # is unusual: the Host header is in the clear, so most requests are
    # identified by name and never land here.
    80: ("HTTP (unencrypted)", "Web Browsing"),
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
    8080: ("HTTP (unencrypted, alt port)", "Web Browsing"),
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


# Content delivery networks host other companies' sites inside their own
# domain, so the registrable domain is the CDN's and the name that means
# something is a label or two earlier:
#
#   amp-api-edge-cdn-lb.itunes-apple.com.akadns.net
#                       ^^^^^^^^^^^^^^^^ the part worth reading
#
# Strip the wrapper and the origin name is an ordinary hostname again.
CDN_WRAPPER_SUFFIXES = (
    ".akadns.net", ".akamai.net", ".akamaiedge.net", ".akamaized.net",
    ".akastat.net", ".edgekey.net", ".edgesuite.net", ".edgesuite-staging.net",
    ".cdn.cloudflare.net", ".fastly.net", ".llnwd.net", ".footprint.net",
    ".azureedge.net", ".cloudfront.net", ".b-cdn.net",
)


def unwrap_cdn_hostname(hostname: str) -> Optional[str]:
    """The origin hostname a CDN name wraps, or None if it wraps nothing."""
    lowered = hostname.lower().strip(".")
    for suffix in CDN_WRAPPER_SUFFIXES:
        if lowered.endswith(suffix) and len(lowered) > len(suffix):
            inner = lowered[: -len(suffix)]
            # Only interesting if a domain survives. "d1234.cloudfront.net"
            # unwraps to "d1234", which names nothing.
            return inner if "." in inner else None
    return None


def _match_rules(hostname: str) -> Optional[ServiceMatch]:
    for pattern, service, category in _COMPILED_DOMAIN_RULES:
        if pattern.search(hostname):
            return ServiceMatch(domain=hostname, service=service, category=category, confidence=1.0)
    return None


def classify_domain(hostname: Optional[str]) -> Optional[ServiceMatch]:
    """Match a hostname against the rules, unwrapping CDN names if needed.

    Four passes, narrowing each time: the hostname as given, its registrable
    domain, then both again with any CDN wrapper stripped. The last two are
    what turn an Akamai or CloudFront name back into the service a person
    would recognise.
    """
    if not hostname:
        return None

    match = _match_rules(hostname) or _match_rules(registrable_domain(hostname))
    if match:
        return match

    inner = unwrap_cdn_hostname(hostname)
    if inner:
        match = _match_rules(inner) or _match_rules(registrable_domain(inner))
        if match:
            # Report the name that was actually seen, not the unwrapped one,
            # so the flow can still be traced back to what crossed the wire.
            return ServiceMatch(domain=hostname, service=match.service,
                                category=match.category, confidence=0.9)
    return None


def classify_port(port: Optional[int]) -> Optional[ServiceMatch]:
    if port is None:
        return None
    hit = PORT_RULES.get(port)
    if not hit:
        return None
    service, category = hit
    return ServiceMatch(domain=None, service=service, category=category, confidence=0.4)
