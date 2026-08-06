"""Three-level activity taxonomy: category -> subcategory -> service.

`service_rules.py` classifies a domain into two levels -- a service
("Spotify") and a category ("Entertainment"). That's enough to say *how much
Entertainment*, but not *what kind*: an hour of background music and an hour
of video both land in the same bucket, even though they mean very different
things about how the time was spent.

This module adds the missing middle level, so Entertainment splits into
Music (Spotify, YouTube Music) and Video (YouTube, Netflix), and Social Media
into Feeds, Forums and so on.

**Subcategory is derived, never stored.** Nothing in the pipeline writes a
subcategory onto a Flow or into the database -- it's looked up from the
service at the moment totals are computed. That's deliberate: it means when
you reorganize the taxonomy, the new grouping applies to *existing and
historical* data immediately, rather than only to traffic captured after the
change. Reorganizing is the point, so it has to be retroactive to be useful.

Defaults are a starting point, not a policy. `load_taxonomy` merges a user
file over them, and a user-defined category replaces that category's defaults
outright rather than merging into them -- if you've said how you want
Entertainment organized, an opinion of ours shouldn't leak back in.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

# Services not named anywhere land here, so a category's subcategory totals
# always add up to the category total.
OTHER = "Other"

# category -> subcategory -> [service names, exactly as service_rules emits them]
DEFAULT_SUBCATEGORIES: dict[str, dict[str, list[str]]] = {
    "Study": {
        "University": ["Canvas LMS", "University Portal", "Educational Institution",
                       "Turnitin", "Overleaf"],
        "Courses": ["Coursera", "Khan Academy", "edX", "Udemy", "Duolingo"],
        "Reference": ["Wikipedia", "Google Scholar", "Quizlet", "Chegg"],
        "Reading": ["Substack", "Medium"],
    },
    "Entertainment": {
        "Music": ["Spotify", "YouTube Music", "SoundCloud", "Pandora"],
        "Video": ["YouTube", "Netflix", "Disney+", "Prime Video", "Twitch",
                  "Hulu", "Max", "Paramount+", "Vimeo"],
    },
    "Social Media": {
        "Feeds": ["Instagram", "Facebook", "TikTok", "X (Twitter)", "Snapchat",
                  "Pinterest", "Tumblr"],
        "Forums": ["Reddit"],
        "Professional": ["LinkedIn"],
    },
    "Communication": {
        "Messaging": ["WhatsApp", "Messenger", "Discord", "Slack", "Telegram", "Signal"],
        "Email": ["Gmail", "Outlook"],
        "Meetings": ["Zoom", "Microsoft Teams", "Skype"],
    },
    "Productivity": {
        "Documents": ["Google Docs", "Notion", "Atlassian (Jira/Confluence)",
                      "Microsoft 365", "SharePoint", "Trello", "Asana"],
        "Storage": ["Google Drive", "Dropbox", "OneDrive", "iCloud"],
        "Design": ["Canva", "Figma", "Adobe"],
    },
    "Software Development": {
        "Code Hosting": ["GitHub", "GitLab", "Bitbucket"],
        "Reference": ["Stack Overflow", "Read the Docs"],
        "Packages": ["npm", "PyPI", "Docker Hub"],
        "Practice": ["LeetCode", "HackerRank", "Kaggle"],
    },
    "Gaming": {
        "Platforms": ["Steam", "Epic Games", "Xbox Live", "PlayStation Network",
                      "Nintendo", "Battle.net"],
        "Games": ["Riot Games", "Roblox", "Minecraft"],
    },
    "Shopping": {
        "Retail": ["Amazon", "eBay", "AliExpress", "Etsy"],
        "Groceries": ["Woolworths", "Coles"],
    },
    "AI Assistants": {
        "Chat": ["ChatGPT", "Claude", "Gemini", "Perplexity", "Microsoft Copilot"],
    },
    "Finance": {
        "Banking": ["Commonwealth Bank", "NAB", "ANZ", "Westpac"],
        "Payments": ["PayPal", "Stripe"],
    },
    "Web Browsing": {
        "Search": ["Google Search", "Bing", "DuckDuckGo", "Ecosia"],
    },
    "News": {
        "Publications": ["New York Times", "BBC", "The Guardian", "ABC News",
                         "news.com.au", "Sydney Morning Herald", "Reuters"],
    },
    "Travel": {
        "Planning": ["Booking.com", "Airbnb", "Tripadvisor"],
        "Getting Around": ["Uber", "Google Maps"],
    },
    "Health": {
        "Fitness": ["Strava", "MyFitnessPal"],
        "Wellbeing": ["Headspace", "Calm"],
    },
    "Ads and Tracking": {
        "Advertising": ["Google Ads", "AppNexus", "Criteo"],
        "Analytics": ["Google Analytics", "Google Tag Manager", "Analytics"],
    },
}


def load_taxonomy(path: str) -> Optional[dict[str, dict[str, list[str]]]]:
    """Load a user taxonomy file:

        {"Entertainment": {"Music": ["Spotify", "YouTube Music"],
                           "Video":  ["YouTube", "Netflix"]}}

    Returns None (with a printed warning) if the file is missing or
    malformed, so a typo falls back to defaults instead of crashing capture --
    same philosophy as load_aliases/load_device_groups.
    """
    try:
        raw = json.loads(Path(path).expanduser().read_text())
    except FileNotFoundError:
        print(f"[activitygraph] Warning: --taxonomy file not found: {path}")
        return None
    except (json.JSONDecodeError, AttributeError, TypeError):
        print(f"[activitygraph] Warning: --taxonomy file is not valid JSON: {path}")
        return None

    if not isinstance(raw, dict):
        print(f"[activitygraph] Warning: --taxonomy file must be an object of "
              f"category -> subcategory -> [services]: {path}")
        return None

    cleaned: dict[str, dict[str, list[str]]] = {}
    for category, subcategories in raw.items():
        if not isinstance(subcategories, dict):
            print(f"[activitygraph] Warning: category '{category}' in {path} must map "
                  f"subcategory -> [services]; skipping.")
            continue
        cleaned_subs: dict[str, list[str]] = {}
        for subcategory, services in subcategories.items():
            if isinstance(services, str):
                services = [services]
            if not isinstance(services, list):
                print(f"[activitygraph] Warning: subcategory '{subcategory}' under "
                      f"'{category}' in {path} is not a list of services; skipping.")
                continue
            cleaned_subs[subcategory] = [s for s in services if isinstance(s, str) and s.strip()]
        if cleaned_subs:
            cleaned[category] = cleaned_subs
    return cleaned


class TaxonomyRegistry:
    """Resolves a service to its subcategory within a category."""

    def __init__(self, user_taxonomy: Optional[dict[str, dict[str, list[str]]]] = None) -> None:
        merged: dict[str, dict[str, list[str]]] = {
            category: {sub: list(services) for sub, services in subs.items()}
            for category, subs in DEFAULT_SUBCATEGORIES.items()
        }
        # A user-defined category replaces ours wholesale. Merging per
        # subcategory would quietly reintroduce our opinion about services
        # the user deliberately moved or left out.
        for category, subs in (user_taxonomy or {}).items():
            merged[category] = {sub: list(services) for sub, services in subs.items()}
        self._taxonomy = merged

        self._lookup: dict[tuple[str, str], str] = {}
        for category, subs in merged.items():
            for subcategory, services in subs.items():
                for service in services:
                    self._lookup[(category, service)] = subcategory

    def subcategory_for(self, category: Optional[str], service: Optional[str]) -> str:
        if not category or not service:
            return OTHER
        return self._lookup.get((category, service), OTHER)
