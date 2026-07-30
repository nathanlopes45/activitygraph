from datetime import datetime, timedelta, timezone

from activitygraph.models import Flow
from activitygraph.service_rules import classify_domain
from activitygraph.taxonomy import OTHER, TaxonomyRegistry, load_taxonomy
from activitygraph.time_analytics import time_by_category_nested

BASE = datetime(2026, 7, 30, 10, 0, 0, tzinfo=timezone.utc)


def _flow(service, category, start_min, end_min):
    return Flow(
        src_ip="192.168.1.5", dst_ip="1.2.3.4", src_port=1, dst_port=443, proto="TCP",
        start_time=BASE + timedelta(minutes=start_min),
        end_time=BASE + timedelta(minutes=end_min),
        byte_count=100, packet_count=5, service=service, category=category,
    )


def _write(tmp_path, text):
    path = tmp_path / "taxonomy.json"
    path.write_text(text)
    return str(path)


# ---------------- defaults ----------------

def test_default_subcategories_split_music_from_video():
    t = TaxonomyRegistry()
    assert t.subcategory_for("Entertainment", "Spotify") == "Music"
    assert t.subcategory_for("Entertainment", "YouTube Music") == "Music"
    assert t.subcategory_for("Entertainment", "YouTube") == "Video"
    assert t.subcategory_for("Entertainment", "Netflix") == "Video"


def test_unknown_service_falls_back_to_other():
    """So a category's subcategory totals always account for the whole
    category rather than silently dropping unmapped services."""
    assert TaxonomyRegistry().subcategory_for("Entertainment", "Some New Service") == OTHER


def test_missing_category_or_service_is_other():
    t = TaxonomyRegistry()
    assert t.subcategory_for(None, "Spotify") == OTHER
    assert t.subcategory_for("Entertainment", None) == OTHER


def test_music_youtube_classifies_separately_from_youtube():
    """Listening and watching must stay distinguishable, which requires the
    music.youtube.com rule to precede the general youtube.com one."""
    assert classify_domain("music.youtube.com").service == "YouTube Music"
    assert classify_domain("youtube.com").service == "YouTube"


# ---------------- user config ----------------

def test_load_taxonomy_parses_user_file(tmp_path):
    path = _write(tmp_path, '{"Entertainment": {"Music": ["Spotify"], "Video": ["Netflix"]}}')
    assert load_taxonomy(path) == {"Entertainment": {"Music": ["Spotify"], "Video": ["Netflix"]}}


def test_load_taxonomy_missing_file_returns_none():
    assert load_taxonomy("/nonexistent/taxonomy.json") is None


def test_load_taxonomy_malformed_returns_none(tmp_path):
    assert load_taxonomy(_write(tmp_path, "not json {{{")) is None


def test_load_taxonomy_skips_bad_category_shape(tmp_path):
    path = _write(tmp_path, '{"Entertainment": 42, "Study": {"Courses": ["Coursera"]}}')
    assert load_taxonomy(path) == {"Study": {"Courses": ["Coursera"]}}


def test_user_category_replaces_defaults_wholesale(tmp_path):
    """If the user has said how Entertainment is organized, our opinion
    about it shouldn't leak back in."""
    user = {"Entertainment": {"Everything": ["Spotify", "YouTube"]}}
    t = TaxonomyRegistry(user)
    assert t.subcategory_for("Entertainment", "Spotify") == "Everything"
    assert t.subcategory_for("Entertainment", "YouTube") == "Everything"
    # Netflix was in our defaults but not the user's list -> unmapped, not "Video"
    assert t.subcategory_for("Entertainment", "Netflix") == OTHER


def test_user_config_leaves_other_categories_on_defaults():
    t = TaxonomyRegistry({"Entertainment": {"Everything": ["Spotify"]}})
    assert t.subcategory_for("Social Media", "Instagram") == "Feeds"


def test_user_can_invent_new_categories():
    t = TaxonomyRegistry({"Wellbeing": {"Meditation": ["Headspace"]}})
    assert t.subcategory_for("Wellbeing", "Headspace") == "Meditation"


# ---------------- nested aggregation ----------------

def test_nested_drilldown_unions_at_every_level():
    """Overlapping services inside a subcategory count once, and so do
    overlapping subcategories inside a category."""
    flows = [
        _flow("Spotify", "Entertainment", 0, 40),
        _flow("YouTube Music", "Entertainment", 30, 50),   # overlaps Spotify
        _flow("YouTube", "Entertainment", 60, 90),
        _flow("Netflix", "Entertainment", 80, 110),        # overlaps YouTube
    ]
    rows = time_by_category_nested(flows, {"192.168.1.5"})
    entertainment = rows[0]
    assert entertainment["category"] == "Entertainment"
    assert entertainment["seconds"] == 100 * 60  # 0-50 and 60-110

    subs = {s["subcategory"]: s for s in entertainment["subcategories"]}
    assert subs["Music"]["seconds"] == 50 * 60   # 0-40 u 30-50, not 60m
    assert subs["Video"]["seconds"] == 50 * 60   # 60-90 u 80-110, not 60m
    assert {s["service"] for s in subs["Music"]["services"]} == {"Spotify", "YouTube Music"}


def test_nested_drilldown_sorted_by_time_at_each_level():
    flows = [
        _flow("Spotify", "Entertainment", 0, 10),
        _flow("Netflix", "Entertainment", 20, 80),
        _flow("Instagram", "Social Media", 0, 5),
    ]
    rows = time_by_category_nested(flows, {"192.168.1.5"})
    assert [r["category"] for r in rows] == ["Entertainment", "Social Media"]
    assert [s["subcategory"] for s in rows[0]["subcategories"]] == ["Video", "Music"]


def test_reorganizing_taxonomy_rebuckets_the_same_flows():
    """The point of user-configurable subcategories: the same captured
    traffic regroups immediately, with no recapture."""
    flows = [_flow("Spotify", "Entertainment", 0, 30), _flow("Netflix", "Entertainment", 0, 30)]

    default_subs = {s["subcategory"] for s in
                    time_by_category_nested(flows, {"192.168.1.5"})[0]["subcategories"]}
    assert default_subs == {"Music", "Video"}

    regrouped = TaxonomyRegistry({"Entertainment": {"Streaming": ["Spotify", "Netflix"]}})
    new_subs = {s["subcategory"] for s in
                time_by_category_nested(flows, {"192.168.1.5"}, taxonomy=regrouped)[0]["subcategories"]}
    assert new_subs == {"Streaming"}
