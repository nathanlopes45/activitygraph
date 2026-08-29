"""Assemble the interview demo: a populated Pipeline plus a seeded history.

Both demo entry points call `build()`:
  * `serve_demo.py` serves the resulting Pipeline through the real dashboard.
  * `export_demo.py` dumps its `summary()` and history to JSON for the
    shareable explainer page.

Everything comes from the real code. The Pipeline is the shipping one; the
history is written through the shipping `HistoryStore`. The only thing this
module adds is the synthetic input (`household.py`) and a 30-day backfill so
the trend chart has something to trend.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from activitygraph.main import Pipeline
from activitygraph.service_rules import BACKGROUND_CATEGORIES, classify_domain
from activitygraph.storage import HistoryStore

from household import ALIASES, DEVICES, GROUPS, SCHEDULE, TAXONOMY, generate

# MAC -> person, the shape GroupRegistry/Pipeline want (household.GROUPS is
# the file-format person -> [MACs], so it is inverted here once).
GROUPS_BY_MAC: dict[str, str] = {
    mac: person for person, macs in GROUPS.items() for mac in macs
}

# Where the demo's history database lives. Kept beside this file so a demo run
# never touches a real ~/.activitygraph history, and is rebuilt from scratch
# each run so it is deterministic.
DEMO_DB = Path(__file__).with_name("demo_history.db")

# How much a category's time/bytes swing between weekdays and weekends, used
# only for the historical backfill so the trend chart has a believable rhythm
# (more study midweek, more streaming at the weekend) instead of a flat line.
_WEEKEND_WEIGHTS = {
    "Entertainment": 1.6, "Social Media": 1.5, "Gaming": 1.7, "Shopping": 1.3,
    "Study": 0.4, "Software Development": 0.5, "Communication": 0.8,
}
_WEEKDAY_WEIGHTS = {
    "Entertainment": 0.8, "Social Media": 0.9, "Gaming": 0.7,
    "Study": 1.3, "Software Development": 1.4, "Communication": 1.2,
}


def build_pipeline(now: datetime | None = None) -> Pipeline:
    """Run the household stream through a real one-shot Pipeline."""
    now = now or datetime.now(timezone.utc)
    pipeline = Pipeline(
        idle_timeout_seconds=5.0,
        session_gap_seconds=300.0,
        device_aliases=dict(ALIASES),
        device_groups=GROUPS_BY_MAC,
        taxonomy=TAXONOMY,
    )
    for packet in generate(now=now):
        pipeline.ingest(packet)
    pipeline.finalize()
    return pipeline


def _seed_prior_days(store: HistoryStore, now: datetime, days: int = 30, seed: int = 7) -> None:
    """Backfill `days` of history from the same schedule, jittered per day.

    Reuses today's blocks so the past looks like more of the same day rather
    than unrelated noise: the same people, the same services, scaled up and
    down with a weekday/weekend rhythm and a little per-day randomness.
    """
    import random

    rng = random.Random(seed)
    mac_by_ip = {d.ip: d.mac for d in DEVICES}
    group_by_ip = {d.ip: d.group for d in DEVICES}

    for day in range(1, days + 1):
        day_shift = timedelta(days=day)
        # One overall level for the day, plus its weekday/weekend character.
        day_scale = rng.uniform(0.7, 1.3)
        weekday = (now - day_shift).weekday()  # 0=Mon .. 6=Sun
        weights = _WEEKEND_WEIGHTS if weekday >= 5 else _WEEKDAY_WEIGHTS

        for block in SCHEDULE:
            match = classify_domain(block.host)
            if match is None or match.category in BACKGROUND_CATEGORIES:
                continue
            weight = weights.get(match.category, 1.0) * day_scale
            # Some activities just don't happen some days.
            if rng.random() > min(1.0, 0.55 + weight * 0.4):
                continue

            start = now - timedelta(minutes=block.start_ago) - day_shift
            base_end = now - timedelta(minutes=block.end_ago) - day_shift
            # Scale the block's duration by the day's weight, clamped so a
            # quiet day still registers and a busy one doesn't run absurdly long.
            factor = max(0.25, min(2.2, weight * rng.uniform(0.8, 1.2)))
            duration = (base_end - start) * factor
            end = start + duration
            byte_count = int(block.packets * block.avg_bytes * factor * rng.uniform(0.8, 1.2))

            store.record_category_intervals(
                block.device_ip, match.category, [(start, end)],
                device_mac=mac_by_ip.get(block.device_ip),
                group=group_by_ip.get(block.device_ip),
                source="demo",
                service=match.service,
            )
            store.record_session(
                {
                    "device_ip": block.device_ip,
                    "start_time": start.isoformat(),
                    "end_time": end.isoformat(),
                    "dominant_category": match.category,
                    "byte_count": byte_count,
                    "services": [match.service],
                },
                mode="demo",
            )


def build(now: datetime | None = None, with_history: bool = True) -> tuple[Pipeline, HistoryStore | None]:
    """The populated Pipeline and (optionally) a freshly-seeded HistoryStore.

    The history database is rebuilt from scratch every call so the demo is
    deterministic and never accumulates across runs.
    """
    now = now or datetime.now(timezone.utc)
    pipeline = build_pipeline(now)

    if not with_history:
        return pipeline, None

    if DEMO_DB.exists():
        DEMO_DB.unlink()
    store = HistoryStore(str(DEMO_DB))
    # Today, straight from the real run: sessions for the byte trend, and
    # per-category-per-service intervals for the time trend.
    store.record_sessions_from_summary(pipeline.summary())
    store.record_time_from_pipeline(pipeline)
    # The preceding 30 days, backfilled from the same schedule.
    _seed_prior_days(store, now)
    return pipeline, store
