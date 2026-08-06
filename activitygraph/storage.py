"""Historical persistence: the missing piece for 'time in category over time'
and 'today vs. your average' -- the digital-wellbeing layer from the
original vision.

Design: records one row per *session*, keyed uniquely on (device_ip,
start_time), not per run. That's what makes it safe to call periodically
from a long-running `--serve --serve-source live` dashboard: a session
recomputed by the Activity Graph stage keeps the same start_time as it
grows, so re-recording it just hits the UNIQUE constraint and gets ignored
(INSERT OR IGNORE) -- no double-counting, no need to track a separate
watermark. The caller only needs to avoid recording a session *before*
it's actually closed (see `BackgroundCapture._record_closed_sessions` in
server.py, which waits until a session has been idle past the session gap).

`record_sessions_from_summary` is the one entry point both callers use:
a one-shot `--demo`/`--live` run records all its (already-closed) sessions
in one call; the live dashboard's background thread calls it every few
seconds with only the sessions that have just closed.

Nothing here leaves the device -- it's a local SQLite file, same privacy
boundary as everything else. Opt-in only, via --history-db.
"""
from __future__ import annotations

import json
import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .time_analytics import union_seconds


def _local_offset() -> timedelta:
    """This machine's current UTC offset."""
    return datetime.now().astimezone().utcoffset() or timedelta(0)


class HistoryStore:
    def __init__(self, db_path: str, tz_offset: timedelta | None = None) -> None:
        self.db_path = Path(db_path).expanduser()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Day buckets are computed in *local* time. Timestamps are stored as
        # UTC ISO strings, so bucketing on them directly would put a
        # Melbourne 8am session (22:00 UTC the day before) on the wrong day
        # -- which matters a lot once the headline figure is "hours today".
        self.tz_offset = _local_offset() if tz_offset is None else tz_offset
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS session_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                category TEXT NOT NULL,
                byte_count INTEGER NOT NULL,
                services TEXT,
                mode TEXT,
                recorded_at TEXT NOT NULL,
                UNIQUE(device_ip, start_time)
            );
            CREATE INDEX IF NOT EXISTS idx_session_events_start_time ON session_events(start_time);

            -- Per-category activity intervals, the basis for time-over-time.
            --
            -- This exists separately from session_events because that table
            -- keeps only each session's *dominant* category -- fine for "what
            -- was this session mostly about", useless for "how many hours of
            -- Study this week", since a mixed session's other categories are
            -- discarded at write time.
            --
            -- Rows are pre-split at local midnight and carry local_day, so a
            -- day's totals are exact rather than approximated from UTC
            -- timestamps.
            CREATE TABLE IF NOT EXISTS category_intervals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                device_mac TEXT,
                group_name TEXT,
                category TEXT NOT NULL,
                service TEXT,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                local_day TEXT NOT NULL,
                source TEXT,
                recorded_at TEXT NOT NULL,
                UNIQUE(device_ip, category, service, start_time)
            );
            CREATE INDEX IF NOT EXISTS idx_category_intervals_day ON category_intervals(local_day);

            -- Learned IP -> hostname mappings, harvested from DNS answers.
            --
            -- Without this the mapping lives only in memory, so every
            -- restart starts blind and classifies traffic by port until
            -- each device happens to repeat a DNS lookup. Devices cache DNS
            -- aggressively, so "happens to repeat" can mean hours -- and in
            -- the meantime everything on 443 collapses into one generic
            -- "HTTPS" bucket, which is exactly the breakdown the dashboard
            -- exists to avoid.
            CREATE TABLE IF NOT EXISTS dns_names (
                ip TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );
        """)
        self._migrate_category_intervals_service()
        self._conn.commit()

    def _migrate_category_intervals_service(self) -> None:
        """Add the `service` column (and widen the uniqueness key) to
        databases written before service-level intervals existed.

        Rows are preserved with service NULL: they still count toward
        category and group totals, they just can't be broken down by service
        or re-bucketed into subcategories retroactively. Dropping them would
        lose real recorded history to gain nothing.
        """
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(category_intervals)")}
        if not columns or "service" in columns:
            return  # fresh database, or already migrated

        self._conn.executescript("""
            ALTER TABLE category_intervals RENAME TO category_intervals_pre_service;
            CREATE TABLE category_intervals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                device_mac TEXT,
                group_name TEXT,
                category TEXT NOT NULL,
                service TEXT,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                local_day TEXT NOT NULL,
                source TEXT,
                recorded_at TEXT NOT NULL,
                UNIQUE(device_ip, category, service, start_time)
            );
            INSERT INTO category_intervals
                (device_ip, device_mac, group_name, category, service,
                 start_time, end_time, local_day, source, recorded_at)
            SELECT device_ip, device_mac, group_name, category, NULL,
                   start_time, end_time, local_day, source, recorded_at
            FROM category_intervals_pre_service;
            DROP TABLE category_intervals_pre_service;
            CREATE INDEX IF NOT EXISTS idx_category_intervals_day ON category_intervals(local_day);
        """)

    # -- writing -----------------------------------------------------------
    def record_session(self, session: dict, mode: str = "unknown") -> bool:
        """Record one session. Returns True if newly recorded, False if it
        was already there (same device_ip + start_time) -- safe to call
        repeatedly on a session that's still open or already recorded."""
        try:
            device_ip = session["device_ip"]
            start_time = session["start_time"]
            end_time = session["end_time"]
        except KeyError:
            return False

        cur = self._conn.execute(
            """INSERT OR IGNORE INTO session_events
               (device_ip, start_time, end_time, category, byte_count, services, mode, recorded_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                device_ip, start_time, end_time,
                session.get("dominant_category", "Uncategorized"),
                session.get("byte_count", 0),
                json.dumps(session.get("services", [])),
                mode,
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()
        return cur.rowcount > 0

    # -- category intervals (time) ------------------------------------------
    def _split_at_local_midnight(self, start: datetime, end: datetime) -> list[tuple[datetime, datetime, str]]:
        """Split an interval so no piece straddles local midnight, tagging
        each piece with the local day it belongs to. An evening session that
        runs past midnight is genuinely two days' activity, and splitting at
        write time keeps every later query a simple grouping."""
        pieces: list[tuple[datetime, datetime, str]] = []
        cursor = start
        while cursor < end:
            local_cursor = cursor + self.tz_offset
            next_local_midnight = (local_cursor + timedelta(days=1)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
            boundary = min(end, next_local_midnight - self.tz_offset)
            pieces.append((cursor, boundary, local_cursor.date().isoformat()))
            cursor = boundary
        if not pieces:  # zero-length interval
            pieces.append((start, end, (start + self.tz_offset).date().isoformat()))
        return pieces

    def record_category_intervals(
        self,
        device_ip: str,
        category: str,
        intervals,
        device_mac: str | None = None,
        group: str | None = None,
        source: str = "flow",
        service: str | None = None,
    ) -> int:
        """Record merged activity intervals for one device+category. Returns
        the number of rows inserted or extended.

        Uses ON CONFLICT ... DO UPDATE rather than INSERT OR IGNORE because a
        merged interval can *grow* while a session is still open (a bridging
        flow joins two previously separate blocks). OR IGNORE would silently
        keep the shorter one and lose the extra time. Comparing UTC ISO
        strings lexicographically is valid here since they all come from
        datetime.isoformat() on tz-aware UTC values.
        """
        written = 0
        now = datetime.now(timezone.utc).isoformat()
        for start, end in intervals:
            for piece_start, piece_end, local_day in self._split_at_local_midnight(start, end):
                cur = self._conn.execute(
                    """INSERT INTO category_intervals
                       (device_ip, device_mac, group_name, category, service, start_time, end_time,
                        local_day, source, recorded_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(device_ip, category, service, start_time) DO UPDATE SET
                         end_time = max(end_time, excluded.end_time),
                         group_name = excluded.group_name""",
                    (device_ip, device_mac, group, category, service,
                     piece_start.isoformat(), piece_end.isoformat(), local_day, source, now),
                )
                written += cur.rowcount
        self._conn.commit()
        return written

    def record_time_from_pipeline(self, pipeline, source: str = "flow") -> int:
        """Record every device's per-category-per-service intervals from a
        live Pipeline. Service granularity is what keeps the taxonomy
        re-organizable after the fact."""
        from .time_analytics import activity_intervals_by_device_category_service

        devices = {d.ip: d for d in pipeline.devices.all_devices()}
        nested = activity_intervals_by_device_category_service(
            pipeline.flows.all_flows(), set(devices), pipeline.min_activity_seconds
        )
        written = 0
        for device_ip, keyed in nested.items():
            device = devices.get(device_ip)
            for (category, service), intervals in keyed.items():
                written += self.record_category_intervals(
                    device_ip, category, intervals,
                    device_mac=device.mac if device else None,
                    group=device.group if device else None,
                    source=source,
                    service=service,
                )
        return written

    def _interval_rows(self, days: int) -> list[tuple]:
        return self._conn.execute(
            """SELECT local_day, group_name, category, start_time, end_time, device_ip, service
               FROM category_intervals
               WHERE local_day >= date('now', 'localtime', ?)
               ORDER BY local_day ASC, start_time ASC""",
            (f"-{days} days",),
        ).fetchall()

    def daily_time_totals_by_subcategory(self, days: int = 30, taxonomy=None) -> list[dict]:
        """Active seconds per (day, category, subcategory), oldest first.

        Subcategory is resolved from the *stored service* at read time, so
        reorganizing the taxonomy re-buckets history immediately instead of
        only affecting traffic captured afterwards. Rows written before
        service was stored carry NULL and fall into the catch-all bucket.
        """
        from .taxonomy import TaxonomyRegistry

        taxonomy = taxonomy or TaxonomyRegistry()
        buckets: dict[tuple[str, str, str], list] = defaultdict(list)
        for local_day, _group, category, start, end, _ip, service in self._interval_rows(days):
            subcategory = taxonomy.subcategory_for(category, service)
            buckets[(local_day, category, subcategory)].append(
                (datetime.fromisoformat(start), datetime.fromisoformat(end))
            )
        return [
            {"day": day, "category": category, "subcategory": subcategory,
             "seconds": union_seconds(intervals)}
            for (day, category, subcategory), intervals in sorted(buckets.items())
        ]

    def daily_time_totals(self, days: int = 30) -> list[dict]:
        """Active seconds per (day, category), oldest first.

        The union is done in Python rather than as SUM(julianday(...)) in SQL
        because summing would double-count the very case this feature is
        about: a phone and a laptop active in the same category at the same
        time. It also keeps one implementation of the merge, shared with the
        live path, so the two can't drift apart.
        """
        buckets: dict[tuple[str, str], list] = defaultdict(list)
        for local_day, _group, category, start, end, _ip, _svc in self._interval_rows(days):
            buckets[(local_day, category)].append(
                (datetime.fromisoformat(start), datetime.fromisoformat(end))
            )
        return [
            {"day": day, "category": category, "seconds": union_seconds(intervals)}
            for (day, category), intervals in sorted(buckets.items())
        ]

    def daily_time_totals_by_group(self, days: int = 30) -> list[dict]:
        """Active seconds per (day, group, category), unioned across each
        group's devices."""
        buckets: dict[tuple[str, str, str], list] = defaultdict(list)
        for local_day, group, category, start, end, _ip, _svc in self._interval_rows(days):
            buckets[(local_day, group or "Ungrouped", category)].append(
                (datetime.fromisoformat(start), datetime.fromisoformat(end))
            )
        return [
            {"day": day, "group": group, "category": category, "seconds": union_seconds(intervals)}
            for (day, group, category), intervals in sorted(buckets.items())
        ]

    def today_vs_average_time(self, lookback_days: int = 14) -> dict:
        """Per-category: today's active seconds vs. the average of the prior
        days, in local time."""
        totals = self.daily_time_totals(days=lookback_days + 1)
        today = (datetime.now(timezone.utc) + self.tz_offset).date().isoformat()

        by_category: dict[str, dict] = {}
        for row in totals:
            bucket = by_category.setdefault(row["category"], {"today": 0.0, "prior": []})
            if row["day"] == today:
                bucket["today"] += row["seconds"]
            else:
                bucket["prior"].append(row["seconds"])

        return {
            category: {
                "today_seconds": data["today"],
                "average_seconds": (sum(data["prior"]) / len(data["prior"])) if data["prior"] else 0.0,
                "days_in_average": len(data["prior"]),
            }
            for category, data in by_category.items()
        }

    def record_sessions_from_summary(self, summary: dict) -> int:
        """Record every session in a Pipeline.summary() dict. Returns the
        count of sessions that were newly recorded (duplicates don't count)."""
        mode = summary.get("mode", "unknown")
        return sum(1 for s in summary.get("sessions", []) if self.record_session(s, mode=mode))

    # -- reading -------------------------------------------------------------
    def daily_totals(self, days: int = 30) -> list[dict]:
        """Byte totals per (day, category) for the last N days, oldest first.

        Grouped by the session's own start_time (when the activity actually
        happened), not when it was recorded -- so a session that gets logged
        a few seconds after midnight still counts toward the day it occurred.
        """
        rows = self._conn.execute(
            """
            SELECT date(start_time) AS day, category, SUM(byte_count) AS byte_count
            FROM session_events
            WHERE date(start_time) >= date('now', ?)
            GROUP BY day, category
            ORDER BY day ASC
            """,
            (f"-{days} days",),
        ).fetchall()
        return [{"day": day, "category": category, "byte_count": byte_count} for day, category, byte_count in rows]

    def today_vs_average(self, lookback_days: int = 14) -> dict:
        """Per-category: today's bytes vs. the average of the prior `lookback_days`."""
        totals = self.daily_totals(days=lookback_days + 1)
        today = datetime.now(timezone.utc).date().isoformat()

        today_by_cat: dict[str, int] = defaultdict(int)
        prior_by_cat: dict[str, list[int]] = defaultdict(list)

        for row in totals:
            if row["day"] == today:
                today_by_cat[row["category"]] += row["byte_count"]
            else:
                prior_by_cat[row["category"]].append(row["byte_count"])

        result = {}
        for cat in set(today_by_cat) | set(prior_by_cat):
            prior_values = prior_by_cat.get(cat, [])
            avg = sum(prior_values) / len(prior_values) if prior_values else 0
            result[cat] = {
                "today_bytes": today_by_cat.get(cat, 0),
                "average_bytes": avg,
                "days_in_average": len(prior_values),
            }
        return result

    def service_seconds_today(self, macs, day: str | None = None) -> dict:
        """Seconds spent per service today by this set of devices.

        Intervals are unioned rather than summed, matching how time is
        measured everywhere else: a group with a phone and a laptop both on
        YouTube for the same hour has spent an hour of its allowance, not
        two. Rows are already split at local midnight and carry local_day,
        so "today" is the day the person lived rather than a UTC window.
        """
        wanted = {m.upper() for m in (macs or []) if m}
        if not wanted:
            return {}
        day = day or (datetime.now(timezone.utc) + self.tz_offset).date().isoformat()

        rows = self._conn.execute(
            """SELECT service, device_mac, start_time, end_time
                 FROM category_intervals
                WHERE local_day = ? AND service IS NOT NULL AND service != ''""",
            (day,),
        )
        by_service: dict[str, list] = {}
        for service, mac, start, end in rows:
            if (mac or "").upper() not in wanted:
                continue
            by_service.setdefault(service, []).append(
                (datetime.fromisoformat(start), datetime.fromisoformat(end)))
        return {service: union_seconds(intervals)
                for service, intervals in by_service.items()}

    def session_count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM session_events").fetchone()[0]

    # -- learned hostnames ---------------------------------------------------

    def load_dns_names(self, max_age_days: int = 30) -> dict[str, str]:
        """Every IP -> hostname mapping still worth trusting.

        Old entries are dropped rather than returned: cloud and CDN
        addresses get reassigned, so a months-old mapping is as likely to
        mislabel a flow as to label it.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        rows = self._conn.execute(
            "SELECT ip, hostname FROM dns_names WHERE last_seen >= ?", (cutoff,))
        return dict(rows)

    def save_dns_names(self, mappings: dict[str, str]) -> None:
        """Persist newly-learned mappings, newest answer winning."""
        if not mappings:
            return
        now = datetime.now(timezone.utc).isoformat()
        self._conn.executemany(
            "INSERT INTO dns_names (ip, hostname, last_seen) VALUES (?, ?, ?) "
            "ON CONFLICT(ip) DO UPDATE SET hostname=excluded.hostname, last_seen=excluded.last_seen",
            [(ip, hostname, now) for ip, hostname in mappings.items()],
        )
        self._conn.commit()

    def prune_dns_names(self, max_age_days: int = 30) -> int:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
        cursor = self._conn.execute("DELETE FROM dns_names WHERE last_seen < ?", (cutoff,))
        self._conn.commit()
        return cursor.rowcount

    def close(self) -> None:
        self._conn.close()
