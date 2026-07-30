from datetime import datetime, timedelta, timezone

from activitygraph.storage import HistoryStore


def _session(device_ip, start, end, category, byte_count, services=None):
    return {
        "device_ip": device_ip,
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "dominant_category": category,
        "byte_count": byte_count,
        "services": services or [],
    }


def _summary(sessions, mode="demo"):
    return {"mode": mode, "sessions": sessions}


def test_record_session_and_session_count(tmp_path):
    store = HistoryStore(str(tmp_path / "history.db"))
    assert store.session_count() == 0
    now = datetime.now(timezone.utc)
    inserted = store.record_session(_session("192.168.1.10", now, now + timedelta(minutes=5), "Study", 1000))
    assert inserted is True
    assert store.session_count() == 1
    store.close()


def test_recording_the_same_session_twice_does_not_duplicate(tmp_path):
    """This is the core correctness property: a live dashboard calling this
    repeatedly on the same still-growing session must not double-count."""
    store = HistoryStore(str(tmp_path / "history.db"))
    now = datetime.now(timezone.utc)
    session = _session("192.168.1.10", now, now + timedelta(minutes=5), "Study", 1000)

    first = store.record_session(session)
    second = store.record_session(session)  # identical device_ip + start_time

    assert first is True
    assert second is False
    assert store.session_count() == 1
    store.close()


def test_record_sessions_from_summary_counts_only_new_ones(tmp_path):
    store = HistoryStore(str(tmp_path / "history.db"))
    now = datetime.now(timezone.utc)
    sessions = [
        _session("192.168.1.10", now, now + timedelta(minutes=5), "Study", 1000),
        _session("192.168.1.11", now, now + timedelta(minutes=5), "Entertainment", 2000),
    ]
    first_count = store.record_sessions_from_summary(_summary(sessions))
    second_count = store.record_sessions_from_summary(_summary(sessions))  # re-record same sessions
    assert first_count == 2
    assert second_count == 0
    assert store.session_count() == 2
    store.close()


def test_daily_totals_aggregates_multiple_sessions_same_day(tmp_path):
    store = HistoryStore(str(tmp_path / "history.db"))
    now = datetime.now(timezone.utc)
    store.record_session(_session("192.168.1.10", now, now + timedelta(minutes=5), "Study", 1000))
    store.record_session(_session("192.168.1.10", now + timedelta(hours=1), now + timedelta(hours=1, minutes=5), "Study", 500))
    totals = store.daily_totals(days=1)
    study_rows = [t for t in totals if t["category"] == "Study"]
    assert len(study_rows) == 1
    assert study_rows[0]["byte_count"] == 1500
    store.close()


def test_daily_totals_splits_across_days(tmp_path):
    store = HistoryStore(str(tmp_path / "history.db"))
    today = datetime.now(timezone.utc)
    yesterday = today - timedelta(days=1)
    store.record_session(_session("192.168.1.10", today, today + timedelta(minutes=5), "Entertainment", 2000))
    store.record_session(_session("192.168.1.10", yesterday, yesterday + timedelta(minutes=5), "Entertainment", 4000))
    totals = store.daily_totals(days=7)
    days = {t["day"] for t in totals}
    assert len(days) == 2
    store.close()


def test_today_vs_average_computes_correctly(tmp_path):
    store = HistoryStore(str(tmp_path / "history.db"))
    today = datetime.now(timezone.utc)
    d1, d2 = today - timedelta(days=1), today - timedelta(days=2)
    store.record_session(_session("192.168.1.10", d1, d1 + timedelta(minutes=5), "Study", 1000))
    store.record_session(_session("192.168.1.10", d2, d2 + timedelta(minutes=5), "Study", 3000))
    store.record_session(_session("192.168.1.10", today, today + timedelta(minutes=5), "Study", 500))

    comparison = store.today_vs_average(lookback_days=14)
    assert comparison["Study"]["today_bytes"] == 500
    assert comparison["Study"]["average_bytes"] == 2000
    assert comparison["Study"]["days_in_average"] == 2
    store.close()


def test_today_vs_average_handles_no_prior_history(tmp_path):
    store = HistoryStore(str(tmp_path / "history.db"))
    today = datetime.now(timezone.utc)
    store.record_session(_session("192.168.1.10", today, today + timedelta(minutes=5), "Gaming", 700))
    comparison = store.today_vs_average()
    assert comparison["Gaming"]["today_bytes"] == 700
    assert comparison["Gaming"]["average_bytes"] == 0
    assert comparison["Gaming"]["days_in_average"] == 0
    store.close()


def test_store_persists_to_disk_across_instances(tmp_path):
    db_path = str(tmp_path / "history.db")
    now = datetime.now(timezone.utc)
    store1 = HistoryStore(db_path)
    store1.record_session(_session("192.168.1.10", now, now + timedelta(minutes=5), "Study", 100))
    store1.close()

    store2 = HistoryStore(db_path)
    assert store2.session_count() == 1
    # Recording the same session again via a fresh connection should still dedupe.
    inserted = store2.record_session(_session("192.168.1.10", now, now + timedelta(minutes=5), "Study", 100))
    assert inserted is False
    store2.close()


def test_record_session_missing_required_fields_is_ignored(tmp_path):
    store = HistoryStore(str(tmp_path / "history.db"))
    inserted = store.record_session({"dominant_category": "Study", "byte_count": 100})  # no device_ip/start_time/end_time
    assert inserted is False
    assert store.session_count() == 0
    store.close()


def test_tilde_in_path_expands_to_home_directory(monkeypatch, tmp_path):
    """Regression test: PowerShell (unlike bash) doesn't expand '~' before
    passing it to the program, so the code itself must handle it.

    Both HOME and USERPROFILE are redirected because expanduser() consults
    different variables per platform -- POSIX reads HOME, Windows reads
    USERPROFILE (then HOMEDRIVE/HOMEPATH). Setting only one made this test
    fail on Windows *and* create a database in the developer's real home
    directory as a side effect.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("HOMEDRIVE", raising=False)
    monkeypatch.delenv("HOMEPATH", raising=False)

    store = HistoryStore("~/activitygraph_test_history.db")
    try:
        assert store.db_path == tmp_path / "activitygraph_test_history.db"
        assert store.db_path.exists()
        assert "~" not in str(store.db_path)
    finally:
        store.close()


# ---------------- category_intervals (time-over-time) ----------------

MELBOURNE = timedelta(hours=10)


def _store(tmp_path, name="time.db"):
    return HistoryStore(str(tmp_path / name), tz_offset=MELBOURNE)


def _utc(y, m, d, hh, mm=0):
    return datetime(y, m, d, hh, mm, tzinfo=timezone.utc)


def test_local_day_bucketing_uses_local_time_not_utc(tmp_path):
    """Regression: a Melbourne 8am session is 22:00 UTC the previous day.
    Bucketing on the UTC timestamp put it on the wrong day, which matters
    once the headline figure is 'hours today'."""
    store = _store(tmp_path)
    start = _utc(2026, 7, 29, 22)  # 2026-07-30 08:00 in Melbourne
    store.record_category_intervals("192.168.1.5", "Study", [(start, start + timedelta(minutes=30))])
    assert [r["day"] for r in store.daily_time_totals(days=3650)] == ["2026-07-30"]
    store.close()


def test_interval_spanning_local_midnight_is_split(tmp_path):
    store = _store(tmp_path)
    start = _utc(2026, 7, 30, 13, 30)  # 23:30 Melbourne
    store.record_category_intervals("192.168.1.5", "Entertainment", [(start, start + timedelta(hours=1))])
    rows = store.daily_time_totals(days=3650)
    assert [(r["day"], r["seconds"]) for r in rows] == [
        ("2026-07-30", 1800.0), ("2026-07-31", 1800.0),
    ]
    store.close()


def test_daily_time_totals_unions_overlapping_devices(tmp_path):
    """The semantic the whole feature rests on: a phone and a laptop both
    active 10:00-10:30 is 30 minutes, not 60."""
    store = _store(tmp_path)
    start = _utc(2026, 7, 30, 2)
    for ip in ("192.168.1.5", "192.168.1.6"):
        store.record_category_intervals(ip, "Entertainment", [(start, start + timedelta(minutes=30))], group="Alice")
    assert store.daily_time_totals(days=3650)[0]["seconds"] == 1800.0
    by_group = store.daily_time_totals_by_group(days=3650)
    assert [(r["group"], r["seconds"]) for r in by_group] == [("Alice", 1800.0)]
    store.close()


def test_growing_interval_extends_rather_than_being_dropped(tmp_path):
    """A merged interval can grow while a session is open (a bridging flow
    joins two blocks). INSERT OR IGNORE would keep the shorter one."""
    store = _store(tmp_path)
    start = _utc(2026, 7, 30, 2)
    store.record_category_intervals("192.168.1.5", "Study", [(start, start + timedelta(minutes=10))])
    store.record_category_intervals("192.168.1.5", "Study", [(start, start + timedelta(minutes=25))])
    assert store.daily_time_totals(days=3650)[0]["seconds"] == 1500.0
    store.close()


def test_recording_same_interval_twice_does_not_double_count(tmp_path):
    store = _store(tmp_path)
    start = _utc(2026, 7, 30, 2)
    for _ in range(3):
        store.record_category_intervals("192.168.1.5", "Study", [(start, start + timedelta(minutes=20))])
    totals = store.daily_time_totals(days=3650)
    assert len(totals) == 1
    assert totals[0]["seconds"] == 1200.0
    store.close()


def test_ungrouped_devices_bucket_under_ungrouped(tmp_path):
    store = _store(tmp_path)
    start = _utc(2026, 7, 30, 2)
    store.record_category_intervals("192.168.1.9", "Study", [(start, start + timedelta(minutes=10))])
    assert store.daily_time_totals_by_group(days=3650)[0]["group"] == "Ungrouped"
    store.close()


def test_category_intervals_table_is_additive_to_existing_db(tmp_path):
    """Existing history DBs must keep working -- the byte-based readers are
    untouched and upgrade silently."""
    path = str(tmp_path / "existing.db")
    old = HistoryStore(path)
    old.record_session({
        "device_ip": "192.168.1.5", "start_time": "2026-07-30T02:00:00+00:00",
        "end_time": "2026-07-30T02:30:00+00:00", "dominant_category": "Study",
        "byte_count": 1000, "services": ["Canvas"],
    }, mode="test")
    old.close()

    reopened = HistoryStore(path, tz_offset=MELBOURNE)
    assert reopened.daily_totals(days=3650)[0]["byte_count"] == 1000  # bytes still work
    assert reopened.daily_time_totals(days=3650) == []               # new table starts empty
    reopened.close()


def test_service_is_stored_so_subcategory_is_derived_at_read_time(tmp_path):
    """The point of storing service rather than subcategory: reorganizing the
    taxonomy re-buckets history immediately, instead of only affecting
    traffic captured after the change."""
    from activitygraph.taxonomy import TaxonomyRegistry

    store = _store(tmp_path)
    start = _utc(2026, 7, 30, 2)
    store.record_category_intervals("192.168.1.5", "Entertainment",
                                    [(start, start + timedelta(minutes=30))], service="Spotify")
    store.record_category_intervals("192.168.1.5", "Entertainment",
                                    [(start + timedelta(hours=1), start + timedelta(hours=1, minutes=30))],
                                    service="Netflix")

    default_subs = {r["subcategory"] for r in store.daily_time_totals_by_subcategory(days=3650)}
    assert default_subs == {"Music", "Video"}

    regrouped = TaxonomyRegistry({"Entertainment": {"Streaming": ["Spotify", "Netflix"]}})
    rows = store.daily_time_totals_by_subcategory(days=3650, taxonomy=regrouped)
    assert {r["subcategory"] for r in rows} == {"Streaming"}
    assert sum(r["seconds"] for r in rows) == 3600.0  # same total, regrouped
    store.close()


def test_two_services_in_one_category_at_same_instant_both_recorded(tmp_path):
    """Widening the uniqueness key to include service matters: before, a
    second service starting at the same moment collided and was dropped."""
    store = _store(tmp_path)
    start = _utc(2026, 7, 30, 2)
    store.record_category_intervals("192.168.1.5", "Entertainment",
                                    [(start, start + timedelta(minutes=10))], service="Spotify")
    store.record_category_intervals("192.168.1.5", "Entertainment",
                                    [(start, start + timedelta(minutes=30))], service="Netflix")
    rows = store.daily_time_totals_by_subcategory(days=3650)
    assert {r["subcategory"] for r in rows} == {"Music", "Video"}
    store.close()


def test_pre_service_rows_survive_migration(tmp_path):
    """Rows recorded before service existed must keep counting toward
    category totals rather than being dropped."""
    path = str(tmp_path / "old.db")
    old = HistoryStore(path, tz_offset=MELBOURNE)
    # Simulate the pre-service schema by dropping the column back out.
    old._conn.executescript("""
        DROP TABLE category_intervals;
        CREATE TABLE category_intervals (
            id INTEGER PRIMARY KEY AUTOINCREMENT, device_ip TEXT NOT NULL, device_mac TEXT,
            group_name TEXT, category TEXT NOT NULL, start_time TEXT NOT NULL,
            end_time TEXT NOT NULL, local_day TEXT NOT NULL, source TEXT,
            recorded_at TEXT NOT NULL, UNIQUE(device_ip, category, start_time));
        INSERT INTO category_intervals
            (device_ip, category, start_time, end_time, local_day, source, recorded_at)
        VALUES ('192.168.1.5', 'Study', '2026-07-30T02:00:00+00:00',
                '2026-07-30T02:30:00+00:00', '2026-07-30', 'flow', '2026-07-30T02:30:00+00:00');
    """)
    old._conn.commit()
    old.close()

    migrated = HistoryStore(path, tz_offset=MELBOURNE)
    assert "service" in {r[1] for r in migrated._conn.execute("PRAGMA table_info(category_intervals)")}
    totals = migrated.daily_time_totals(days=3650)
    assert totals == [{"day": "2026-07-30", "category": "Study", "seconds": 1800.0}]
    migrated.close()
