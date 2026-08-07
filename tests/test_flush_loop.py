"""The background thread that does everything periodic.

Closing flows, writing history, learning names and refreshing the firewall
all run on one thread. It died on a live gateway with "dictionary changed
size during iteration": the capture thread adds an entry to the DNS cache
for every answer it sees, and the firewall refresh iterated that same dict.
The process kept serving a dashboard that had silently stopped recording and
stopped enforcing, which reads as an idle network rather than a fault.
"""
import sqlite3
import threading
import time

from activitygraph.accounts import AccountStore
from activitygraph.main import run_demo
from activitygraph.server import BackgroundCapture, _snapshot

PHONE = "AA:BB:CC:00:00:01"


def capture_with_a_blacklist():
    pipeline = run_demo(idle_timeout=5.0)
    accounts = AccountStore(sqlite3.connect(":memory:"))
    accounts.create_user("theadmin", "password123")
    sam = accounts.create_user("sam", "password123")
    accounts.claim_device(sam.id, PHONE, "iPhone")
    accounts.add_blocked(sam.id, "YouTube")
    return BackgroundCapture(pipeline, accounts=accounts, enforce_blacklist=True)


# ---------------- the snapshot ----------------

def test_a_dict_being_written_can_still_be_copied():
    """dict(d) is one bytecode but not an atomic one, so it can raise while
    another thread grows the dict. Retrying is enough: the window is a few
    microseconds and the writer is not in a loop."""
    live = {f"10.0.0.{i}": "example.com" for i in range(500)}
    stop = threading.Event()

    def churn():
        counter = 0
        while not stop.is_set():
            live[f"192.168.1.{counter % 250}"] = "youtube.com"
            live.pop(f"192.168.1.{(counter + 7) % 250}", None)
            counter += 1

    writer = threading.Thread(target=churn, daemon=True)
    writer.start()
    try:
        for _ in range(500):
            assert isinstance(_snapshot(live), dict)
    finally:
        stop.set()
        writer.join(timeout=2)


def test_a_snapshot_is_a_copy_not_the_original():
    """Handing out the live dict would only move the race downstream."""
    live = {"1.2.3.4": "youtube.com"}
    copied = _snapshot(live)
    live["5.6.7.8"] = "instagram.com"
    assert copied == {"1.2.3.4": "youtube.com"}


# ---------------- the refresh that crashed ----------------

def test_the_firewall_refresh_survives_dns_arriving_mid_pass():
    """The reported crash, reproduced: a device looking something up while
    the rules are being rebuilt."""
    capture = capture_with_a_blacklist()
    cache = capture.pipeline.services._dns_cache
    cache.update({f"142.250.0.{i}": "youtube.com" for i in range(300)})

    stop = threading.Event()
    failures = []

    def resolve():
        counter = 0
        while not stop.is_set():
            cache[f"172.217.{counter % 250}.1"] = "rr3---sn-abc.googlevideo.com"
            cache.pop(f"172.217.{(counter + 9) % 250}.1", None)
            counter += 1

    writer = threading.Thread(target=resolve, daemon=True)
    writer.start()
    try:
        for _ in range(200):
            try:
                capture._refresh_blacklist()
            except Exception as exc:          # noqa: BLE001 - the point of the test
                failures.append(exc)
                break
    finally:
        stop.set()
        writer.join(timeout=2)

    assert failures == [], f"refresh raised {failures[:1]}"


# ---------------- the thread must outlive a failure ----------------

def test_a_failing_pass_does_not_end_the_thread():
    """Whatever goes wrong, the next tick must still run. A dead thread
    stops history and enforcement together, silently."""
    capture = capture_with_a_blacklist()
    capture.flush_interval_seconds = 0.01
    calls = []

    def sometimes_broken():
        calls.append(1)
        if len(calls) < 3:
            raise RuntimeError("dictionary changed size during iteration")

    capture._flush_once = sometimes_broken
    thread = threading.Thread(target=capture._flush_loop, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while len(calls) < 5 and time.monotonic() < deadline:
        time.sleep(0.01)
    capture.stop()
    thread.join(timeout=2)

    assert len(calls) >= 5, "the loop stopped at the first failure"
    assert capture.status()["flush_errors"] == 2
    assert "dictionary changed size" in capture.status()["last_flush_error"]


def test_a_healthy_run_reports_no_errors():
    assert capture_with_a_blacklist().status()["flush_errors"] == 0
