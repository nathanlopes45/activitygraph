import threading
from unittest.mock import MagicMock

from activitygraph.server import BackgroundCapture


def _capture(pipeline=None, **kwargs):
    """BackgroundCapture with a tiny backoff so restart tests stay fast."""
    kwargs.setdefault("restart_backoff_seconds", 0.01)
    kwargs.setdefault("max_restart_backoff_seconds", 0.05)
    return BackgroundCapture(pipeline or MagicMock(), **kwargs)


def test_capture_loop_restarts_when_sniff_returns_early():
    """Regression test: scapy's pcap socket can die on its own, in which
    case sniff() *returns* rather than raising. Without a retry the capture
    thread would end silently and the dashboard would serve a frozen
    snapshot that looks like an idle network."""
    capture = _capture()
    calls = []
    done = threading.Event()

    def fake_run(on_packet, timeout=None):
        calls.append(1)
        if len(calls) >= 3:
            capture._stop_flag.set()
            done.set()

    capture.collector.run = fake_run
    capture._capture_loop()

    assert done.is_set()
    assert len(calls) >= 3
    assert capture._capture_restarts >= 2


def test_capture_loop_restarts_when_sniff_raises():
    capture = _capture()
    calls = []

    def fake_run(on_packet, timeout=None):
        calls.append(1)
        if len(calls) >= 2:
            capture._stop_flag.set()
        raise OSError("socket closed")

    capture.collector.run = fake_run
    capture._capture_loop()

    assert len(calls) == 2
    assert capture._capture_error == "socket closed"


def test_capture_loop_exits_promptly_when_stopped():
    capture = _capture()

    def fake_run(on_packet, timeout=None):
        capture._stop_flag.set()

    capture.collector.run = fake_run
    capture._capture_loop()

    # Stopped deliberately, so this is not counted as an unexpected restart.
    assert capture._capture_restarts == 0


def test_capture_loop_backoff_grows_but_is_capped():
    capture = _capture(restart_backoff_seconds=0.01, max_restart_backoff_seconds=0.02)
    waits = []
    original_wait = capture._stop_flag.wait

    def recording_wait(timeout=None):
        waits.append(timeout)
        return original_wait(0)

    capture._stop_flag.wait = recording_wait
    calls = []

    def fake_run(on_packet, timeout=None):
        calls.append(1)
        if len(calls) >= 4:
            capture._stop_flag.set()

    capture.collector.run = fake_run
    capture._capture_loop()

    assert waits == [0.01, 0.02, 0.02]  # doubles, then clamps to the max


def test_status_reports_capture_health():
    capture = _capture()
    status = capture.status()
    assert status["capture_alive"] is False
    assert status["capture_restarts"] == 0
    assert status["last_capture_error"] is None


def test_status_says_whether_byte_totals_are_exact_or_sampled():
    """Without flow accounting the totals come from whatever got past the
    capture filter, so a dashboard showing exact-looking numbers should be
    able to say which it is."""
    assert _capture().status()["flow_accounting"]["enabled"] is False


def test_capture_alive_reflects_running_thread():
    capture = _capture()
    assert capture.capture_alive is False

    started = threading.Event()

    def fake_run(on_packet, timeout=None):
        started.set()
        capture._stop_flag.wait(1.0)
        capture._stop_flag.set()

    capture.collector.run = fake_run
    capture._capture_thread = threading.Thread(target=capture._capture_loop, daemon=True)
    capture._capture_thread.start()
    started.wait(1.0)
    assert capture.capture_alive is True

    capture._stop_flag.set()
    capture._capture_thread.join(timeout=2.0)
    assert capture.capture_alive is False
