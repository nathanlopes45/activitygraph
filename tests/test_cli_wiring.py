"""Smoke tests that every CLI mode can actually be constructed.

These exist because a keyword argument was added to one call and, by way of
a bulk edit, to a second call that did not accept it. Every unit test passed:
each component was correct in isolation, and nothing put them together the
way the command line does. It failed on the first real run instead.

They deliberately assert almost nothing about behaviour. Their whole job is
to walk each mode's wiring end to end and let a TypeError surface here
rather than on a gateway.
"""
import sys
from unittest.mock import patch

import pytest


class _StubCollector:
    """Stands in for TrafficCollector so no interface is opened."""

    def __init__(self, interface=None, bpf_filter=None):
        self.interface = interface
        self.bpf_filter = bpf_filter

    def run(self, *args, **kwargs):
        return None

    def capture(self, *args, **kwargs):
        return None

    def list_interfaces(self):
        return []


def run_cli(argv, tmp_path):
    """Run main() with everything that blocks or touches the network stubbed."""
    from activitygraph import main as cli

    with patch.object(cli, "TrafficCollector", _StubCollector), \
         patch("activitygraph.server.TrafficCollector", _StubCollector, create=True), \
         patch("uvicorn.run"), \
         patch("activitygraph.server.BackgroundCapture.start"), \
         patch("activitygraph.collector.warn_if_capturing_wan"), \
         patch.object(sys, "argv", ["activitygraph"] + argv):
        try:
            cli.main()
        except SystemExit as exc:  # argparse errors are real failures here
            if exc.code:
                raise AssertionError(f"exited {exc.code} for: {' '.join(argv)}") from exc


BASE_SERVE = ["--serve", "--serve-source", "live", "-i", "eth1", "--no-browser"]


@pytest.mark.parametrize("extra", [
    [],
    ["--include-self"],
    ["--capture-mode", "light"],
    ["--capture-mode", "light", "--include-self"],
    ["--bpf-filter", "arp or (udp and port 53)"],
], ids=["plain", "include-self", "light", "light+include-self", "own-filter"])
def test_serve_live_constructs(extra, tmp_path):
    """The mode a gateway runs, and the one that broke. It builds a Pipeline
    and a BackgroundCapture from the same arguments, so a keyword accepted
    by one and not the other only shows up here."""
    run_cli(BASE_SERVE + extra, tmp_path)


def test_serve_live_with_everything_a_gateway_uses(tmp_path):
    run_cli(BASE_SERVE + [
        "--capture-mode", "light",
        "--dhcp-leases",
        "--accounts", str(tmp_path / "accounts.db"),
        "--history-db", str(tmp_path / "history.db"),
    ], tmp_path)


def test_serve_demo_constructs(tmp_path):
    run_cli(["--serve", "--serve-source", "demo", "--no-browser",
             "--history-db", str(tmp_path / "h.db")], tmp_path)


@pytest.mark.parametrize("extra", [[], ["--include-self"], ["--capture-mode", "light"]])
def test_live_capture_constructs(extra, tmp_path):
    run_cli(["--live", "-i", "eth1", "--duration", "0"] + extra, tmp_path)


def test_demo_constructs(tmp_path):
    run_cli(["--demo"], tmp_path)


def test_demo_with_history_constructs(tmp_path):
    run_cli(["--demo", "--history-db", str(tmp_path / "h.db")], tmp_path)


def test_an_invalid_capture_filter_is_rejected_before_anything_starts(tmp_path):
    """The check has to run early enough to stop the whole command, not deep
    inside a capture thread once the dashboard is already serving."""
    with pytest.raises(AssertionError, match="exited 2"):
        run_cli(BASE_SERVE + ["--bpf-filter", "this is not bpf"], tmp_path)


def test_serve_live_with_a_freshness_window_constructs(tmp_path):
    run_cli(BASE_SERVE + ["--active-within", "15"], tmp_path)


def test_serve_demo_with_a_freshness_window_constructs(tmp_path):
    run_cli(["--serve", "--serve-source", "demo", "--no-browser", "--active-within", "15"],
            tmp_path)


def test_serve_live_showing_background_traffic_constructs(tmp_path):
    run_cli(BASE_SERVE + ["--show-background"], tmp_path)
