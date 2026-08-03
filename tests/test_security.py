"""Regression tests for security-relevant behaviour.

These cover properties that are easy to break silently and expensive to
notice: an unauthenticated listener bound beyond loopback, credentials left
world-readable, an unbounded query parameter, and untrusted network-supplied
strings reaching the DOM.
"""
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from activitygraph.router_client import load_router_credentials
from activitygraph.server import _is_loopback, create_app
from activitygraph.storage import HistoryStore

WEBAPP = Path(__file__).resolve().parent.parent / "activitygraph" / "webapp" / "index.html"


# ---------------- bind address ----------------

@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", ""])
def test_loopback_addresses_recognised(host):
    assert _is_loopback(host) is True


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "example.test"])
def test_non_loopback_addresses_recognised(host):
    assert _is_loopback(host) is False


def test_serve_warns_when_binding_beyond_loopback(capsys):
    """The dashboard exposes every device's browsing activity and has no
    authentication, so binding beyond loopback must never be silent."""
    from activitygraph.main import Pipeline
    from activitygraph.server import serve

    with patch("uvicorn.run") as run:
        serve(Pipeline(idle_timeout_seconds=5.0), host="0.0.0.0", open_browser=False)
    assert run.called
    assert "no authentication" in capsys.readouterr().err


def test_serve_does_not_warn_on_loopback(capsys):
    from activitygraph.main import Pipeline
    from activitygraph.server import serve

    with patch("uvicorn.run"):
        serve(Pipeline(idle_timeout_seconds=5.0), host="127.0.0.1", open_browser=False)
    assert "no authentication" not in capsys.readouterr().err


# ---------------- credentials file permissions ----------------

@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits only")
def test_warns_when_credentials_are_world_readable(tmp_path, capsys):
    path = tmp_path / "router.json"
    path.write_text(json.dumps({"brand": "tplink", "host": "10.0.0.1",
                                "username": "admin", "password": "secret"}))
    path.chmod(0o644)
    load_router_credentials(str(path))
    out = capsys.readouterr().out
    assert "readable by other users" in out
    assert "secret" not in out  # never echo the credential itself


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits only")
def test_no_warning_when_credentials_are_locked_down(tmp_path, capsys):
    path = tmp_path / "router.json"
    path.write_text(json.dumps({"brand": "tplink", "host": "10.0.0.1",
                                "username": "admin", "password": "secret"}))
    path.chmod(0o600)
    load_router_credentials(str(path))
    assert "readable by other users" not in capsys.readouterr().out


def test_credential_warnings_never_echo_the_password(tmp_path, capsys):
    """Malformed-config paths must not leak the file's contents into logs."""
    path = tmp_path / "router.json"
    path.write_text('{"brand": "tplink", "password": "hunter2"')  # truncated JSON
    assert load_router_credentials(str(path)) is None
    captured = capsys.readouterr()
    assert "hunter2" not in captured.out + captured.err


# ---------------- API input bounds ----------------

def test_history_days_parameter_is_clamped(tmp_path):
    """An absurd `days` value must not force an unbounded scan."""
    from activitygraph.main import Pipeline

    store = HistoryStore(str(tmp_path / "h.db"))
    app = create_app(Pipeline(idle_timeout_seconds=5.0), history_store=store)
    endpoint = {r.path: r.endpoint for r in app.routes if hasattr(r, "endpoint")}["/api/history"]

    seen = []
    original = store.daily_totals
    store.daily_totals = lambda days=30: seen.append(days) or original(days=days)

    # /api/history takes the request so it can identify the caller when
    # accounts are enabled. None are here, so the auth check is skipped.
    class _Req:
        client = None
        cookies: dict = {}

    endpoint(_Req(), days=10**9)
    endpoint(_Req(), days=-5)
    assert max(seen) <= 3650
    assert min(seen) >= 1
    store.close()


# ---------------- dashboard injection surface ----------------

def test_dom_helper_has_no_raw_html_path():
    """Device names, service labels and hostnames all originate from the
    network (DHCP, mDNS, TLS SNI), so a device can name itself
    '<img onerror=...>'. The DOM helper must insert text nodes only."""
    source = WEBAPP.read_text(encoding="utf-8")
    helper = source.split("function el(")[1].split("\n}")[0]
    assert "createTextNode" in helper
    assert "innerHTML" not in helper


def test_no_untrusted_interpolation_into_inner_html():
    """Guard against a future edit reintroducing template-literal innerHTML,
    the usual way this class of bug returns."""
    source = WEBAPP.read_text(encoding="utf-8")
    for line in source.splitlines():
        if "innerHTML" not in line or line.strip().startswith("//"):
            continue
        # Clearing a container is fine; assigning anything else is not.
        assert "innerHTML = \"\"" in line, f"unexpected innerHTML assignment: {line.strip()}"


# ---------------- usable startup URLs ----------------

def test_wildcard_bind_expands_to_reachable_addresses():
    """0.0.0.0 means "listen on every interface", not a destination. Printing
    it back gives the operator an address that cannot be opened."""
    from activitygraph.server import reachable_urls

    urls = reachable_urls("0.0.0.0", 8420)
    assert "http://0.0.0.0:8420" not in urls
    assert all(u.endswith(":8420") for u in urls)
    assert any("127.0.0.1" in u for u in urls)


def test_explicit_host_is_used_verbatim():
    from activitygraph.server import reachable_urls

    assert reachable_urls("192.168.50.1", 8420) == ["http://192.168.50.1:8420"]
    assert reachable_urls("127.0.0.1", 9000) == ["http://127.0.0.1:9000"]
