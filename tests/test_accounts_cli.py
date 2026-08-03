"""Tests for enabling accounts from the command line, and for the parts of
the dashboard that expose them.

The backend was complete and correct for a while before any of it was
reachable: no flag turned it on and no page called it. These cover the
wiring, which is the part with no other test to catch it.
"""
from pathlib import Path

import pytest

from activitygraph.main import _open_accounts

WEBAPP = Path(__file__).resolve().parent.parent / "activitygraph" / "webapp" / "index.html"


# ---------------- opening the store ----------------

def test_accounts_are_off_by_default():
    """The single-user loopback mode must not start demanding a password."""
    accounts, secret = _open_accounts(None, None)
    assert accounts is None
    assert secret == b""


def test_opening_accounts_creates_the_database_and_key(tmp_path):
    db = tmp_path / "nested" / "accounts.db"
    accounts, secret = _open_accounts(str(db), None)

    assert db.exists(), "parent directory should be created"
    assert db.with_suffix(".key").exists(), "signing key should sit beside the database"
    assert len(secret) >= 32


def test_the_key_is_reused_so_sessions_survive_a_restart(tmp_path):
    db = str(tmp_path / "accounts.db")
    _, first = _open_accounts(db, None)
    _, second = _open_accounts(db, None)
    assert first == second


def test_the_key_can_live_somewhere_else(tmp_path):
    db = tmp_path / "accounts.db"
    key = tmp_path / "elsewhere" / "signing.key"
    _open_accounts(str(db), str(key))
    assert key.exists()
    assert not db.with_suffix(".key").exists()


def test_a_reopened_store_keeps_its_users(tmp_path):
    db = str(tmp_path / "accounts.db")
    accounts, _ = _open_accounts(db, None)
    accounts.create_user("alice", "password123")

    reopened, _ = _open_accounts(db, None)
    assert reopened.user_count() == 1
    assert reopened.authenticate("alice", "password123") is not None


# ---------------- the bind warning ----------------

def test_binding_beyond_loopback_still_warns_without_accounts(capsys):
    from activitygraph.main import Pipeline
    from activitygraph.server import serve
    from unittest.mock import patch

    with patch("uvicorn.run"):
        serve(Pipeline(idle_timeout_seconds=5.0), host="0.0.0.0", open_browser=False)
    assert "no authentication" in capsys.readouterr().err


def test_no_warning_beyond_loopback_once_accounts_are_on(tmp_path, capsys):
    """The warning says the dashboard has no authentication. With accounts
    enabled that is false, and a warning that cries wolf trains people to
    ignore the one that matters."""
    from unittest.mock import patch

    from activitygraph.main import Pipeline
    from activitygraph.server import serve

    accounts, secret = _open_accounts(str(tmp_path / "accounts.db"), None)
    with patch("uvicorn.run"):
        serve(Pipeline(idle_timeout_seconds=5.0), host="0.0.0.0", open_browser=False,
              accounts=accounts, secret=secret)
    assert "no authentication" not in capsys.readouterr().err


# ---------------- the dashboard's auth surface ----------------

@pytest.fixture(scope="module")
def page():
    return WEBAPP.read_text(encoding="utf-8")


def test_the_sign_in_gate_starts_hidden(page):
    """It is revealed only after /api/auth/state confirms accounts are on.
    Shipping it visible would block the single-user mode entirely."""
    assert '<div id="auth-gate" class="auth-gate" hidden>' in page


def test_the_gate_covers_the_page_rather_than_sitting_beside_it(page):
    """A gate that only hides the panels would still have painted them, and
    they would still be in the DOM to read."""
    gate_css = page.split(".auth-gate {")[1].split("}")[0]
    assert "position: fixed" in gate_css
    assert "inset: 0" in gate_css


def test_the_password_field_is_a_password_field(page):
    assert 'id="auth-password" name="password" type="password"' in page


def test_signed_out_requests_stop_polling_instead_of_retrying(page):
    """/api/summary re-polls every few seconds in live mode. Without this
    an expired session turns into a permanent 401 loop against the server."""
    assert "res.status === 401" in page


def test_account_names_are_not_interpolated_into_html(page):
    """Usernames and device names both reach the header and the claimed-device
    list. Everything user-supplied must go through the text-node helper."""
    for line in page.splitlines():
        if "innerHTML" not in line or line.strip().startswith("//"):
            continue
        assert 'innerHTML = ""' in line, f"unexpected innerHTML assignment: {line.strip()}"
