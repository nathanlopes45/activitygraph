"""What the API does with input nobody intended to send.

Every case here was a live 500 or a silent write to the wrong place, found
by throwing odd but reachable values at the endpoints a signed-in person can
call. None of them needed a hostile user: "nan" in a number box and a
mistyped id in the admin panel are both things that happen by accident.
"""
import json
import sqlite3

import pytest

from activitygraph.accounts import AccountStore, issue_token
from activitygraph.main import run_demo
from activitygraph.server import MAX_LIMIT_MINUTES, SESSION_COOKIE, create_app

SECRET = b"test-secret-key-32-bytes-long!!!"


class FakeClient:
    def __init__(self, host):
        self.host = host


class FakeRequest:
    def __init__(self, ip="192.168.1.10", token=None):
        self.client = FakeClient(ip)
        self.cookies = {SESSION_COOKIE: token} if token else {}


@pytest.fixture
def env():
    pipeline = run_demo(idle_timeout=5.0)
    accounts = AccountStore(sqlite3.connect(":memory:"))
    admin = accounts.create_user("theadmin", "password123")
    sam = accounts.create_user("sam", "password123")
    app = create_app(pipeline, live=False, accounts=accounts, secret=SECRET)
    routes = {r.endpoint.__name__: r.endpoint
              for r in app.routes if hasattr(r, "endpoint")}
    return {
        "accounts": accounts, "routes": routes,
        "admin": admin, "sam": sam,
        "admin_token": issue_token(admin.id, SECRET),
        "sam_token": issue_token(sam.id, SECRET),
    }


def body(result):
    if hasattr(result, "body"):
        return json.loads(result.body)
    return result


def status(result):
    return getattr(result, "status_code", 200)


# ---------------- daily limits ----------------

@pytest.mark.parametrize("minutes", ["nan", "inf", "-inf", 1e30, -5, MAX_LIMIT_MINUTES + 1])
def test_an_unusable_limit_is_refused_not_crashed(env, minutes):
    """float() accepts nan and inf, and int() then raises: the person who
    typed it got a 500 rather than being told what to type instead."""
    result = env["routes"]["set_quota"](
        FakeRequest(token=env["sam_token"]), {"service": "YouTube", "minutes": minutes})
    assert status(result) == 400
    assert "minutes" in body(result)["error"].lower()


def test_a_normal_limit_still_works(env):
    result = env["routes"]["set_quota"](
        FakeRequest(token=env["sam_token"]), {"service": "YouTube", "minutes": 60})
    assert body(result)["limits"] == {"YouTube": 3600}


def test_a_whole_day_is_allowed(env):
    """The boundary is the useful value, not an off-by-one to trip over."""
    result = env["routes"]["set_quota"](
        FakeRequest(token=env["sam_token"]),
        {"service": "YouTube", "minutes": MAX_LIMIT_MINUTES})
    assert status(result) == 200


# ---------------- whose list is being edited ----------------

@pytest.mark.parametrize("user_id", ["abc", [], {"a": 1}, True])
def test_a_malformed_user_id_is_refused_not_crashed(env, user_id):
    result = env["routes"]["add_blacklist"](
        FakeRequest(token=env["admin_token"]),
        {"pattern": "tiktok.com", "user_id": user_id})
    assert status(result) in (403, 404)


@pytest.mark.parametrize("user_id", [999999, -1, 0])
def test_an_unknown_user_id_writes_nothing(env, user_id):
    """SQLite does not enforce the foreign key unless asked, and this
    connection does not ask, so the row landed as an orphan: an entry no
    group displays and no rule applies, which reads as blocking that does
    nothing."""
    result = env["routes"]["add_blacklist"](
        FakeRequest(token=env["admin_token"]),
        {"pattern": "tiktok.com", "user_id": user_id})
    assert status(result) == 404

    rows = env["accounts"]._conn.execute("SELECT COUNT(*) FROM blacklist").fetchone()[0]
    assert rows == 0, "an entry was stored against a user that does not exist"


def test_a_float_user_id_does_not_land_on_a_different_user(env):
    """int(1.5) is 1, which is a real account: the entry would silently be
    added to somebody else's list."""
    env["routes"]["add_blacklist"](
        FakeRequest(token=env["admin_token"]),
        {"pattern": "tiktok.com", "user_id": env["sam"].id + 0.5})
    assert env["accounts"].blocked_for(env["admin"].id) == []
    assert env["accounts"].blocked_for(env["sam"].id) == []


def test_an_admin_can_still_edit_a_real_users_list(env):
    """The guard must not cost the admin panel the thing it exists for."""
    result = env["routes"]["add_blacklist"](
        FakeRequest(token=env["admin_token"]),
        {"pattern": "tiktok.com", "user_id": env["sam"].id})
    assert status(result) == 200
    assert env["accounts"].blocked_for(env["sam"].id) == ["service:TikTok"]


def test_a_user_id_sent_as_a_string_still_works(env):
    """Form fields and JSON round-trips both produce strings."""
    result = env["routes"]["add_blacklist"](
        FakeRequest(token=env["admin_token"]),
        {"pattern": "tiktok.com", "user_id": str(env["sam"].id)})
    assert status(result) == 200


def test_a_normal_user_naming_somebody_else_is_refused(env):
    result = env["routes"]["add_blacklist"](
        FakeRequest(token=env["sam_token"]),
        {"pattern": "tiktok.com", "user_id": env["admin"].id})
    assert status(result) == 403
    assert env["accounts"].blocked_for(env["admin"].id) == []


# ---------------- unblocking round trip ----------------

@pytest.mark.parametrize("typed", ["service:YouTube", "service:youtube", "SERVICE:YOUTUBE"])
def test_unblocking_matches_however_the_entry_is_cased(env, typed):
    """Stored form is "service:YouTube". Any other casing matched no row, so
    the unblock reported success and left the block in place."""
    accounts = env["accounts"]
    accounts.add_blocked(env["sam"].id, "YouTube")
    assert accounts.blocked_for(env["sam"].id) == ["service:YouTube"]

    assert accounts.remove_blocked(env["sam"].id, typed) is True
    assert accounts.blocked_for(env["sam"].id) == []
