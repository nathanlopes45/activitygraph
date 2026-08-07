"""An admin changing somebody else's limits.

Removing one from the admin panel did nothing visible. The page sent no
user_id, the server read that as "my own", and it deleted a limit the admin
did not have while the group's limit stayed exactly where it was. The
response was 200 and the page threw it away, so a refusal and a success
looked identical: the row just came back on the next refresh.
"""
import json
import sqlite3
import threading

import pytest

from activitygraph.accounts import AccountStore, issue_token
from activitygraph.main import run_demo
from activitygraph.server import SESSION_COOKIE, create_app

SECRET = b"test-secret-key-32-bytes-long!!!"


class FakeClient:
    def __init__(self, host):
        self.host = host


class FakeRequest:
    def __init__(self, ip="192.168.50.64", token=None):
        self.client = FakeClient(ip)
        self.cookies = {SESSION_COOKIE: token} if token else {}


def body(result):
    return json.loads(result.body) if hasattr(result, "body") else result


def status(result):
    return getattr(result, "status_code", 200)


@pytest.fixture
def env():
    pipeline = run_demo(idle_timeout=5.0)
    accounts = AccountStore(sqlite3.connect(":memory:", check_same_thread=False))
    admin = accounts.create_user("theadmin", "password123")
    sam = accounts.create_user("sam", "password123")
    accounts.set_quota(sam.id, "YouTube", 3600)
    app = create_app(pipeline, live=False, accounts=accounts, secret=SECRET)
    return {
        "accounts": accounts, "admin": admin, "sam": sam,
        "routes": {r.endpoint.__name__: r.endpoint
                   for r in app.routes if hasattr(r, "endpoint")},
        "admin_token": issue_token(admin.id, SECRET),
        "sam_token": issue_token(sam.id, SECRET),
    }


def test_the_admin_view_carries_the_user_id_each_row_belongs_to(env):
    """The page cannot address the right group without it, and the limit
    rows themselves do not carry one."""
    payload = body(env["routes"]["get_quotas"](FakeRequest(token=env["admin_token"])))
    group = payload["groups"][0]
    assert group["user_id"] == env["sam"].id
    assert [row["service"] for row in group["limits"]] == ["YouTube"]


def test_an_admin_removes_the_limit_it_was_shown(env):
    result = env["routes"]["set_quota"](
        FakeRequest(token=env["admin_token"]),
        {"service": "YouTube", "minutes": 0, "user_id": env["sam"].id})
    assert status(result) == 200
    assert env["accounts"].quotas_for(env["sam"].id) == {}


def test_removing_without_naming_the_owner_does_not_touch_another_group(env):
    """What the page used to send. It must not silently succeed against the
    wrong account, which is what made the bug invisible."""
    env["routes"]["set_quota"](FakeRequest(token=env["admin_token"]),
                               {"service": "YouTube", "minutes": 0})
    assert env["accounts"].quotas_for(env["sam"].id) == {"YouTube": 3600}


def test_a_user_still_removes_their_own_without_naming_themselves(env):
    """The personal view sends no user_id and must keep working."""
    result = env["routes"]["set_quota"](FakeRequest(token=env["sam_token"]),
                                        {"service": "YouTube", "minutes": 0})
    assert status(result) == 200
    assert env["accounts"].quotas_for(env["sam"].id) == {}


def test_a_user_cannot_remove_somebody_elses(env):
    other = env["accounts"].create_user("alex", "password123")
    env["accounts"].set_quota(other.id, "TikTok", 600)

    result = env["routes"]["set_quota"](
        FakeRequest(token=env["sam_token"]),
        {"service": "TikTok", "minutes": 0, "user_id": other.id})
    assert status(result) == 403
    assert env["accounts"].quotas_for(other.id) == {"TikTok": 600}


def test_naming_a_user_that_does_not_exist_is_refused(env):
    result = env["routes"]["set_quota"](
        FakeRequest(token=env["admin_token"]),
        {"service": "YouTube", "minutes": 0, "user_id": 999999})
    assert status(result) == 404


# ---------------- the shared connection ----------------

def test_the_store_survives_two_threads(env):
    """The store is opened with check_same_thread=False and used by request
    handlers and the background pass at once. A read interleaved with
    another thread's write can raise, and a failure inside a request handler
    surfaces to the person using it as suddenly not being signed in."""
    accounts, admin, sam = env["accounts"], env["admin"], env["sam"]
    errors = []
    stop = threading.Event()

    def background():
        while not stop.is_set():
            try:
                accounts.device_labels()
                accounts.group_map()
                accounts.blocked_by_group()
            except Exception as exc:          # noqa: BLE001 - the point
                errors.append(f"background: {type(exc).__name__}: {exc}")
                return

    worker = threading.Thread(target=background, daemon=True)
    worker.start()
    try:
        for index in range(300):
            try:
                accounts.set_quota(sam.id, "YouTube", 60 + index)
                accounts.claim_device(sam.id, "AA:BB:CC:00:00:01", "phone")
                assert accounts.get_user(admin.id) is not None, "the admin vanished"
            except Exception as exc:          # noqa: BLE001 - the point
                errors.append(f"request: {type(exc).__name__}: {exc}")
                break
    finally:
        stop.set()
        worker.join(timeout=3)

    assert errors == [], errors[:2]
