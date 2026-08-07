"""Making "it is not blocking" answerable.

Blocking is invisible from the outside. No rule written, a rule naming an
address the traffic never goes to, and nft rejecting the ruleset all look
identical from a phone that can still load YouTube. Every one of those
happened, and each time the only way to tell them apart was to read the
journal on the gateway.
"""
import json
import sqlite3

import pytest

from activitygraph.accounts import AccountStore, issue_token
from activitygraph.main import run_demo
from activitygraph.server import BackgroundCapture, SESSION_COOKIE, create_app

SECRET = b"test-secret-key-32-bytes-long!!!"
PHONE = "AA:BB:CC:00:00:01"


class FakeClient:
    def __init__(self, host):
        self.host = host


class FakeRequest:
    def __init__(self, ip="192.168.1.10", token=None):
        self.client = FakeClient(ip)
        self.cookies = {SESSION_COOKIE: token} if token else {}


def body(result):
    return json.loads(result.body) if hasattr(result, "body") else result


def status(result):
    return getattr(result, "status_code", 200)


@pytest.fixture
def env():
    pipeline = run_demo(idle_timeout=5.0)
    accounts = AccountStore(sqlite3.connect(":memory:"))
    admin = accounts.create_user("theadmin", "password123")
    sam = accounts.create_user("sam", "password123")
    accounts.claim_device(sam.id, PHONE, "iPhone")
    return {"pipeline": pipeline, "accounts": accounts, "admin": admin, "sam": sam,
            "admin_token": issue_token(admin.id, SECRET),
            "sam_token": issue_token(sam.id, SECRET)}


def routes_for(env, capture=None):
    app = create_app(env["pipeline"], live=True, accounts=env["accounts"],
                     secret=SECRET, capture=capture, enforce_blacklist=True)
    return {r.endpoint.__name__: r.endpoint for r in app.routes if hasattr(r, "endpoint")}


# ---------------- who may ask ----------------

def test_a_stranger_is_refused(env):
    assert status(routes_for(env)["enforcement"](FakeRequest())) == 401


def test_a_normal_user_is_refused(env):
    """It names every group's lists, which is the admin's business."""
    result = routes_for(env)["enforcement"](FakeRequest(token=env["sam_token"]))
    assert status(result) == 403


def test_an_admin_may_ask(env):
    result = routes_for(env)["enforcement"](FakeRequest(token=env["admin_token"]))
    assert status(result) == 200


# ---------------- what it says ----------------

def test_a_demo_run_says_so_rather_than_looking_broken(env):
    payload = body(routes_for(env)["enforcement"](FakeRequest(token=env["admin_token"])))
    assert payload["enabled"] is False
    assert "live capture" in payload["message"]


def test_enforcement_switched_off_is_named_as_the_reason(env):
    capture = BackgroundCapture(env["pipeline"], accounts=env["accounts"],
                                enforce_blacklist=False)
    capture._refresh_blacklist()
    assert capture.enforcement_status()["message"] == "started without --enforce-blacklist"


def test_a_refresh_reports_what_it_resolved(env):
    """The numbers that answer "why is nothing dropped": how many addresses
    the group's devices hold, and how many the patterns resolved to."""
    accounts = env["accounts"]
    accounts.add_blocked(env["sam"].id, "YouTube")

    capture = BackgroundCapture(env["pipeline"], accounts=accounts,
                                enforce_blacklist=True)
    # Stand in for the learned DNS map. Cleared first: the demo pipeline
    # ships with its own entries, and the count below is the assertion.
    env["pipeline"].services._dns_cache.clear()
    env["pipeline"].services._dns_cache.update({
        "142.250.1.1": "youtube.com",
        "172.217.2.2": "rr3---sn-abc.googlevideo.com",
        "9.9.9.9": "github.com",
    })
    capture._refresh_blacklist()

    report = capture.enforcement_status()
    assert report["enabled"] is True
    assert report["dns_cache_size"] == 3
    group = [g for g in report["groups"] if g["group"] == "sam's group"][0]
    assert group["patterns"] == ["service:YouTube"]
    assert group["blocked_addresses"] == 2, \
        "the site and the host its app streams from, and not github"


def test_a_group_with_no_devices_is_visible_as_such(env):
    """A list with nothing to apply it to blocks nothing, and that is the
    single most likely reason for "I blocked it and it still works"."""
    accounts = env["accounts"]
    accounts.release_device(env["sam"].id, PHONE)
    accounts.add_blocked(env["sam"].id, "YouTube")

    capture = BackgroundCapture(env["pipeline"], accounts=accounts,
                                enforce_blacklist=True)
    capture._refresh_blacklist()

    group = [g for g in capture.enforcement_status()["groups"]
             if g["group"] == "sam's group"][0]
    assert group["device_macs"] == []
    assert group["device_addresses"] == []
