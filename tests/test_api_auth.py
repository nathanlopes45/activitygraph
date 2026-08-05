"""End-to-end tests for authentication, claiming and per-user scoping.

The central test here is `test_user_cannot_see_another_users_device_anywhere`.
It walks the entire response payload rather than checking named fields,
because the failure that matters is a panel nobody remembered to filter. A
test that only checks the fields we thought of would pass while leaking
through the one we forgot.
"""
import json
import sqlite3

import pytest

from activitygraph.accounts import AccountStore, issue_token
from activitygraph.main import run_demo
from activitygraph.server import SESSION_COOKIE, create_app

SECRET = b"test-secret-key-32-bytes-long!!!"


class FakeClient:
    def __init__(self, host):
        self.host = host


class FakeRequest:
    """Minimal stand-in for a Starlette Request: a peer address and cookies."""

    def __init__(self, ip="192.168.1.10", token=None):
        self.client = FakeClient(ip)
        self.cookies = {SESSION_COOKIE: token} if token else {}


class FakeResponse:
    def __init__(self):
        self.cookies = {}
        self.deleted = []

    def set_cookie(self, key, value, **kwargs):
        self.cookies[key] = (value, kwargs)

    def delete_cookie(self, key, **kwargs):
        self.deleted.append(key)


@pytest.fixture
def env():
    """Pipeline, account store and routes, with an admin already present.

    The first account registered becomes the admin, so tests about a
    restricted user must not create the first account themselves. Creating
    the admin here makes every user a test creates a normal one.
    """
    pipeline = run_demo(idle_timeout=5.0)
    accounts = AccountStore(sqlite3.connect(":memory:"))
    accounts.create_user("theadmin", "password123")
    app = create_app(pipeline, live=False, accounts=accounts, secret=SECRET)
    routes = {r.path: r.endpoint for r in app.routes if hasattr(r, "endpoint")}
    return pipeline, accounts, routes


def body(result):
    """Endpoints return dicts or JSONResponse; normalise to a dict."""
    if hasattr(result, "body"):
        return json.loads(result.body)
    return result


def status(result):
    return getattr(result, "status_code", 200)


# ---------------- registration and login ----------------

def test_register_sets_a_session_cookie(env):
    _, _, routes = env
    response = FakeResponse()
    result = routes["/api/auth/register"](response, {"username": "alice", "password": "password123"})
    assert body(result)["user"]["username"] == "alice"
    assert body(result)["user"]["is_admin"] is False, "only the first account is admin"
    assert SESSION_COOKIE in response.cookies


def test_session_cookie_is_httponly_and_samesite(env):
    """Not readable from JavaScript, and not sent on cross-site posts."""
    _, _, routes = env
    response = FakeResponse()
    routes["/api/auth/register"](response, {"username": "alice", "password": "password123"})
    _, options = response.cookies[SESSION_COOKIE]
    assert options["httponly"] is True
    assert options["samesite"] == "lax"


def test_login_rejects_wrong_password_without_saying_why(env):
    _, accounts, routes = env
    accounts.create_user("alice", "password123")
    result = routes["/api/auth/login"](FakeResponse(), {"username": "alice", "password": "nope"})
    assert status(result) == 401
    assert body(result)["error"] == "Incorrect username or password."


def test_unknown_user_gives_the_identical_error(env):
    """So the response cannot be used to discover which accounts exist."""
    _, accounts, routes = env
    accounts.create_user("alice", "password123")
    unknown = routes["/api/auth/login"](FakeResponse(), {"username": "ghost", "password": "password123"})
    wrong = routes["/api/auth/login"](FakeResponse(), {"username": "alice", "password": "nope"})
    assert body(unknown) == body(wrong)
    assert status(unknown) == status(wrong)


# ---------------- access control ----------------

def test_summary_requires_sign_in_when_accounts_enabled(env):
    _, _, routes = env
    result = routes["/api/summary"](FakeRequest())
    assert status(result) == 401


def test_history_requires_sign_in(env):
    _, _, routes = env
    result = routes["/api/history"](FakeRequest())
    assert status(result) == 401


def test_forged_cookie_is_not_accepted(env):
    """A token signed with a different key must not authenticate anyone."""
    _, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    forged = issue_token(alice.id, b"a-completely-different-secret-key")
    assert status(routes["/api/summary"](FakeRequest(token=forged))) == 401


def test_new_user_sees_no_devices_until_they_claim(env):
    """Fail closed: an account with no claims sees nothing, rather than the
    whole network by default."""
    _, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    data = body(routes["/api/summary"](FakeRequest(token=issue_token(alice.id, SECRET))))
    assert data["devices"] == []
    assert data["flows"] == []


# ---------------- device claiming ----------------

def test_claim_attaches_the_requesting_device(env):
    pipeline, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    device = pipeline.devices.all_devices()[0]

    result = routes["/api/claim"](FakeRequest(ip=device.ip, token=issue_token(alice.id, SECRET)))
    assert body(result)["claimed"]["mac"] == device.mac.upper()
    assert accounts.macs_for_user(alice.id) == {device.mac.upper()}


def test_claim_from_an_unknown_address_is_refused(env):
    """You cannot claim a device the gateway has never seen."""
    _, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    result = routes["/api/claim"](FakeRequest(ip="203.0.113.99", token=issue_token(alice.id, SECRET)))
    assert status(result) == 404


def test_claim_requires_sign_in(env):
    pipeline, _, routes = env
    device = pipeline.devices.all_devices()[0]
    assert status(routes["/api/claim"](FakeRequest(ip=device.ip))) == 401


def test_you_can_only_claim_the_device_you_are_using(env):
    """The rule the whole model rests on: browsing from device A cannot
    attach device B, even though both are on the network."""
    pipeline, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    devices = pipeline.devices.all_devices()
    here, other = devices[0], devices[1]

    routes["/api/claim"](FakeRequest(ip=here.ip, token=issue_token(alice.id, SECRET)))

    claimed = accounts.macs_for_user(alice.id)
    assert claimed == {here.mac.upper()}
    assert other.mac.upper() not in claimed


def test_unclaim_refuses_a_device_you_do_not_own(env):
    pipeline, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    bob = accounts.create_user("bob", "password123")
    device = pipeline.devices.all_devices()[0]
    accounts.claim_device(bob.id, device.mac)

    result = routes["/api/unclaim"](
        FakeRequest(token=issue_token(alice.id, SECRET)), {"mac": device.mac})
    assert status(result) == 404
    assert accounts.macs_for_user(bob.id) == {device.mac.upper()}


# ---------------- the property that matters most ----------------

def test_user_cannot_see_another_users_device_anywhere(env):
    """Walk the whole payload rather than named fields.

    The dangerous bug is a panel nobody remembered to filter, so this test
    searches every string in the response for the other device's identifiers
    instead of trusting a list of fields we thought of.
    """
    pipeline, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    bob = accounts.create_user("bob", "password123")

    devices = pipeline.devices.all_devices()
    alice_device, bob_device = devices[0], devices[1]
    accounts.claim_device(alice.id, alice_device.mac)
    accounts.claim_device(bob.id, bob_device.mac)

    payload = json.dumps(body(routes["/api/summary"](
        FakeRequest(token=issue_token(alice.id, SECRET)))))

    assert bob_device.ip not in payload, "another user's IP leaked into the response"
    assert bob_device.mac.upper() not in payload.upper(), "another user's MAC leaked"
    assert alice_device.ip in payload, "the user's own device should be present"


def test_admin_sees_every_device(env):
    pipeline, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    assert admin.is_admin is True

    data = body(routes["/api/summary"](FakeRequest(token=issue_token(admin.id, SECRET))))
    assert len(data["devices"]) == len(pipeline.devices.all_devices())
    assert data["viewer"]["sees_all_devices"] is True


def test_non_admin_viewer_is_marked_as_restricted(env):
    _, accounts, routes = env
    bob = accounts.create_user("bob", "password123")
    data = body(routes["/api/summary"](FakeRequest(token=issue_token(bob.id, SECRET))))
    assert data["viewer"]["sees_all_devices"] is False


# ---------------- accounts disabled ----------------

def test_without_accounts_the_api_stays_open(env):
    """The single-user loopback mode must keep working unchanged."""
    pipeline = run_demo(idle_timeout=5.0)
    app = create_app(pipeline, live=False)
    routes = {r.path: r.endpoint for r in app.routes if hasattr(r, "endpoint")}

    data = body(routes["/api/summary"](FakeRequest()))
    assert len(data["devices"]) == len(pipeline.devices.all_devices())


# ---------------- view filters ----------------

# Filters narrow what a caller may already see. The risk is that a filter
# parameter becomes a second, unchecked way of naming a device, so these
# check it subtracts and never adds.

def test_a_filter_cannot_reveal_another_users_device(env):
    """The one that matters: naming somebody else's MAC in the filter must
    return nothing, not that device."""
    pipeline, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    bob = accounts.create_user("bob", "password123")

    devices = pipeline.devices.all_devices()
    alice_device, bob_device = devices[0], devices[1]
    accounts.claim_device(alice.id, alice_device.mac)
    accounts.claim_device(bob.id, bob_device.mac)

    result = routes["/api/summary"](
        FakeRequest(token=issue_token(alice.id, SECRET)), devices=bob_device.mac)
    payload = json.dumps(body(result))

    assert bob_device.ip not in payload
    assert bob_device.mac.upper() not in payload.upper()
    assert body(result)["devices"] == []


def test_filter_options_are_scoped_to_the_viewer(env):
    """The chips a user is offered must not enumerate the network."""
    pipeline, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    devices = pipeline.devices.all_devices()
    accounts.claim_device(alice.id, devices[0].mac)

    data = body(routes["/api/summary"](FakeRequest(token=issue_token(alice.id, SECRET))))
    offered = {d["mac"] for d in data["filter_options"]["devices"]}
    assert offered == {devices[0].mac.upper()}


def test_admin_can_filter_to_a_single_device(env):
    pipeline, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    target = pipeline.devices.all_devices()[0]

    data = body(routes["/api/summary"](
        FakeRequest(token=issue_token(admin.id, SECRET)), devices=target.mac))
    assert [d["ip"] for d in data["devices"]] == [target.ip]
    assert all(f["src_ip"] == target.ip or f["dst_ip"] == target.ip for f in data["flows"])


def test_admin_can_filter_to_a_service_across_devices(env):
    """The other half of the request: one service, whoever used it."""
    pipeline, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    token = issue_token(admin.id, SECRET)

    everything = body(routes["/api/summary"](FakeRequest(token=token)))
    service = everything["filter_options"]["services"][0]

    data = body(routes["/api/summary"](FakeRequest(token=token), services=service))
    assert data["flows"], "expected at least one flow for a service that was offered"
    assert {f["service"] for f in data["flows"]} == {service}
    assert data["active_filters"]["services"] == [service]


def test_filtering_recomputes_the_time_totals(env):
    """A filter that only hid rows would leave the headline figure stating
    the unfiltered total, which is worse than not filtering at all."""
    pipeline, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    token = issue_token(admin.id, SECRET)

    everything = body(routes["/api/summary"](FakeRequest(token=token)))
    target = pipeline.devices.all_devices()[0]
    one = body(routes["/api/summary"](FakeRequest(token=token), devices=target.mac))

    assert one["time_totals"]["total_active_seconds"] < \
        everything["time_totals"]["total_active_seconds"]


def test_devices_with_nothing_left_drop_out_of_a_service_filter(env):
    """Otherwise they sit at zero, which reads as "used it for no time"
    rather than "did not use it"."""
    pipeline, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    token = issue_token(admin.id, SECRET)

    everything = body(routes["/api/summary"](FakeRequest(token=token)))
    service = everything["filter_options"]["services"][0]
    data = body(routes["/api/summary"](FakeRequest(token=token), services=service))
    assert 0 < len(data["devices"]) <= len(everything["devices"])


def test_an_unknown_filter_value_yields_nothing_rather_than_everything(env):
    """Failing open here would turn a typo into a full disclosure."""
    _, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    data = body(routes["/api/summary"](
        FakeRequest(token=issue_token(admin.id, SECRET)), devices="00:00:00:00:00:00"))
    assert data["devices"] == []
    assert data["flows"] == []
