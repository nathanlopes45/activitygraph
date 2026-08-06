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
    # /api/blacklist is three handlers on one path, so keying by path
    # alone keeps only the last one registered.
    routes.update({r.endpoint.__name__: r.endpoint
                   for r in app.routes if hasattr(r, "endpoint")})
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

    result = routes["/api/claim"](FakeRequest(ip=device.ip, token=issue_token(alice.id, SECRET)),
                                  {"name": "iPhone"})
    assert body(result)["claimed"]["mac"] == device.mac.upper()
    assert accounts.macs_for_user(alice.id) == {device.mac.upper()}


def test_claim_from_an_unknown_address_is_refused(env):
    """You cannot claim a device the gateway has never seen."""
    _, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    result = routes["/api/claim"](FakeRequest(ip="203.0.113.99", token=issue_token(alice.id, SECRET)),
                                  {"name": "iPhone"})
    assert status(result) == 404


def test_claim_requires_sign_in(env):
    pipeline, _, routes = env
    device = pipeline.devices.all_devices()[0]
    assert status(routes["/api/claim"](FakeRequest(ip=device.ip), {"name": "iPhone"})) == 401


def test_you_can_only_claim_the_device_you_are_using(env):
    """The rule the whole model rests on: browsing from device A cannot
    attach device B, even though both are on the network."""
    pipeline, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    devices = pipeline.devices.all_devices()
    here, other = devices[0], devices[1]

    routes["/api/claim"](FakeRequest(ip=here.ip, token=issue_token(alice.id, SECRET)),
                         {"name": "iPhone"})

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


# ---------------- the admin does not claim ----------------

# An admin already sees every device, so a claim adds nothing to their view.
# It would also take the device away from whoever it belongs to, since a
# device belongs to one group at a time, and they would have no way to get
# it back. Seeing everything and owning nothing is the whole role.

def test_the_admin_cannot_claim_a_device(env):
    pipeline, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    device = pipeline.devices.all_devices()[0]

    result = routes["/api/claim"](
        FakeRequest(ip=device.ip, token=issue_token(admin.id, SECRET)), {"name": "x"})
    assert status(result) == 403
    assert accounts.macs_for_user(admin.id) == set()


def test_the_refusal_explains_what_to_do_instead(env):
    """A bare "forbidden" would read as a bug on the one account that can
    see everything."""
    pipeline, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    device = pipeline.devices.all_devices()[0]

    message = body(routes["/api/claim"](
        FakeRequest(ip=device.ip, token=issue_token(admin.id, SECRET)), {"name": "x"}))["error"]
    assert "personal account" in message


def test_refusing_the_admin_leaves_the_device_claimable_by_its_owner(env):
    """The point of the rule: the device must still be available."""
    pipeline, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    alice = accounts.create_user("alice", "password123")
    device = pipeline.devices.all_devices()[0]

    routes["/api/claim"](FakeRequest(ip=device.ip, token=issue_token(admin.id, SECRET)))
    result = routes["/api/claim"](FakeRequest(ip=device.ip, token=issue_token(alice.id, SECRET)),
                                  {"name": "iPhone"})

    assert status(result) == 200
    assert accounts.macs_for_user(alice.id) == {device.mac.upper()}


def test_the_admin_still_sees_every_device_and_its_traffic(env):
    """Refusing the claim must not narrow what the admin can see."""
    pipeline, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")

    data = body(routes["/api/summary"](FakeRequest(token=issue_token(admin.id, SECRET))))
    assert len(data["devices"]) == len(pipeline.devices.all_devices())
    assert data["flows"], "the admin should still see traffic"
    assert data["viewer"]["sees_all_devices"] is True


def test_the_admin_is_told_not_to_offer_the_claim_button(env):
    pipeline, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    device = pipeline.devices.all_devices()[0]

    data = body(routes["/api/me"](FakeRequest(ip=device.ip, token=issue_token(admin.id, SECRET))))
    assert data["can_claim"] is False


def test_a_normal_account_is_still_offered_the_button(env):
    pipeline, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    device = pipeline.devices.all_devices()[0]

    data = body(routes["/api/me"](FakeRequest(ip=device.ip, token=issue_token(alice.id, SECRET))))
    assert data["can_claim"] is True


def test_the_admin_can_still_release_a_claim_made_earlier(env):
    """Claims made before this rule existed would otherwise be stuck on the
    one account that cannot claim, and so cannot undo it either."""
    pipeline, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    device = pipeline.devices.all_devices()[0]
    accounts.claim_device(admin.id, device.mac)  # as if from before the rule

    result = routes["/api/unclaim"](
        FakeRequest(token=issue_token(admin.id, SECRET)), {"mac": device.mac})
    assert status(result) == 200
    assert accounts.macs_for_user(admin.id) == set()


# ---------------- the name its owner gave it ----------------

# What a device broadcasts about itself varies by make, by OS version and by
# whether it happens to be awake. Its owner always knows what it is, so the
# name is asked for at claim time rather than guessed at forever.

def test_claiming_requires_a_name(env):
    pipeline, accounts, routes = env
    alice = accounts.create_user("alice", "password123")
    device = pipeline.devices.all_devices()[0]

    result = routes["/api/claim"](
        FakeRequest(ip=device.ip, token=issue_token(alice.id, SECRET)), {"name": "  "})
    assert status(result) == 400
    assert accounts.macs_for_user(alice.id) == set()


def test_the_owner_is_part_of_the_name_everyone_sees(env):
    """Sam calling his phone "iPhone" reads as "Sam's iPhone" to whoever
    administers the network, which is what makes it identifiable there."""
    pipeline, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    device = pipeline.devices.all_devices()[0]

    routes["/api/claim"](FakeRequest(ip=device.ip, token=issue_token(sam.id, SECRET)),
                         {"name": "iPhone"})
    assert accounts.device_labels()[device.mac.upper()] == "Sam's iPhone"


def test_the_name_reaches_the_dashboard_immediately(env):
    """Applied as an alias, which outranks every protocol guess, so one
    mechanism covers every panel rather than each needing to know about
    ownership."""
    pipeline, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    admin = accounts.authenticate("theadmin", "password123")
    device = pipeline.devices.all_devices()[0]

    routes["/api/claim"](FakeRequest(ip=device.ip, token=issue_token(sam.id, SECRET)),
                         {"name": "iPhone"})

    data = body(routes["/api/summary"](FakeRequest(token=issue_token(admin.id, SECRET))))
    names = {d["display_name"] for d in data["devices"]}
    assert "Sam's iPhone" in names


def test_a_group_is_named_after_its_person(env):
    _, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    assert sam.group_name == "Sam's group"


def test_usernames_cannot_repeat(env):
    """The whole naming scheme leans on the username being unique: two Sams
    would produce two indistinguishable "Sam's iPhone"."""
    from activitygraph.accounts import AccountError

    _, accounts, _ = env
    accounts.create_user("Sam", "password123")
    with pytest.raises(AccountError):
        accounts.create_user("sam", "password123")


def test_releasing_a_device_takes_its_name_back(env):
    """Otherwise it would keep reading as Sam's after he gave it up."""
    pipeline, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    device = pipeline.devices.all_devices()[0]

    routes["/api/claim"](FakeRequest(ip=device.ip, token=issue_token(sam.id, SECRET)),
                         {"name": "iPhone"})
    routes["/api/unclaim"](FakeRequest(token=issue_token(sam.id, SECRET)),
                           {"mac": device.mac})
    assert accounts.device_labels() == {}


# ---------------- blacklists ----------------

# A group's own list, not a network-wide one: one person's distraction is
# another person's work. The rule that carries the weight is that editing
# someone else's list requires being the admin.

@pytest.mark.parametrize("typed,stored", [
    # A recognised service is stored as the service, however it was written,
    # so blocking it covers the app as well as the website.
    ("tiktok.com", "service:TikTok"),
    ("TikTok.com", "service:TikTok"),
    ("www.tiktok.com", "service:TikTok"),
    ("https://www.tiktok.com/foryou?lang=en", "service:TikTok"),
    ("  instagram.com/  ", "service:Instagram"),
    ("tiktok.com:443", "service:TikTok"),
    # Anything else keeps its domain, since there is nothing wider to mean.
    ("https://shop.example.invalid/x", "shop.example.invalid"),
    ("WWW.Example.Invalid", "example.invalid"),
])
def test_what_someone_types_is_reduced_to_what_they_meant(typed, stored):
    """People paste URLs and type "www." out of habit. Storing those
    verbatim gives a list nobody can reason about and a rule that has to
    match every variant."""
    from activitygraph.accounts import normalise_blocked_pattern

    assert normalise_blocked_pattern(typed) == stored


@pytest.mark.parametrize("nonsense", ["", "   ", "not a domain", "localhost", "/", "http://"])
def test_things_that_do_not_name_a_domain_are_refused(nonsense):
    from activitygraph.accounts import normalise_blocked_pattern

    assert normalise_blocked_pattern(nonsense) == ""


def test_a_user_manages_their_own_list(env):
    _, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    token = issue_token(sam.id, SECRET)

    routes["add_blacklist"](FakeRequest(token=token), {"pattern": "https://www.TikTok.com/foryou"})
    assert accounts.blocked_for(sam.id) == ["service:TikTok"]

    data = body(routes["get_blacklist"](FakeRequest(token=token)))
    assert data["patterns"] == ["service:TikTok"]
    assert data["group"] == "Sam's group"


def test_adding_the_same_entry_twice_is_harmless(env):
    _, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    for _ in range(3):
        accounts.add_blocked(sam.id, "tiktok.com")
    assert accounts.blocked_for(sam.id) == ["service:TikTok"]


def test_one_group_cannot_edit_anothers_list(env):
    """The rule the per-group model rests on."""
    _, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    bob = accounts.create_user("Bob", "password123")

    result = routes["add_blacklist"](
        FakeRequest(token=issue_token(bob.id, SECRET)),
        {"pattern": "tiktok.com", "user_id": sam.id})

    assert status(result) == 403
    assert accounts.blocked_for(sam.id) == []


def test_a_user_does_not_see_anyone_elses_list(env):
    _, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    bob = accounts.create_user("Bob", "password123")
    accounts.add_blocked(sam.id, "tiktok.com")

    data = body(routes["get_blacklist"](FakeRequest(token=issue_token(bob.id, SECRET))))
    assert data["patterns"] == []
    assert "groups" not in data, "only the admin sees every group"


def test_the_admin_sees_every_group_with_the_devices_it_applies_to(env):
    """Enforcement needs both halves: a block applies to that group's
    devices and nobody else's."""
    pipeline, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    sam = accounts.create_user("Sam", "password123")
    device = pipeline.devices.all_devices()[0]
    accounts.claim_device(sam.id, device.mac, "iPhone")
    accounts.add_blocked(sam.id, "tiktok.com")

    data = body(routes["get_blacklist"](FakeRequest(token=issue_token(admin.id, SECRET))))
    assert data["is_admin"] is True
    sams = [g for g in data["groups"] if g["username"] == "Sam"][0]
    assert sams["patterns"] == ["service:TikTok"]
    assert sams["device_macs"] == [device.mac.upper()]


def test_the_admin_can_update_another_groups_list(env):
    _, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    sam = accounts.create_user("Sam", "password123")

    routes["add_blacklist"](FakeRequest(token=issue_token(admin.id, SECRET)),
                            {"pattern": "tiktok.com", "user_id": sam.id})
    assert accounts.blocked_for(sam.id) == ["service:TikTok"]


def test_removing_an_entry_that_is_not_there_says_so(env):
    _, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    result = routes["remove_blacklist"](
        FakeRequest(token=issue_token(sam.id, SECRET)), {"pattern": "nothere.com"})
    assert status(result) in (400, 404)


def test_a_blacklist_needs_a_sign_in(env):
    _, _, routes = env
    assert status(routes["get_blacklist"](FakeRequest())) == 401


# ---------------- daily limits ----------------

def test_a_user_sets_a_limit_in_minutes(env):
    _, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    routes["set_quota"](FakeRequest(token=issue_token(sam.id, SECRET)),
                        {"service": "YouTube", "minutes": 60})
    assert accounts.quotas_for(sam.id) == {"YouTube": 3600}


def test_a_zero_limit_removes_it(env):
    _, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    accounts.set_quota(sam.id, "YouTube", 3600)
    routes["set_quota"](FakeRequest(token=issue_token(sam.id, SECRET)),
                        {"service": "YouTube", "minutes": 0})
    assert accounts.quotas_for(sam.id) == {}


def test_one_group_cannot_set_anothers_limit(env):
    _, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    bob = accounts.create_user("Bob", "password123")
    result = routes["set_quota"](FakeRequest(token=issue_token(bob.id, SECRET)),
                                 {"service": "YouTube", "minutes": 60, "user_id": sam.id})
    assert status(result) == 403
    assert accounts.quotas_for(sam.id) == {}


def test_the_admin_sees_every_groups_limits(env):
    _, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    sam = accounts.create_user("Sam", "password123")
    accounts.set_quota(sam.id, "YouTube", 3600)

    data = body(routes["get_quotas"](FakeRequest(token=issue_token(admin.id, SECRET))))
    sams = [g for g in data["groups"] if g["username"] == "Sam"][0]
    assert sams["limits"][0]["service"] == "YouTube"
    assert sams["limits"][0]["daily_seconds"] == 3600


def test_a_limit_reports_whether_it_can_actually_be_enforced(env):
    """A limit on something with no known front door is recorded but never
    blocks, and saying so is better than a promise the tool will not keep."""
    _, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    accounts.set_quota(sam.id, "YouTube", 3600)
    accounts.set_quota(sam.id, "Some Internal Tool", 600)

    data = body(routes["get_quotas"](FakeRequest(token=issue_token(sam.id, SECRET))))
    by_service = {row["service"]: row["enforceable"] for row in data["limits"]}
    assert by_service == {"YouTube": True, "Some Internal Tool": False}


def test_usage_is_unioned_across_a_groups_devices(tmp_path):
    """A phone and a laptop both on YouTube for the same hour have spent an
    hour of the group's allowance, not two."""
    from datetime import datetime, timedelta, timezone

    from activitygraph.storage import HistoryStore

    store = HistoryStore(str(tmp_path / "h.db"))
    day = (datetime.now(timezone.utc) + store.tz_offset).date().isoformat()
    start = datetime.now(timezone.utc).replace(microsecond=0)

    for ip, mac in (("192.168.50.50", "AA:BB:CC:00:00:01"),
                    ("192.168.50.51", "AA:BB:CC:00:00:02")):
        store._conn.execute(
            """INSERT INTO category_intervals
               (device_ip, device_mac, category, service, start_time, end_time,
                local_day, recorded_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (ip, mac, "Entertainment", "YouTube",
             start.isoformat(), (start + timedelta(minutes=30)).isoformat(),
             day, start.isoformat()))
    store._conn.commit()

    used = store.service_seconds_today(["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"])
    assert used["YouTube"] == pytest.approx(1800, abs=2), "overlapping time counted twice"
    store.close()


def test_another_groups_devices_do_not_count_toward_a_limit(tmp_path):
    from datetime import datetime, timedelta, timezone

    from activitygraph.storage import HistoryStore

    store = HistoryStore(str(tmp_path / "h.db"))
    day = (datetime.now(timezone.utc) + store.tz_offset).date().isoformat()
    start = datetime.now(timezone.utc).replace(microsecond=0)
    store._conn.execute(
        """INSERT INTO category_intervals
           (device_ip, device_mac, category, service, start_time, end_time,
            local_day, recorded_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        ("192.168.50.60", "BB:BB:BB:00:00:09", "Entertainment", "YouTube",
         start.isoformat(), (start + timedelta(hours=3)).isoformat(), day, start.isoformat()))
    store._conn.commit()

    assert store.service_seconds_today(["AA:BB:CC:00:00:01"]) == {}
    store.close()


def test_unblocking_a_service_actually_removes_it(env):
    """The reported bug. Entries are stored as "service:YouTube", and
    removing one passed that back through the normaliser, whose
    port-stripping turned it into "service": no dot, rejected as not a
    domain, so the delete matched nothing and the button did nothing."""
    _, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    token = issue_token(sam.id, SECRET)

    routes["add_blacklist"](FakeRequest(token=token), {"pattern": "YouTube"})
    stored = accounts.blocked_for(sam.id)
    assert stored == ["service:YouTube"]

    result = routes["remove_blacklist"](FakeRequest(token=token), {"pattern": stored[0]})
    assert status(result) == 200
    assert accounts.blocked_for(sam.id) == []


def test_unblocking_a_plain_domain_still_works(env):
    _, accounts, routes = env
    sam = accounts.create_user("Sam", "password123")
    token = issue_token(sam.id, SECRET)

    routes["add_blacklist"](FakeRequest(token=token), {"pattern": "example.invalid"})
    routes["remove_blacklist"](FakeRequest(token=token), {"pattern": "example.invalid"})
    assert accounts.blocked_for(sam.id) == []


def test_the_admin_can_unblock_another_groups_entry(env):
    """The admin panel offers the same control, so it has to work there too."""
    _, accounts, routes = env
    admin = accounts.authenticate("theadmin", "password123")
    sam = accounts.create_user("Sam", "password123")
    accounts.add_blocked(sam.id, "TikTok")

    routes["remove_blacklist"](FakeRequest(token=issue_token(admin.id, SECRET)),
                               {"pattern": "service:TikTok", "user_id": sam.id})
    assert accounts.blocked_for(sam.id) == []


def test_what_is_stored_can_always_be_removed(env):
    """Anything add stores, remove must find. The two went out of step
    because only one of them normalised."""
    from activitygraph.accounts import normalise_blocked_pattern

    for typed in ["YouTube", "youtube.com", "https://www.tiktok.com/x", "example.invalid"]:
        stored = normalise_blocked_pattern(typed)
        assert normalise_blocked_pattern(stored) == stored, \
            f"{typed!r} stored as {stored!r} but re-normalises to something else"
