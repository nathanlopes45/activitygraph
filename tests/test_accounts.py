"""Tests for accounts, password hashing and session tokens.

These cover the properties that decide whether the login is real protection
or decoration: that passwords are never recoverable from storage, that a
client cannot edit its own session, and that one user cannot reach another
user's devices.
"""
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from activitygraph.accounts import (
    AccountError,
    AccountStore,
    hash_password,
    issue_token,
    load_or_create_secret,
    read_token,
    verify_password,
)

SECRET = b"0" * 32
NOW = datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def store():
    return AccountStore(sqlite3.connect(":memory:"))


# ---------------- password hashing ----------------

def test_correct_password_verifies():
    encoded = hash_password("correct horse battery")
    assert verify_password("correct horse battery", encoded) is True


def test_wrong_password_rejected():
    encoded = hash_password("correct horse battery")
    assert verify_password("Correct horse battery", encoded) is False
    assert verify_password("", encoded) is False


def test_hash_never_contains_the_password():
    """The stored value must not be reversible or greppable."""
    encoded = hash_password("hunter2")
    assert "hunter2" not in encoded


def test_same_password_hashes_differently_each_time():
    """Per-user salt, so identical passwords do not produce identical hashes
    and a stolen database cannot be attacked with one rainbow table."""
    assert hash_password("same") != hash_password("same")


def test_malformed_hash_is_rejected_not_crashed():
    for bad in ("", "garbage", "pbkdf2_sha256$notanint$a$b", "md5$1$a$b"):
        assert verify_password("anything", bad) is False


# ---------------- session tokens ----------------

def test_valid_token_round_trips():
    token = issue_token(7, SECRET, now=NOW)
    assert read_token(token, SECRET, now=NOW) == 7


def test_token_signed_with_another_secret_is_rejected():
    token = issue_token(7, SECRET, now=NOW)
    assert read_token(token, b"1" * 32, now=NOW) is None


def test_tampered_payload_is_rejected():
    """The whole point of signing: editing the cookie must not promote you."""
    forged = issue_token(999, SECRET, now=NOW).split(".")[0]
    genuine_signature = issue_token(7, SECRET, now=NOW).split(".")[1]
    assert read_token(f"{forged}.{genuine_signature}", SECRET, now=NOW) is None


def test_expired_token_is_rejected():
    token = issue_token(7, SECRET, lifetime=timedelta(hours=1), now=NOW)
    assert read_token(token, SECRET, now=NOW + timedelta(hours=2)) is None


def test_garbage_token_is_rejected_not_crashed():
    for bad in ("", "no-dot", "a.b", "...", "x" * 500):
        assert read_token(bad, SECRET, now=NOW) is None


# ---------------- secret persistence ----------------

def test_secret_is_created_once_and_reused(tmp_path):
    path = str(tmp_path / "secret.key")
    first = load_or_create_secret(path)
    assert len(first) >= 32
    assert load_or_create_secret(path) == first, "sessions must survive a restart"


def test_secret_with_whitespace_bytes_at_the_edges_survives_a_reload(tmp_path):
    """The secret is random bytes, not text, so some fraction of installs
    get one starting or ending with a byte that is ASCII whitespace.
    Trimming it on read would load a different key than was written and
    invalidate every existing session on restart."""
    path = tmp_path / "secret.key"
    written = b"\n " + b"k" * 28 + b" \t"
    path.write_bytes(written)
    assert load_or_create_secret(str(path)) == written


def test_a_reloaded_secret_still_validates_existing_tokens(tmp_path):
    """The consequence that matters, stated directly."""
    path = str(tmp_path / "secret.key")
    token = issue_token(7, load_or_create_secret(path))
    assert read_token(token, load_or_create_secret(path)) == 7


# ---------------- registration ----------------

def test_first_user_becomes_admin(store):
    """Open registration otherwise leaves nobody able to see the network."""
    first = store.create_user("alice", "password123")
    second = store.create_user("bob", "password123")
    assert first.is_admin is True
    assert second.is_admin is False


def test_duplicate_username_rejected(store):
    store.create_user("alice", "password123")
    with pytest.raises(AccountError):
        store.create_user("alice", "different123")


def test_username_comparison_is_case_insensitive(store):
    store.create_user("alice", "password123")
    with pytest.raises(AccountError):
        store.create_user("ALICE", "password123")


@pytest.mark.parametrize("username", ["ab", "x" * 33, "has space", "has/slash", ""])
def test_invalid_usernames_rejected(store, username):
    with pytest.raises(AccountError):
        store.create_user(username, "password123")


def test_short_password_rejected(store):
    with pytest.raises(AccountError):
        store.create_user("alice", "short")


def test_user_dict_excludes_password_material(store):
    payload = store.create_user("alice", "password123").to_dict()
    assert set(payload) == {"id", "username", "group", "is_admin"}


# ---------------- authentication ----------------

def test_authenticate_accepts_correct_credentials(store):
    store.create_user("alice", "password123")
    assert store.authenticate("alice", "password123").username == "alice"


def test_authenticate_rejects_wrong_password(store):
    store.create_user("alice", "password123")
    assert store.authenticate("alice", "wrongpassword") is None


def test_authenticate_rejects_unknown_user_the_same_way(store):
    """An unknown username and a wrong password must be indistinguishable, so
    the response cannot be used to enumerate accounts."""
    store.create_user("alice", "password123")
    assert store.authenticate("nobody", "password123") is None
    assert store.authenticate("alice", "wrongpassword") is None


# ---------------- device claiming ----------------

def test_claim_assigns_device_to_user(store):
    alice = store.create_user("alice", "password123")
    store.claim_device(alice.id, "aa:bb:cc:00:00:01")
    assert store.macs_for_user(alice.id) == {"AA:BB:CC:00:00:01"}


def test_claiming_is_case_insensitive_on_mac(store):
    alice = store.create_user("alice", "password123")
    store.claim_device(alice.id, "aa:bb:cc:00:00:01")
    assert store.owner_of("AA:BB:CC:00:00:01") == alice.id


def test_a_device_belongs_to_only_one_user(store):
    """Otherwise two people could both claim a device and both see its
    traffic, which defeats the scoping entirely."""
    alice = store.create_user("alice", "password123")
    bob = store.create_user("bob", "password123")

    store.claim_device(alice.id, "AA:BB:CC:00:00:01")
    store.claim_device(bob.id, "AA:BB:CC:00:00:01")

    assert store.macs_for_user(alice.id) == set()
    assert store.macs_for_user(bob.id) == {"AA:BB:CC:00:00:01"}


def test_release_only_affects_your_own_device(store):
    alice = store.create_user("alice", "password123")
    bob = store.create_user("bob", "password123")
    store.claim_device(alice.id, "AA:BB:CC:00:00:01")

    assert store.release_device(bob.id, "AA:BB:CC:00:00:01") is False
    assert store.macs_for_user(alice.id) == {"AA:BB:CC:00:00:01"}

    assert store.release_device(alice.id, "AA:BB:CC:00:00:01") is True
    assert store.macs_for_user(alice.id) == set()


def test_group_map_reports_group_names(store):
    alice = store.create_user("alice", "password123", group_name="Alice's things")
    store.claim_device(alice.id, "AA:BB:CC:00:00:01")
    assert store.group_map() == {"AA:BB:CC:00:00:01": "Alice's things"}


def test_users_see_no_devices_by_default(store):
    alice = store.create_user("alice", "password123")
    assert store.macs_for_user(alice.id) == set()
