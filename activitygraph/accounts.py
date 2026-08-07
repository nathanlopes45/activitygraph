"""User accounts, password hashing and session tokens.

This module exists because the dashboard changed from a single-user local
tool into something that holds *other people's* browsing history and decides
who may see it. That is a meaningful shift in responsibility: a login that
looks protective but is not is worse than no login at all, because it invites
exposure the operator believes is covered.

The choices here are deliberately conservative:

- **PBKDF2-HMAC-SHA256 from the standard library**, with a per-user random
  salt and a high iteration count. No new dependency, and no hand-rolled
  cryptography. Passwords are never stored, logged, or returned by any API.
- **HMAC-signed session tokens** carrying only a user id and an expiry. The
  token is verified before it is trusted, so a client cannot edit it to
  become another user or extend its own session.
- **A persisted random secret**, generated once with `secrets` and written
  with owner-only permissions. Signing with a hardcoded or per-process key
  would either be forgeable or log everyone out on restart.

Comparisons that involve secrets use `hmac.compare_digest`, which does not
leak information through how long it takes to fail.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# OWASP's floor for PBKDF2-HMAC-SHA256 has risen over time; this sits above
# the 2023 guidance and costs a few hundred milliseconds per login, which is
# unnoticeable to a person and expensive to an attacker guessing offline.
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
SESSION_LIFETIME = timedelta(days=30)

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{3,32}$")
MIN_PASSWORD_LENGTH = 8


class AccountError(Exception):
    """Raised for conditions the caller is expected to show to a user."""


SERVICE_PREFIX = "service:"


def normalise_blocked_pattern(pattern: str) -> str:
    """Reduce what someone typed to a service name or the domain it names.

    A service name is preferred whenever the text matches one, because
    "YouTube" is what a person means and covers the app, the website and
    whatever host the video actually comes from. Knowing that YouTube video
    arrives from googlevideo.com is not something anyone should need.
    """
    text = (pattern or "").strip()
    if not text:
        return ""

    # Already in stored form, which is what removing an entry passes back.
    # Normalising it again destroyed it: the port-stripping below turns
    # "service:YouTube" into "service", which has no dot and is rejected as
    # not a domain, so the delete matched nothing and unblocking silently
    # did nothing at all.
    from .service_rules import PRIMARY_DOMAINS

    if text.lower().startswith(SERVICE_PREFIX):
        name = text[len(SERVICE_PREFIX):].strip()
        # Canonicalise the case as well as the prefix. Stored form is
        # "service:YouTube", so passing "service:youtube" back matched no row
        # and unblocking reported success while leaving the entry in place.
        for service in PRIMARY_DOMAINS:
            if name.lower() == service.lower():
                return SERVICE_PREFIX + service
        return SERVICE_PREFIX + name

    for service in PRIMARY_DOMAINS:
        if text.lower() == service.lower():
            return SERVICE_PREFIX + service
    # Typing a service's own address means the service, not just that host.
    guessed = _normalise_domain(text)
    if guessed:
        from .service_rules import classify_domain

        match = classify_domain(guessed)
        if match and match.service in PRIMARY_DOMAINS:
            return SERVICE_PREFIX + match.service
    return guessed


def _normalise_domain(pattern: str) -> str:
    """Reduce what someone typed to the domain it names.

    People paste URLs, type "www." out of habit, and capitalise
    inconsistently. Storing those verbatim gives a list nobody can reason
    about and an enforcement rule that has to match every variant, so the
    normalising happens once, here, on the way in.

    Returns "" for anything that does not name a domain, which the caller
    reports rather than storing.
    """
    text = (pattern or "").strip().lower()
    if not text:
        return ""
    text = re.sub(r"^[a-z]+://", "", text)   # scheme
    text = text.split("/")[0]                # path
    text = text.split("?")[0].split("#")[0]
    text = text.split("@")[-1]               # credentials
    text = text.split(":")[0]                # port
    text = text.strip(".")
    if text.startswith("www."):
        text = text[4:]
    # A domain, not a sentence and not an address typed by mistake.
    if not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", text):
        return ""
    return text


@dataclass
class User:
    id: int
    username: str
    group_name: str
    is_admin: bool

    def to_dict(self) -> dict:
        """Safe to serialise: deliberately contains no password material."""
        return {
            "id": self.id,
            "username": self.username,
            "group": self.group_name,
            "is_admin": self.is_admin,
        }


# -- password hashing ------------------------------------------------------

def hash_password(password: str) -> str:
    """Return a self-describing hash string: algorithm, iterations, salt, key.

    Storing the parameters alongside the hash means the iteration count can be
    raised later without invalidating existing accounts.
    """
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ITERATIONS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(derived).decode("ascii"),
    )


def verify_password(password: str, encoded: str) -> bool:
    """Check a password against a stored hash, in constant time."""
    try:
        algorithm, iterations, salt_b64, hash_b64 = encoded.split("$")
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError):
        return False

    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
    return hmac.compare_digest(candidate, expected)


# -- session secret --------------------------------------------------------

def load_or_create_secret(path: str) -> bytes:
    """Read the signing secret, generating it on first use.

    Written with owner-only permissions where the platform supports it. A
    secret readable by other users would let them mint valid sessions for any
    account.
    """
    secret_path = Path(path).expanduser()
    if secret_path.exists():
        # Read back byte-for-byte. Stripping here looks harmless but is not:
        # the secret is 32 random bytes, so roughly one file in twenty
        # begins or ends with a byte that happens to be ASCII whitespace.
        # Those installs would load a different secret than they wrote and
        # invalidate every session on restart, logging out every user.
        return secret_path.read_bytes()

    secret = secrets.token_bytes(32)
    secret_path.parent.mkdir(parents=True, exist_ok=True)
    secret_path.write_bytes(secret)
    if os.name == "posix":
        secret_path.chmod(0o600)
    return secret


# -- session tokens --------------------------------------------------------

def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue_token(user_id: int, secret: bytes, lifetime: timedelta = SESSION_LIFETIME,
                now: Optional[datetime] = None) -> str:
    """Create a signed session token for `user_id`."""
    now = now or datetime.now(timezone.utc)
    payload = json.dumps({
        "uid": user_id,
        "exp": (now + lifetime).timestamp(),
    }, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(secret, payload, hashlib.sha256).digest()
    return f"{_b64url(payload)}.{_b64url(signature)}"


def read_token(token: str, secret: bytes, now: Optional[datetime] = None) -> Optional[int]:
    """Return the user id from a valid, unexpired token, else None.

    The signature is checked *before* the payload is trusted, so a client
    cannot promote itself to another user or extend its own expiry by editing
    the cookie.
    """
    now = now or datetime.now(timezone.utc)
    try:
        payload_b64, signature_b64 = token.split(".")
        payload = _unb64url(payload_b64)
        signature = _unb64url(signature_b64)
    except (ValueError, TypeError):
        return None

    expected = hmac.new(secret, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        return None

    try:
        data = json.loads(payload)
        if float(data["exp"]) < now.timestamp():
            return None
        return int(data["uid"])
    except (ValueError, KeyError, TypeError):
        return None


# -- account store ---------------------------------------------------------

def _synchronised(method):
    """Serialise one method against the shared connection.

    The store is opened with check_same_thread=False and then used from two
    threads at once: request handlers answering the dashboard, and the
    background pass that re-applies names and groups and rebuilds the
    firewall rules every few seconds. sqlite3 will not corrupt anything
    under that, but a read interleaved with another thread's write can
    raise, and a failure inside a request handler surfaces as a signed-in
    person suddenly not being signed in.

    Reentrant, because several of these methods call each other.
    """
    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return wrapper


class AccountStore:
    """Users and their claimed devices, persisted alongside history."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._lock = threading.RLock()
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                group_name TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            -- A device belongs to at most one group, which is why device_mac
            -- is the primary key rather than a plain column. Without that,
            -- two users could each claim the same device and both see it.
            CREATE TABLE IF NOT EXISTS claimed_devices (
                device_mac TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                -- What its owner calls it. A person naming their own phone
                -- is the only reliable source there is: what a device
                -- broadcasts about itself varies by make, by OS version and
                -- by whether it happens to be awake.
                label TEXT,
                claimed_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            -- Domains a group has chosen not to reach. Scoped per user
            -- rather than network-wide: one person's distraction is another
            -- person's work, and a shared list would make every entry an
            -- argument.
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                pattern TEXT NOT NULL,
                added_at TEXT NOT NULL,
                UNIQUE(user_id, pattern),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            -- How long a group is willing to spend on a service each day.
            -- Stored in seconds and per service rather than per domain,
            -- because "an hour of YouTube" is the thing a person means, and
            -- which hosts that turns into is the tool's problem.
            CREATE TABLE IF NOT EXISTS quotas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                service TEXT NOT NULL,
                daily_seconds INTEGER NOT NULL,
                UNIQUE(user_id, service),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        self._conn.commit()

    # -- users -------------------------------------------------------------
    @_synchronised
    def user_count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    @_synchronised
    def create_user(self, username: str, password: str,
                    group_name: Optional[str] = None) -> User:
        """Register an account. The first one created becomes the admin.

        With open registration there is otherwise nobody able to see the whole
        network, and no way to appoint one.
        """
        username = (username or "").strip()
        if not USERNAME_PATTERN.match(username):
            raise AccountError(
                "Username must be 3 to 32 characters, using letters, digits, dot, dash "
                "or underscore."
            )
        if len(password or "") < MIN_PASSWORD_LENGTH:
            raise AccountError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")

        is_admin = self.user_count() == 0
        try:
            cur = self._conn.execute(
                """INSERT INTO users (username, password_hash, group_name, is_admin, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (username, hash_password(password), (group_name or f"{username}'s group").strip(),
                 1 if is_admin else 0, datetime.now(timezone.utc).isoformat()),
            )
        except sqlite3.IntegrityError:
            raise AccountError("That username is already taken.") from None
        self._conn.commit()
        return User(id=cur.lastrowid, username=username,
                    group_name=(group_name or f"{username}'s group").strip(), is_admin=is_admin)

    @_synchronised
    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Return the user on correct credentials, else None.

        The same None is returned for an unknown username and a wrong
        password, so the response cannot be used to discover which accounts
        exist.
        """
        row = self._conn.execute(
            "SELECT id, username, password_hash, group_name, is_admin FROM users WHERE username = ?",
            (username or "",),
        ).fetchone()
        if row is None:
            # Spend roughly the same time as a real check, so response timing
            # does not reveal whether the account exists.
            hash_password(password or "")
            return None
        if not verify_password(password or "", row[2]):
            return None
        return User(id=row[0], username=row[1], group_name=row[3], is_admin=bool(row[4]))

    @_synchronised
    def get_user(self, user_id: int) -> Optional[User]:
        row = self._conn.execute(
            "SELECT id, username, group_name, is_admin FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row is None:
            return None
        return User(id=row[0], username=row[1], group_name=row[2], is_admin=bool(row[3]))

    @_synchronised
    def set_group_name(self, user_id: int, group_name: str) -> None:
        group_name = (group_name or "").strip()
        if not group_name:
            raise AccountError("Group name cannot be empty.")
        self._conn.execute("UPDATE users SET group_name = ? WHERE id = ?", (group_name, user_id))
        self._conn.commit()

    # -- claimed devices ---------------------------------------------------
    @_synchronised
    def claim_device(self, user_id: int, mac: str, label: Optional[str] = None) -> None:
        """Attach a device to this user under a name they chose.

        Re-claiming is allowed because the claim can only be made from the
        device itself, so whoever is holding it is the person entitled to say
        where it belongs, and what it is called.
        """
        self._conn.execute(
            """INSERT INTO claimed_devices (device_mac, user_id, label, claimed_at)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(device_mac) DO UPDATE SET
                 user_id = excluded.user_id,
                 label = excluded.label,
                 claimed_at = excluded.claimed_at""",
            (mac.upper(), user_id, (label or "").strip() or None,
             datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()

    @_synchronised
    def device_labels(self) -> dict:
        """Every claimed device's MAC mapped to "<owner>'s <name>".

        Fed to the device registry as aliases, which already outrank every
        protocol guess, so one mechanism covers the whole dashboard rather
        than each panel needing to know about ownership.
        """
        rows = self._conn.execute(
            """SELECT c.device_mac, c.label, u.username
                 FROM claimed_devices c JOIN users u ON u.id = c.user_id
                WHERE c.label IS NOT NULL AND c.label != ''""")
        return {mac: f"{username}'s {label}" for mac, label, username in rows}

    # -- blacklists --------------------------------------------------------

    @_synchronised
    def add_blocked(self, user_id: int, pattern: str) -> str:
        """Add a domain to a group's blacklist. Returns the stored form.

        Normalised on the way in, because a list that holds both
        "TikTok.com" and "www.tiktok.com/" as separate entries is one a
        person cannot reason about, and enforcement would have to match
        both.
        """
        cleaned = normalise_blocked_pattern(pattern)
        if not cleaned:
            raise AccountError("Enter a website address, for example tiktok.com")
        self._conn.execute(
            """INSERT INTO blacklist (user_id, pattern, added_at) VALUES (?, ?, ?)
               ON CONFLICT(user_id, pattern) DO NOTHING""",
            (user_id, cleaned, datetime.now(timezone.utc).isoformat()),
        )
        self._conn.commit()
        return cleaned

    @_synchronised
    def remove_blocked(self, user_id: int, pattern: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM blacklist WHERE user_id = ? AND pattern = ?",
            (user_id, normalise_blocked_pattern(pattern)),
        )
        self._conn.commit()
        return cur.rowcount > 0

    @_synchronised
    def blocked_for(self, user_id: int) -> list:
        rows = self._conn.execute(
            "SELECT pattern FROM blacklist WHERE user_id = ? ORDER BY pattern", (user_id,))
        return [row[0] for row in rows]

    @_synchronised
    def blocked_by_group(self) -> list:
        """Every group's list, for the admin view and for enforcement.

        Enforcement needs the owner's devices alongside the patterns: the
        whole point is that a block applies to that group's devices and
        nobody else's.
        """
        rows = self._conn.execute(
            """SELECT u.id, u.username, u.group_name, b.pattern
                 FROM users u LEFT JOIN blacklist b ON b.user_id = u.id
                WHERE u.is_admin = 0
                ORDER BY u.username, b.pattern""")
        groups = {}
        for user_id, username, group_name, pattern in rows:
            entry = groups.setdefault(user_id, {
                "user_id": user_id, "username": username,
                "group": group_name, "patterns": [], "device_macs": [],
            })
            if pattern:
                entry["patterns"].append(pattern)
        for entry in groups.values():
            entry["device_macs"] = sorted(self.macs_for_user(entry["user_id"]))
        return list(groups.values())

    # -- daily limits ------------------------------------------------------

    @_synchronised
    def set_quota(self, user_id: int, service: str, daily_seconds: int) -> None:
        """Limit a service to this many seconds a day. Zero removes it."""
        service = (service or "").strip()
        if not service:
            raise AccountError("Choose a service to limit.")
        if daily_seconds <= 0:
            self._conn.execute(
                "DELETE FROM quotas WHERE user_id = ? AND service = ?", (user_id, service))
        else:
            self._conn.execute(
                """INSERT INTO quotas (user_id, service, daily_seconds) VALUES (?, ?, ?)
                   ON CONFLICT(user_id, service) DO UPDATE SET
                     daily_seconds = excluded.daily_seconds""",
                (user_id, service, int(daily_seconds)),
            )
        self._conn.commit()

    @_synchronised
    def quotas_for(self, user_id: int) -> dict:
        rows = self._conn.execute(
            "SELECT service, daily_seconds FROM quotas WHERE user_id = ?", (user_id,))
        return {service: seconds for service, seconds in rows}

    @_synchronised
    def all_quotas(self) -> dict:
        """Every group's limits, keyed by user id, for enforcement."""
        rows = self._conn.execute("SELECT user_id, service, daily_seconds FROM quotas")
        limits = {}
        for user_id, service, seconds in rows:
            limits.setdefault(user_id, {})[service] = seconds
        return limits

    @_synchronised
    def release_device(self, user_id: int, mac: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM claimed_devices WHERE device_mac = ? AND user_id = ?",
            (mac.upper(), user_id),
        )
        self._conn.commit()
        return cur.rowcount > 0

    @_synchronised
    def macs_for_user(self, user_id: int) -> set[str]:
        return {
            row[0] for row in self._conn.execute(
                "SELECT device_mac FROM claimed_devices WHERE user_id = ?", (user_id,)
            )
        }

    @_synchronised
    def owner_of(self, mac: str) -> Optional[int]:
        row = self._conn.execute(
            "SELECT user_id FROM claimed_devices WHERE device_mac = ?", (mac.upper(),)
        ).fetchone()
        return row[0] if row else None

    @_synchronised
    def group_map(self) -> dict[str, str]:
        """MAC -> group name, for every claimed device."""
        return {
            row[0]: row[1] for row in self._conn.execute(
                """SELECT c.device_mac, u.group_name
                   FROM claimed_devices c JOIN users u ON u.id = c.user_id"""
            )
        }
