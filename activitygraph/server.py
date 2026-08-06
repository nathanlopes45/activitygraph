"""Dashboard stage: serves the Pipeline's data over a local HTTP API and
hosts the single-page dashboard frontend.

Binds to 127.0.0.1 by default. Binding wider (`--host 0.0.0.0`) so other
devices can reach it is a deliberate choice, and the server warns when you
make it.

When an account store is supplied the API becomes multi-user: each signed-in
person sees only the devices they have claimed, and an admin sees everything.
Two rules carry the weight of that:

  1. A device can only be claimed *from itself*. The claim endpoint resolves
     the request's own source address to a device, so you cannot claim a
     phone you are not holding.
  2. Scoping happens inside `Pipeline.summary(visible_macs=...)`, which
     restricts the inputs rather than filtering the finished payload, so a
     panel added later is scoped automatically instead of leaking.

Without an account store the API stays open, which is the right behaviour
for a loopback-only single-user run.
"""
from __future__ import annotations

import ipaddress
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import Body, FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse

from .accounts import AccountError, AccountStore, issue_token, read_token

SESSION_COOKIE = "activitygraph_session"

WEBAPP_DIR = Path(__file__).parent / "webapp"

# A filter is a convenience, not a query language. Capping the number of
# values keeps a hand-written URL from turning one request into a long scan.
MAX_FILTER_VALUES = 100


def _split_filter(raw: str, limit: int) -> list[str]:
    """Parse a comma-separated filter parameter into distinct values."""
    if not raw:
        return []
    seen: list[str] = []
    for part in raw.split(","):
        value = part.strip()
        if value and value not in seen:
            seen.append(value)
        if len(seen) >= limit:
            break
    return seen


def create_app(pipeline, live: bool = False, history_store=None, capture=None,
               accounts: 'AccountStore | None' = None, secret: bytes = b"",
               active_within_seconds: float | None = None,
               include_background: bool = False) -> FastAPI:
    """Build the FastAPI app around an existing Pipeline instance.

    In live mode, a background thread should already be feeding packets
    into `pipeline` (see `run_live_server` in main.py) -- this app just
    reads a fresh snapshot on every request via `pipeline.summary()`.

    `capture` is the BackgroundCapture driving that thread, if any; it's
    used only to report capture health, so a dead capture is visible
    rather than looking like an idle network.
    """
    app = FastAPI(title="ActivityGraph", docs_url="/api/docs")

    def current_user(request: Request):
        """The signed-in user, or None. Returns None whenever accounts are
        disabled, which keeps the single-user local mode working unchanged."""
        if accounts is None:
            return None
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            return None
        user_id = read_token(token, secret)
        return accounts.get_user(user_id) if user_id is not None else None

    def visible_macs_for(user) -> "set[str] | None":
        """Which devices this caller may see. None means no restriction.

        Admins and the accounts-disabled case get None. Everyone else gets
        exactly the devices they have claimed, so a new user sees nothing
        until they claim something, rather than seeing the network by
        default.
        """
        if accounts is None or (user is not None and user.is_admin):
            return None
        if user is None:
            return set()
        return accounts.macs_for_user(user.id)

    def _set_session(response: Response, user_id: int) -> None:
        response.set_cookie(
            SESSION_COOKIE,
            issue_token(user_id, secret),
            httponly=True,      # not readable from JavaScript
            samesite="lax",     # not sent on cross-site form posts
            path="/",
            max_age=30 * 24 * 3600,
        )

    def requesting_device(request: Request):
        """Resolve the caller's own source address to a known device.

        Deliberately uses the socket peer address and ignores X-Forwarded-For:
        there is no proxy in front of this server, and trusting that header
        would let any client claim to be any address, which is precisely the
        check this is meant to perform.
        """
        client = request.client
        if client is None:
            return None
        return pipeline.devices.get(client.host)

    @app.get("/api/auth/state")
    def auth_state(request: Request):
        """What the UI needs before deciding whether to show a login form."""
        if accounts is None:
            return {"accounts_enabled": False, "authenticated": True, "user": None}
        user = current_user(request)
        return {
            "accounts_enabled": True,
            "authenticated": user is not None,
            "user": user.to_dict() if user else None,
            "any_accounts_exist": accounts.user_count() > 0,
        }

    @app.post("/api/auth/register")
    def register(response: Response, payload: dict = Body(...)):
        if accounts is None:
            return JSONResponse({"error": "Accounts are not enabled."}, status_code=400)
        try:
            user = accounts.create_user(payload.get("username", ""), payload.get("password", ""))
        except AccountError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        _set_session(response, user.id)
        return {"user": user.to_dict()}

    @app.post("/api/auth/login")
    def login(response: Response, payload: dict = Body(...)):
        if accounts is None:
            return JSONResponse({"error": "Accounts are not enabled."}, status_code=400)
        user = accounts.authenticate(payload.get("username", ""), payload.get("password", ""))
        if user is None:
            # One message for both causes, so this cannot be used to work out
            # which usernames exist.
            return JSONResponse({"error": "Incorrect username or password."}, status_code=401)
        _set_session(response, user.id)
        return {"user": user.to_dict()}

    @app.post("/api/auth/logout")
    def logout(response: Response):
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}

    @app.get("/api/me")
    def me(request: Request):
        user = current_user(request)
        if user is None:
            return JSONResponse({"error": "Not signed in."}, status_code=401)

        claimed = accounts.macs_for_user(user.id)
        by_mac = {(d.mac or "").upper(): d for d in pipeline.devices.all_devices()}
        here = requesting_device(request)
        here_mac = (here.mac or "").upper() if here is not None else None

        return {
            "user": user.to_dict(),
            "devices": [
                {"mac": mac,
                 "ip": by_mac[mac].ip if mac in by_mac else None,
                 "name": by_mac[mac].display_name() if mac in by_mac else None,
                 "is_this_device": mac == here_mac}
                for mac in sorted(claimed)
            ],
            "this_device": {
                "mac": here_mac,
                "name": here.display_name() if here is not None else None,
                "claimed_by_you": here_mac in claimed if here_mac else False,
                "recognised": here is not None,
            },
            # So the page can leave the button out rather than offering an
            # action the server will refuse.
            "can_claim": not user.is_admin,
        }

    @app.post("/api/claim")
    def claim(request: Request):
        """Claim the device this request came from, and only that device."""
        user = current_user(request)
        if user is None:
            return JSONResponse({"error": "Not signed in."}, status_code=401)

        if user.is_admin:
            # Nothing to gain and something to lose. An admin already sees
            # every device, so a claim adds nothing to their view, and a
            # device belongs to one group at a time -- so claiming one would
            # take it away from the person whose device it actually is, and
            # they would have no way to get it back.
            return JSONResponse(
                {"error": "The admin account already sees every device, and claiming one "
                          "would stop its owner from claiming it. Sign in with a personal "
                          "account to build a group."},
                status_code=403,
            )

        device = requesting_device(request)
        if device is None or not device.mac:
            return JSONResponse(
                {"error": "This device is not recognised on the network yet. "
                          "It needs to have sent some traffic through the gateway first."},
                status_code=404,
            )

        accounts.claim_device(user.id, device.mac)
        return {"claimed": {"mac": device.mac.upper(), "name": device.display_name(),
                            "ip": device.ip}}

    @app.post("/api/unclaim")
    def unclaim(request: Request, payload: dict = Body(...)):
        user = current_user(request)
        if user is None:
            return JSONResponse({"error": "Not signed in."}, status_code=401)
        mac = (payload.get("mac") or "").strip()
        if not mac:
            return JSONResponse({"error": "No device given."}, status_code=400)
        if not accounts.release_device(user.id, mac):
            # Covers both "not yours" and "not claimed", without revealing
            # which, so this cannot be used to probe other people's devices.
            return JSONResponse({"error": "That device is not in your group."}, status_code=404)
        return {"released": mac.upper()}

    @app.get("/")
    def index():
        return FileResponse(WEBAPP_DIR / "index.html")

    @app.get("/api/summary")
    def summary(request: Request, devices: str = "", services: str = "") -> JSONResponse:
        """`devices` and `services` are comma-separated view filters.

        They narrow what the caller is already permitted to see; the
        permission check runs first inside Pipeline.summary, so passing a
        MAC belonging to somebody else's device filters down to nothing
        rather than revealing it.
        """
        user = current_user(request)
        if accounts is not None and user is None:
            return JSONResponse({"error": "Not signed in."}, status_code=401)

        data = pipeline.summary(
            visible_macs=visible_macs_for(user),
            only_macs=_split_filter(devices, limit=MAX_FILTER_VALUES),
            only_services=_split_filter(services, limit=MAX_FILTER_VALUES),
            active_within_seconds=active_within_seconds,
            include_background=include_background,
        )
        data["mode"] = "live" if live else "demo"
        data["viewer"] = {
            "user": user.to_dict() if user else None,
            "sees_all_devices": visible_macs_for(user) is None,
        }
        if capture is not None:
            data["capture"] = capture.status()
        return JSONResponse(data)

    @app.get("/api/history")
    def history(request: Request, days: int = 30) -> JSONResponse:
        if accounts is not None and current_user(request) is None:
            return JSONResponse({"error": "Not signed in."}, status_code=401)
        # Bounded so a caller can't request an unbounded scan; the readers
        # pull rows into Python to union them, so the cost is real.
        days = max(1, min(days, 3650))
        if history_store is None:
            return JSONResponse({
                "available": False, "daily_totals": [], "today_vs_average": {},
                "daily_time_totals": [], "daily_time_totals_by_group": [],
                "daily_time_totals_by_subcategory": [], "today_vs_average_time": {},
            })
        return JSONResponse({
            "available": True,
            "daily_totals": history_store.daily_totals(days=days),
            "today_vs_average": history_store.today_vs_average(),
            "daily_time_totals": history_store.daily_time_totals(days=days),
            "daily_time_totals_by_group": history_store.daily_time_totals_by_group(days=days),
            "daily_time_totals_by_subcategory": history_store.daily_time_totals_by_subcategory(
                days=days, taxonomy=getattr(pipeline, "taxonomy", None)),
            "today_vs_average_time": history_store.today_vs_average_time(),
        })

    @app.get("/api/health")
    def health():
        payload = {"status": "ok", "mode": "live" if live else "demo"}
        if capture is not None:
            payload.update(capture.status())
            if not capture.capture_alive:
                payload["status"] = "capture_stopped"
        return payload

    return app


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost", "")


def _is_wildcard(host: str) -> bool:
    """True for the bind-any addresses, which are not reachable destinations."""
    return host in ("0.0.0.0", "::", "")


def reachable_urls(host: str, port: int) -> list[str]:
    """URLs that will actually open in a browser.

    `0.0.0.0` means "listen on every interface", so printing it back is
    useless: it is not somewhere you can browse to. Expand it into the
    machine's real addresses instead, which on a gateway means one URL per
    side of the network.
    """
    if not _is_wildcard(host):
        return [f"http://{host}:{port}"]

    # 169.254.x.x means the interface asked for a DHCP lease and never got
    # one, so it is not somewhere anybody can reach. Loopback goes last: it
    # works, but only from the machine itself, and on a gateway the point of
    # this list is to open the dashboard from a phone.
    addresses = [a for a in _interface_addresses()
                 if not a.startswith("127.") and not a.startswith("169.254.")]
    addresses.append("127.0.0.1")
    return [f"http://{address}:{port}" for address in addresses]


def _interface_addresses() -> list[str]:
    """Every IPv4 address this machine actually holds, one per interface.

    Resolving the hostname is the usual shortcut for this and it is wrong.
    Debian and Raspberry Pi OS map the hostname to 127.0.1.1 in /etc/hosts,
    so on a Pi gateway -- the machine this whole feature exists for -- it
    yields two loopback addresses and nothing anyone can browse to.

    scapy is already a hard dependency and reports per-interface addresses
    directly, which is what "reachable" actually means here.
    """
    addresses: list[str] = []
    try:
        from scapy.all import get_if_addr, get_if_list

        for interface in get_if_list():
            try:
                address = get_if_addr(interface)
            except Exception:
                continue  # interface with no IPv4 address, or gone since listing
            if address and address != "0.0.0.0" and address not in addresses:
                addresses.append(address)
    except Exception:
        pass
    return addresses


def serve(pipeline, live: bool = False, host: str = "127.0.0.1", port: int = 8420, open_browser: bool = True, history_store=None, capture=None,
          accounts=None, secret: bytes = b"", active_within_seconds: float | None = None,
          include_background: bool = False) -> None:
    """Blocking call: starts the dashboard server. Ctrl-C to stop."""
    import uvicorn

    if not _is_loopback(host) and accounts is None:
        # Without accounts the API is unauthenticated -- the threat model is
        # "my own browser on my own machine". Binding beyond loopback then
        # publishes everyone's browsing history to anyone who can reach the
        # port, which is a legitimate choice on a trusted LAN but should
        # never happen silently. With --accounts the warning would be false,
        # since every endpoint requires a session.
        print(
            f"[activitygraph] Warning: binding {host}:{port}, which is reachable beyond this "
            f"machine. The dashboard has no authentication, so anyone who can reach that address "
            f"can read every device's browsing activity. Use 127.0.0.1, or turn on --accounts, "
            f"unless you intend this.",
            file=sys.stderr,
        )

    app = create_app(pipeline, live=live, history_store=history_store, capture=capture,
                     accounts=accounts, secret=secret,
                     active_within_seconds=active_within_seconds,
                     include_background=include_background)

    urls = reachable_urls(host, port)

    if open_browser:
        threading.Timer(1.0, lambda: _try_open_browser(urls[0])).start()

    mode = "live" if live else "demo"
    if len(urls) == 1:
        print(f"\nActivityGraph dashboard running at {urls[0]}  (mode: {mode})")
    else:
        print(f"\nActivityGraph dashboard running  (mode: {mode}). Open any of:")
        for url in urls:
            print(f"    {url}")
    print("Press Ctrl-C to stop.\n")
    uvicorn.run(app, host=host, port=port, log_level="warning")


def _try_open_browser(url: str) -> None:
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass


class BackgroundCapture:
    """Runs live packet capture on a daemon thread while the API server
    serves snapshots of the same Pipeline on the main thread.

    If `history_store` is given, every flush cycle also checks for sessions
    that have gone quiet (idle past the pipeline's session gap) and records
    them. A session is only ever recorded once it's stopped growing, and
    HistoryStore's own (device_ip, start_time) uniqueness makes any repeat
    attempt a safe no-op -- so this can run indefinitely without drifting
    into double-counted totals.
    """

    def __init__(
        self,
        pipeline,
        interface: Optional[str] = None,
        flush_interval_seconds: float = 5.0,
        history_store=None,
        arp_sweep: bool = False,
        arp_sweep_subnet: Optional[str] = None,
        arp_sweep_timeout: float = 3.0,
        router_devices: bool = False,
        router_credentials: Optional[str] = None,
        restart_backoff_seconds: float = 2.0,
        max_restart_backoff_seconds: float = 60.0,
        dhcp_leases: Optional[str] = None,
        bpf_filter: Optional[str] = None,
    ) -> None:
        from .collector import TrafficCollector

        self.pipeline = pipeline
        self.collector = (TrafficCollector(interface=interface, bpf_filter=bpf_filter)
                          if bpf_filter else TrafficCollector(interface=interface))
        self.flush_interval_seconds = flush_interval_seconds
        self.history_store = history_store
        self.arp_sweep = arp_sweep
        self.arp_sweep_subnet = arp_sweep_subnet
        self.arp_sweep_timeout = arp_sweep_timeout
        self.router_devices = router_devices
        self.router_credentials = router_credentials
        self.dhcp_leases = dhcp_leases
        self.restart_backoff_seconds = restart_backoff_seconds
        self.max_restart_backoff_seconds = max_restart_backoff_seconds
        self._stop_flag = threading.Event()
        self._capture_thread: Optional[threading.Thread] = None
        self._flush_thread: Optional[threading.Thread] = None
        self._capture_restarts = 0
        self._capture_error: Optional[str] = None

    def start(self) -> None:
        # Blocking, but only ever a few seconds -- run before the capture
        # thread starts so swept/router-reported devices are already in
        # the registry by the time the dashboard's first request comes in.
        from .collector import warn_if_capturing_wan

        warn_if_capturing_wan(self.collector.interface)
        if self.dhcp_leases is not None:
            from .dhcp_leases import ingest_leases

            ingest_leases(self.pipeline, self.dhcp_leases or None)
        if self.router_devices:
            from .router_client import ingest_router_devices

            ingest_router_devices(self.pipeline, self.router_credentials)
        if self.arp_sweep:
            found = self.collector.arp_sweep_and_ingest(
                on_packet=self.pipeline.ingest, subnet=self.arp_sweep_subnet, timeout=self.arp_sweep_timeout,
            )
            print(f"[activitygraph] ARP sweep found {found} device(s).")
        self._capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._capture_thread.start()
        self._flush_thread.start()

    def _capture_loop(self) -> None:
        # sniff() with no count/timeout normally blocks here for the life
        # of the process. But the underlying pcap socket can die on its own
        # -- scapy prints "Socket ... failed with '<error>'. It was closed."
        # and sniff() simply *returns* rather than raising. Without a retry
        # here, this thread would end silently and the dashboard would serve
        # a frozen snapshot indefinitely, looking like "no traffic" rather
        # than "capture is broken". So: restart, with a backoff so a
        # permanently-broken interface doesn't spin hot.
        backoff = self.restart_backoff_seconds
        while not self._stop_flag.is_set():
            try:
                self.collector.run(on_packet=self.pipeline.ingest, timeout=None)
                self._capture_error = None
            except Exception as exc:
                self._capture_error = str(exc)
            if self._stop_flag.is_set():
                break
            self._capture_restarts += 1
            print(
                f"[activitygraph] Packet capture stopped unexpectedly "
                f"(restart #{self._capture_restarts}, retrying in {backoff:.0f}s).",
                file=sys.stderr,
            )
            if self._stop_flag.wait(backoff):
                break
            backoff = min(backoff * 2, self.max_restart_backoff_seconds)

    @property
    def capture_alive(self) -> bool:
        return self._capture_thread is not None and self._capture_thread.is_alive()

    def status(self) -> dict:
        """Capture health, surfaced through the API so a dead or flapping
        capture is visible in the dashboard instead of silently looking
        like an idle network."""
        return {
            "capture_alive": self.capture_alive,
            "capture_restarts": self._capture_restarts,
            "last_capture_error": self._capture_error,
        }

    def _flush_loop(self) -> None:
        while not self._stop_flag.is_set():
            time.sleep(self.flush_interval_seconds)
            # Re-read leases so devices that joined after startup show up
            # without a restart. Re-registering a known device just refreshes
            # its last-seen time, and the file is tiny.
            if self.dhcp_leases is not None:
                from .dhcp_leases import ingest_leases

                ingest_leases(self.pipeline, self.dhcp_leases or None, announce=False)
            self.pipeline.flows.flush_idle()
            for flow in self.pipeline.flows.closed_flows():
                if flow.service is None:
                    self.pipeline.services.apply(flow)
            if self.history_store is not None:
                self._record_closed_sessions()
                # Intervals are keyed (device_ip, category, start_time) and
                # extend on conflict, so recording an interval that is still
                # growing is safe -- unlike sessions, which wait until closed.
                self.history_store.record_time_from_pipeline(self.pipeline)
                # Hostnames learned since the last tick, written here rather
                # than per DNS answer to keep disk writes off the capture path.
                self.pipeline.services.flush()

    def _record_closed_sessions(self) -> None:
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        gap = self.pipeline.session_gap_seconds
        for session in self.pipeline.sessions():
            # Only record once a session has gone quiet past the session gap
            # -- otherwise we'd record a partial session that's still growing.
            if (now - session.end_time).total_seconds() > gap:
                self.history_store.record_session(session.to_dict(), mode="live")

    def stop(self) -> None:
        self._stop_flag.set()
