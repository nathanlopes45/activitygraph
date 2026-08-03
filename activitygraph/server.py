"""Dashboard stage: serves the Pipeline's data over a local HTTP API and
hosts the single-page dashboard frontend.

This is intentionally a *local-only* server -- it binds to 127.0.0.1 by
default and has no auth, because the threat model is "my own browser, on
my own machine," not "the internet." If you bind it to 0.0.0.0 to view it
from another device on your LAN, that's a deliberate choice you're making,
not the default.
"""
from __future__ import annotations

import ipaddress
import sys
import threading
import time
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse

WEBAPP_DIR = Path(__file__).parent / "webapp"


def create_app(pipeline, live: bool = False, history_store=None, capture=None) -> FastAPI:
    """Build the FastAPI app around an existing Pipeline instance.

    In live mode, a background thread should already be feeding packets
    into `pipeline` (see `run_live_server` in main.py) -- this app just
    reads a fresh snapshot on every request via `pipeline.summary()`.

    `capture` is the BackgroundCapture driving that thread, if any; it's
    used only to report capture health, so a dead capture is visible
    rather than looking like an idle network.
    """
    app = FastAPI(title="ActivityGraph", docs_url="/api/docs")

    @app.get("/")
    def index():
        return FileResponse(WEBAPP_DIR / "index.html")

    @app.get("/api/summary")
    def summary() -> JSONResponse:
        data = pipeline.summary()
        data["mode"] = "live" if live else "demo"
        if capture is not None:
            data["capture"] = capture.status()
        return JSONResponse(data)

    @app.get("/api/history")
    def history(days: int = 30) -> JSONResponse:
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

    addresses: list[str] = []
    try:
        import socket

        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
    except Exception:
        pass

    # Loopback always works locally and is a useful fallback when the
    # hostname does not resolve to anything.
    if "127.0.0.1" not in addresses:
        addresses.append("127.0.0.1")
    return [f"http://{address}:{port}" for address in addresses]


def serve(pipeline, live: bool = False, host: str = "127.0.0.1", port: int = 8420, open_browser: bool = True, history_store=None, capture=None) -> None:
    """Blocking call: starts the dashboard server. Ctrl-C to stop."""
    import uvicorn

    if not _is_loopback(host):
        # The API has no authentication -- the threat model is "my own browser
        # on my own machine". Binding beyond loopback publishes everyone's
        # browsing history to anyone who can reach the port, which is a
        # legitimate choice on a trusted LAN but should never happen silently.
        print(
            f"[activitygraph] Warning: binding {host}:{port}, which is reachable beyond this "
            f"machine. The dashboard has no authentication, so anyone who can reach that address "
            f"can read every device's browsing activity. Use 127.0.0.1 unless you intend this.",
            file=sys.stderr,
        )

    app = create_app(pipeline, live=live, history_store=history_store, capture=capture)

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
    ) -> None:
        from .collector import TrafficCollector

        self.pipeline = pipeline
        self.collector = TrafficCollector(interface=interface)
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
