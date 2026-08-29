"""Launch the real ActivityGraph dashboard on the interview demo data.

This is the "here's the actual project running" entry point. It builds the
populated Pipeline and seeded history from `build_demo.build()` and hands them
straight to the shipping `activitygraph.server.serve` -- the same server the
live capture uses. Nothing about the dashboard is faked; only its input is
synthetic.

    python demo/serve_demo.py                 # opens http://127.0.0.1:8420
    python demo/serve_demo.py --port 9000 --no-browser

Run it from the repo root (so `import household` resolves), inside the venv.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# This project's own path contains a check mark; force UTF-8 so a print of it
# (or of box-drawing characters) never dies on the Windows cp1252 console.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

# Import sibling modules (household, build_demo) and the activitygraph package
# straight from the source tree, no matter where the script is launched from
# and regardless of whether an editable install is present/current.
_DEMO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_DEMO_DIR))          # household, build_demo
sys.path.insert(0, str(_DEMO_DIR.parent))   # the activitygraph package at repo root

from build_demo import build  # noqa: E402
from activitygraph.server import serve  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the ActivityGraph interview demo.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default 127.0.0.1).")
    parser.add_argument("--port", type=int, default=8420, help="Bind port (default 8420).")
    parser.add_argument("--no-browser", action="store_true", help="Do not open a browser.")
    parser.add_argument("--no-history", action="store_true",
                        help="Skip the 30-day history backfill (faster start, empty History panel).")
    args = parser.parse_args()

    print("[demo] Building a household of synthetic traffic and running it "
          "through the real pipeline...")
    pipeline, store = build(with_history=not args.no_history)
    summary = pipeline.summary()
    print(f"[demo] {len(summary['devices'])} devices, {len(summary['flows'])} flows, "
          f"{len(summary['sessions'])} sessions ready.")
    if store is not None:
        print(f"[demo] Seeded {store.session_count()} history sessions "
              f"(30-day trend + today).")

    serve(
        pipeline,
        live=False,
        host=args.host,
        port=args.port,
        open_browser=not args.no_browser,
        history_store=store,
    )


if __name__ == "__main__":
    main()
