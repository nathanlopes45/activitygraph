"""Export the demo's real computed output as JSON for the shareable page.

The explainer artifact must show the numbers the pipeline actually produces,
not numbers typed into HTML. So this runs the same `build()` the live demo
uses, then writes `summary()` and the history readouts to `demo_data.json`.

    python demo/export_demo.py            # writes demo/demo_data.json
    python demo/export_demo.py -o path.json
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# This project's own path contains a check mark, and other output can carry
# box-drawing characters; force UTF-8 so a print never dies on the Windows
# cp1252 console.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

_DEMO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_DEMO_DIR))          # household, build_demo
sys.path.insert(0, str(_DEMO_DIR.parent))   # the activitygraph package at repo root

from build_demo import build  # noqa: E402


def _pipeline_trace(summary: dict) -> dict | None:
    """One concrete flow walked through every stage, for the explainer.

    Picks a substantial YouTube/Netflix video flow and reports what each
    stage of the real pipeline made of it: the packet metadata, the 5-tuple
    flow, the service/category the rules assigned, and the session it landed
    in. Every value is read back from the computed summary.
    """
    flows = summary.get("flows", [])
    # A recognisable, high-byte streaming flow reads best in the walkthrough.
    candidates = [f for f in flows if f.get("service") in ("YouTube", "Netflix")
                  and f.get("byte_count", 0) > 0]
    if not candidates:
        return None
    flow = max(candidates, key=lambda f: f.get("byte_count", 0))

    device = next((d for d in summary["devices"]
                   if flow["src_ip"] in (d.get("addresses") or [d.get("ip")])), None)
    session = next((s for s in summary["sessions"]
                    if s["device_ip"] == flow["src_ip"]
                    and flow["service"] in s.get("services", [])), None)
    return {"flow": flow, "device": device, "session": session}


def main() -> None:
    parser = argparse.ArgumentParser(description="Export demo data as JSON.")
    parser.add_argument("-o", "--output", default=str(Path(__file__).with_name("demo_data.json")))
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    pipeline, store = build(now=now)
    summary = pipeline.summary()

    data = {
        "generated_at": now.isoformat(),
        "summary": summary,
        "trace": _pipeline_trace(summary),
        "history": {
            "daily_totals": store.daily_totals(days=30),
            "today_vs_average": store.today_vs_average(),
            "daily_time_totals": store.daily_time_totals(days=30),
            "daily_time_totals_by_group": store.daily_time_totals_by_group(days=30),
            "daily_time_totals_by_subcategory": store.daily_time_totals_by_subcategory(
                days=30, taxonomy=pipeline.taxonomy),
            "today_vs_average_time": store.today_vs_average_time(),
            "session_count": store.session_count(),
        },
    }

    out = Path(args.output)
    out.write_text(json.dumps(data, indent=2))
    print(f"[demo] Wrote {out} "
          f"({len(summary['devices'])} devices, {len(summary['flows'])} flows, "
          f"{store.session_count()} history sessions).")


if __name__ == "__main__":
    main()
