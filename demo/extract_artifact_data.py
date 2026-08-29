"""Trim demo_data.json down to exactly what the explainer page renders.

The full export carries every flow (hundreds of KB). The page needs only a
handful of summaries, so this pulls those out into a compact object that can
be embedded directly in the HTML.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
data = json.loads((HERE / "demo_data.json").read_text(encoding="utf-8"))
s = data["summary"]
h = data["history"]

# Sessions, trimmed to what the mini activity-graph needs.
sessions = [
    {"device_ip": x["device_ip"], "title": x["title"],
     "category": x["dominant_category"], "services": x["services"],
     "bytes": x["byte_count"],
     "start": x["start_time"][11:16], "end": x["end_time"][11:16]}
    for x in s["sessions"]
]

devices = [
    {"name": d["display_name"], "ip": d["ip"], "mac": d["mac"],
     "vendor": d["vendor"], "group": d["group"]}
    for d in s["devices"]
]

compact = {
    "generated_at": data["generated_at"],
    "totals": {
        "active_seconds": s["time_totals"]["total_active_seconds"],
        "device_count": len(s["devices"]),
        "session_count": len(s["sessions"]),
        "flow_count": len(s["flows"]),
        "service_count": len({f.get("service") for f in s["flows"] if f.get("service")}),
    },
    "by_category": [
        {"category": r["category"], "seconds": r["seconds"],
         "subcategories": [
             {"subcategory": sub["subcategory"], "seconds": sub["seconds"],
              "services": [{"service": v["service"], "seconds": v["seconds"]}
                           for v in sub.get("services", [])]}
             for sub in r.get("subcategories", [])
         ]}
        for r in s["time_totals"]["by_category"]
    ],
    "by_group": [
        {"group": g["group"], "seconds": g["seconds"],
         "device_seconds": g["device_seconds"], "device_count": g["device_count"],
         "by_category": [{"category": c["category"], "seconds": c["seconds"]}
                         for c in g["by_category"]]}
        for g in s["time_totals"]["by_group"]
    ],
    "ranked_services": [
        {"service": r["service"], "bytes": r["byte_count"], "category": r["category"]}
        for r in s["ranked_services"][:12]
    ],
    "category_bytes": [
        {"category": r["category"], "bytes": r["byte_count"]}
        for r in s["ranked_categories"]
    ],
    "devices": devices,
    "sessions": sessions,
    "background": s["background"],
    "trace": data["trace"],
    "history": {
        "daily_time_totals": h["daily_time_totals"],
        "today_vs_average_time": h["today_vs_average_time"],
        "session_count": h["session_count"],
    },
}

out = HERE / "artifact_data.json"
out.write_text(json.dumps(compact, separators=(",", ":")), encoding="utf-8")
print(f"wrote {out} ({out.stat().st_size} bytes)")
