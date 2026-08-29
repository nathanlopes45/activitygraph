"""Assemble the self-contained explainer page from template + real data.

    python demo/export_demo.py            # 1. run the pipeline -> demo_data.json
    python demo/extract_artifact_data.py  # 2. trim it        -> artifact_data.json
    python demo/build_explainer.py        # 3. inject          -> explainer.html

The page embeds the trimmed data inline (no network fetch), so it opens
anywhere with no server and no dependencies.
"""
from __future__ import annotations

from pathlib import Path

HERE = Path(__file__).resolve().parent
template = (HERE / "explainer_template.html").read_text(encoding="utf-8")
data = (HERE / "artifact_data.json").read_text(encoding="utf-8")

# The data sits inside a <script type="application/json"> block, which is read
# as raw text until the first "</". No JSON structure needs "</", so escaping
# any that appears inside a string value keeps the block intact without
# changing the parsed value ("<\/" is JSON for "</").
data = data.replace("</", "<\\/")

out = HERE / "explainer.html"
out.write_text(template.replace("__DATA_JSON__", data), encoding="utf-8")
print(f"wrote {out.name} ({out.stat().st_size} bytes)")
