# Interview demo

A believable, fully-populated version of ActivityGraph for showing the
project without a live network capture — plus a self-contained page that walks
an interviewer through *how the pipeline works*, using the real numbers the
code produces.

Everything here is additive. It imports the shipping package and feeds it
synthetic input; it changes nothing in `activitygraph/`, and the test suite is
untouched (`pytest` still green).

## Two things to show

### 1. The live dashboard (the real app, running)

From the repo root:

```powershell
./run-demo.ps1                       # Windows
# or, any platform, inside the venv:
python demo/serve_demo.py
```

Opens `http://127.0.0.1:8420`. This builds a household of synthetic traffic,
runs it through the **actual** `Pipeline` and `server.py`, seeds a 30-day
history, and serves the interactive dashboard — activity graph, per-person
time, category drill-downs, live filters, 30-day trends. No admin rights, no
real capture.

Flags pass straight through: `python demo/serve_demo.py --port 9000 --no-browser`.

### 2. The shareable explainer page (no setup, sendable)

A single self-contained HTML file that explains the seven-stage pipeline,
walks one real packet through every stage, and recreates the dashboard panels
— all from the numbers the pipeline actually computed. Open
[`explainer.html`](explainer.html) in any browser, or send the link; it needs
no server and no Python.

## How it's built

| File | Role |
|---|---|
| `household.py` | The synthetic household: 7 devices, 3 people + shared, and one evening's schedule of activity. Feeds packets into the real `Pipeline`. |
| `build_demo.py` | Assembles the populated `Pipeline` and seeds a `HistoryStore` (today from the real run, 30 prior days backfilled from the same schedule). |
| `serve_demo.py` | Hands that to the shipping `activitygraph.server.serve`. Deliverable #1. |
| `export_demo.py` | Dumps the pipeline's `summary()` + history to `demo_data.json`. |
| `extract_artifact_data.py` | Trims that to `artifact_data.json` (only what the page renders). |
| `explainer_template.html` + `build_explainer.py` | Injects the data into the page → `explainer.html`. Deliverable #2. |

The aliases, groups and taxonomy the demo applies live in `household.py` (as
the `ALIASES` / `GROUPS` / `TAXONOMY` dicts) — the same shapes
`--device-aliases` / `--device-groups` / `--taxonomy` load from disk. See
[`../examples/`](../examples/) for the on-disk file format.

To regenerate the explainer page after editing the household:

```powershell
python demo/export_demo.py
python demo/extract_artifact_data.py
python demo/build_explainer.py
```

## Why it's honest

The demo's only fiction is the *input traffic*. Every device name, category,
per-person total, session, trend and "today vs. average" figure is computed by
the same code a real capture runs — so what an interviewer sees on the page is
genuinely what the software does, not a mock-up drawn to look like it.
