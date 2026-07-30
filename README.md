# ActivityGraph -- Backend Core

> Understand your digital life.

This is the **first working slice** of ActivityGraph: the local pipeline that
turns raw network traffic into identified devices and service-tagged flows.

```
Network → Traffic Collector → Flow Processor → Service Detection → Devices/Flows
```

The AI Classification (local LLM), Activity Graph (session grouping), and
Dashboard stages from the full architecture build on top of what's here --
see [Roadmap](#roadmap).

## What it does

- **Traffic Collector** (`collector.py`): captures live packets with `scapy`,
  extracting only metadata already visible in transit -- no payload content is
  stored. It reads DNS queries/answers and parses TLS ClientHello messages
  for the SNI hostname (sent in cleartext, so this needs no decryption). It
  can also, with `--arp-sweep` (opt-in), broadcast ARP requests across the
  local subnet to register devices that never send traffic through this
  host -- see "Finding every device on your network" below, including an
  important caveat about what that does and doesn't give you.
- **Device identification** (`device_id.py`, `oui_database.py`): builds an
  IP↔MAC table from ARP traffic and looks up the vendor from a small,
  bundled offline OUI table -- no external "vendor lookup" API call, ever.
  Devices also get a human-friendly **name**, not just an IP/MAC, from
  (in priority order): a manual alias you configure (`--device-aliases`,
  see below), a passively-observed hostname -- mDNS/.local names,
  NetBIOS names, or a DHCP hostname option, whichever the device happens
  to broadcast -- or, with `--active-resolve` (opt-in), a direct query to
  the device itself (reverse DNS, unicast mDNS, NBSTAT -- the same idea as
  how a router resolves names for its own admin UI) -- or, with
  `--dhcp-leases` / `--router-devices` (opt-in), read from a DHCP server's
  lease table, which covers devices that answer neither of the above
  (phones, commonly). Not every device announces or answers a name, so some
  will still only show a vendor or IP; that is reported as unknown rather
  than guessed at.
  `Device.display_name` (exposed as `display_name` in the dashboard/JSON)
  is the single field everything else should read -- it already applies
  this fallback chain for you.
- **Flow Processor** (`flow_processor.py`): aggregates packets into 5-tuple
  flows (src/dst IP, src/dst port, protocol), tracking byte/packet counts
  and idle-based finalization.
- **Service Detection** (`service_detector.py`, `service_rules.py`):
  classifies each flow into a service + category using SNI/DNS-derived
  hostnames matched against ~50 domain rules (`canvas.instructure.com` →
  Study, `youtube.com` → Entertainment, and generic `.edu`/`.edu.au` suffixes
  → Study all work out of the box), falling back to well-known ports, and finally to a
  pluggable local-LLM classifier for anything still unrecognized. SNI/DNS
  lookups are direction-independent -- a TCP conversation produces two Flow
  objects (one per direction), and both correctly resolve to the same
  service even though the SNI is only ever observed on the outbound packet.
- **AI Classification** (`llm_classifier.py`): the long-tail fallback. Talks
  to a locally hosted, open-source model via the [Ollama](https://ollama.com)
  HTTP API (`localhost:11434` by default) -- only ever called for domains the
  rule engine didn't recognize, and only ever local. If no LLM is reachable,
  it fails open to "Uncategorized" rather than calling out to a cloud API.
  Results are cached (in-memory, or persisted to disk with `--llm-cache`) so
  the same domain is never classified twice.
- **Activity Graph** (`activity_graph.py`): groups device-initiated flows
  into named **Sessions** -- a run of activity close together in time gets
  folded into one session (default: within 5 minutes of each other),
  labeled by its dominant category (by bytes) and listing the distinct
  services seen. This is what turns a flat flow list into the tree shape
  from the original spec (`Laptop → Study Session → Canvas, Docs, Gmail`).
  Infrastructure noise (DNS/DHCP/NTP) is filtered out so it doesn't spawn or
  extend sessions on its own. Flows only count toward a session once
  they've actually been classified (not while `category` is still
  unset) -- on a live dashboard this means a new flow takes a few seconds
  to appear (until the next flush/classify cycle) rather than flickering
  in as "Uncategorized" and then disappearing once it turns out to be
  background noise like an OS connectivity check.
- **Usage Ranking** (`analytics.py`): three ranked lists, most-to-least
  used -- by device, by service, and by category -- computed straight from
  the flow set. This is also how "Uncategorized" stops being an opaque
  blob: ranking by *service* shows each unrecognized domain individually
  (its "service" name is just the domain itself), with its own byte count,
  so you can see exactly what's contributing and decide whether it's worth
  a new rule or not. Exposed as `ranked_devices`/`ranked_services`/
  `ranked_categories` in `Pipeline.summary()`, shown in both the CLI report
  and the dashboard's "Top Devices"/"Top Services" panels.
- **Dashboard** (`server.py`, `webapp/index.html`): a local-only web
  dashboard (FastAPI + a dependency-free single-page frontend -- no CDN,
  no build step) showing the activity graph as an actual node-link diagram
  (device → session → service), ranked Top Devices/Top Services panels, a
  category breakdown, devices, sessions, top flows, and a history panel.
  Binds to `127.0.0.1` by default; there's no login because the threat
  model is "my own browser," not "the internet."
- **History** (`storage.py`): a local SQLite file tracking category totals
  across sessions, powering the dashboard's "last 30 days" trend chart and
  "today vs. your average" comparison -- the start of the "digital wellbeing
  insights" from the original vision. Opt-in via `--history-db`; nothing is
  recorded unless you ask for it. Records are keyed uniquely on
  `(device_ip, start_time)`, which makes it safe to record periodically from
  a long-running `--serve --serve-source live` dashboard: a session that's
  still growing gets skipped (only sessions idle past the session gap are
  recorded), and re-attempting an already-recorded session is a safe no-op
  rather than a double-count.

## Install

Set up a virtual environment first, so ActivityGraph's dependencies stay
isolated from the rest of your system's Python packages:

```bash
git clone <repository-url> activitygraph && cd activitygraph
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

pip install -e .
```

Installing with `-e .` also provides an `activitygraph` command, so
`activitygraph --demo` works anywhere `python -m activitygraph.main --demo`
would. Both forms are used interchangeably below.

Optional extras:

```bash
pip install -e ".[dev]"        # pytest, for running the test suite
pip install -e ".[router]"     # tplinkrouterc6u, only for --router-devices
```

Verify the install without needing privileges or real traffic:

```bash
activitygraph --demo
```

You'll need to run `source .venv/bin/activate` again (Windows:
`.venv\Scripts\activate`) each time you open a new terminal to work on this
project -- your prompt will show `(.venv)` when it's active. To leave the
environment, run `deactivate`.

**Windows PowerShell:** if `.venv\Scripts\activate` fails with `running
scripts is disabled on this system` (`UnauthorizedAccess` /
`PSSecurityException`), PowerShell's default execution policy is blocking
the activation script. Allow it for just this PowerShell session (safe,
reverts automatically when you close the window -- no admin rights needed):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

### System dependency: libpcap

`scapy` needs the system's packet-capture library to actually open a
network interface -- `pip install` alone isn't enough for live capture
(demo mode doesn't need it). If `--live` or `--serve --serve-source live`
fails with something like `Cannot find libpcap.so library` or `libpcap is
not available`, install it at the OS level:

```bash
# Debian / Ubuntu
sudo apt install libpcap-dev

# Fedora / RHEL
sudo dnf install libpcap-devel

# macOS (libpcap ships with the OS, but Homebrew's build works too)
brew install libpcap

# Windows
# Install Npcap: https://npcap.com/#download
```

Then re-run your `--live`/`--serve` command -- no need to reinstall scapy
itself, since the Python side was already fine.

## Usage

### Demo mode (no root, no real traffic needed)

Runs the full pipeline against a synthetic packet stream so you can see it
work immediately:

```bash
python3 -m activitygraph.main --demo
```

### Live capture

Needs elevated privileges, because raw packet capture always does. How you
get those privileges is different per platform:

**Linux / macOS** -- root, via `sudo`. Note that plain `sudo python3` won't
see your venv's packages, since `sudo` resets the environment and
`python3` resolves back to the system Python. Call the venv's interpreter
directly instead:

```bash
sudo .venv/bin/python3 -m activitygraph.main --list-interfaces
sudo .venv/bin/python3 -m activitygraph.main --live -i eth0 -d 60
```

**Windows (native, not WSL)** -- there's no `sudo`; instead, open PowerShell
itself **as Administrator** (right-click → "Run as administrator") before
activating the venv. Once that shell is elevated, run commands normally --
no `sudo` prefix, and use `python` (`python3` may not exist as a command on
Windows unless you've aliased it):

```powershell
python -m activitygraph.main --list-interfaces
python -m activitygraph.main --live -i "Wi-Fi" -d 60
```

Also see [Running natively on Windows](#running-natively-on-windows) below
for the full setup (Npcap, venv, interface names).

### JSON output

```bash
python3 -m activitygraph.main --demo --json -o summary.json
```

### With local AI classification

Requires [Ollama](https://ollama.com) -- a standalone local LLM server, not
a Python package. Install it **system-wide, outside the venv**; it runs as
its own background service and ActivityGraph just talks to it over HTTP on
`localhost:11434`, the same way it would talk to any other local server:

```bash
# Debian / Ubuntu (snap)
sudo snap install ollama

# Or the official install script (Linux/macOS):
curl -fsSL https://ollama.com/install.sh | sh

# Windows / manual installers:
# https://ollama.com/download
```

Then pull a model and make sure the server's running (these are plain
system commands too -- no venv activation needed):

```bash
ollama pull qwen2.5:1.5b   # or any small instruction-tuned model
ollama serve               # skip if it's already running as a background service
```

Now activate your venv as usual and run ActivityGraph with `--llm`:

```bash
source .venv/bin/activate
python3 -m activitygraph.main --demo --llm
python3 -m activitygraph.main --demo --llm --llm-model qwen2.5:1.5b --llm-cache ~/.activitygraph/llm_cache.json
```

If no LLM server is reachable, ActivityGraph prints a warning once and
continues with rule-based classification only -- the `--llm` flag never
blocks or crashes the pipeline.

### Finding every device on your network

By default, ActivityGraph only learns about a device once it sees that
device's traffic -- and on Wi-Fi, a normal adapter in managed/infrastructure
mode only receives frames addressed to it, plus broadcast/multicast. It
can't see another station's unicast traffic to the router the way a wired
hub (or a mirrored switch port) would let it. So a device that never
happens to talk *through* the machine running the capture -- your phone,
say, while your laptop is the one capturing -- simply never shows up,
regardless of how long you capture for.

`--arp-sweep` fixes the *visibility* half of that: before capture starts,
it broadcasts ARP "who-has" requests across the local subnet. Even in
managed mode, the replies get through, because they're addressed directly
to you -- the same trick tools like `arp-scan`/`nmap -sn` use.

```bash
python3 -m activitygraph.main --live -i "Wi-Fi" --arp-sweep --active-resolve
```

**This is inventory, not usage.** A device found only via ARP sweep gets
an entry (IP/MAC/vendor, name if `--active-resolve` or an alias resolves
one) but zero flows and zero bytes, because the sweep produces no traffic
for it -- it just proves the device exists. Measuring *usage* for a device
that never routes through your capture host needs a different data
source entirely -- see `--router-devices` below, or (for byte counts, not
just names) monitor-mode capture / a mirrored switch port, neither of
which is implemented here.

Auto-detects the sweep range as a /24 from the capture interface's own IP
(override with `--arp-sweep-subnet 192.168.1.0/24` if your network isn't
a standard /24). Needs the same elevated privileges as live capture.

#### Covering every device: run it on a gateway

Everything above works around the fact that a Wi-Fi client can't see other
devices' traffic. The way to stop working around it is to move the capture to
a machine every packet must pass *through*.

A Raspberry Pi 4B (or any small Linux box) acting as your network's gateway
gives full fidelity for **every** device -- real flows, TLS SNI, byte counts,
categories, per-person time -- with the existing code unchanged. It's also
**router-agnostic**: once the Pi serves DHCP, `--dhcp-leases` reads device
names straight from its own lease table, so nothing depends on your router's
brand, admin API or credentials.

See **[docs/raspberry-pi-gateway.md](docs/raspberry-pi-gateway.md)** for the
full setup, including the one misconfiguration that silently ruins all
per-device data (capturing the WAN side, post-NAT -- ActivityGraph now warns
about it at startup).

#### Why other devices show 0 bytes

**Devices discovered via `--arp-sweep` or `--router-devices` show a name but
no traffic. That is the expected result, not a fault.** Both
flags solve *discovery* (what exists on the network); neither can solve
*measurement* (how many bytes it used), because measurement requires
physically receiving that device's frames.

On Wi-Fi you will only ever see byte counts for:
- the machine running the capture, and
- traffic between the router and that machine.

Getting real per-device byte counts for *everything* on the network needs
a fundamentally different capture position -- monitor mode on an adapter
whose driver supports it, a mirrored switch port, or the router's own
per-client traffic counters. None of those are implemented here yet;
`--router-devices` reads the router's *device list*, not its byte counters.

### Pulling the device list from your router

Your router already knows every device's name -- it's the DHCP server, so
it captured each client's self-reported hostname at lease time, which is
exactly what its own admin page shows you. `--router-devices` logs into
that admin page and reads its client list directly, covering devices that
answer neither `--active-resolve`'s probes nor show up cleanly in
`--arp-sweep` (phones are the common case: no NetBIOS, mDNS often silent).

Login details go in their own JSON file -- never a bare CLI argument, so
the password doesn't end up in shell history or a process listing:

```json
{
  "brand": "tplink",
  "host": "192.168.1.1",
  "username": "admin",
  "password": "..."
}
```

```bash
pip install tplinkrouterc6u   # only needed for --router-devices --router-credentials ...
python3 -m activitygraph.main --live -i "Wi-Fi" --router-devices --router-credentials ~/.activitygraph/router.json
```

Keep that file private (it's a plaintext credential file, same as any
other) -- treat it like an SSH key, not something you commit or share.

Only TP-Link is implemented today, via the
[`tplinkrouterc6u`](https://pypi.org/project/tplinkrouterc6u/) library,
which handles the RSA/AES-encrypted login flow TP-Link's web admin uses
and auto-detects the right client for your specific model/firmware.
`router_client.py` is a small plugin interface (`RouterClient.get_devices()`
returning vendor-neutral `RouterDevice` records) -- adding another vendor
means writing one class and registering it in `_BACKENDS`, not restructuring
anything. Any failure (wrong password, unreachable router, unsupported
model) prints a warning and the rest of the pipeline continues normally --
this is a bonus data source, not a dependency.

Router-reported hostnames behave like a passive hint: they win over
nothing captured yet, but a `--device-aliases` entry for the same MAC
still overrides them.

### Grouping devices by person, and tracking time

Bytes answer "how much data moved"; they're a poor proxy for attention -- one
video stream outweighs hours of reading. `--device-groups` maps devices to a
person so the dashboard can answer **"where did *I* spend my time?"** across
all of them:

```json
{
  "Alice": ["AA:BB:CC:00:00:01", "AA:BB:CC:00:00:02"],
  "Family": ["AA:BB:CC:00:00:04"]
}
```

```bash
python3 -m activitygraph.main --demo --device-groups ~/.activitygraph/groups.json
```

Grouping is MAC-keyed (like `--device-aliases`) because DHCP hands out
different IPs across leases. Devices you haven't listed fall under
"Ungrouped" rather than disappearing.

**How time is counted.** For each category, the time ranges of its flows are
merged and the covered seconds summed -- a *union*, not a sum. A video stream
opens several connections at once; those are one span of time, not three. The
same applies across a group: if your phone and laptop both stream 10:00-10:30,
that's **30 minutes of your life**, not 60 device-minutes. Both figures are
reported -- `seconds` (the union, the headline) and `device_seconds` (the sum,
per-device detail) -- because "phone 30m + laptop 30m, 30m of your time" says
more than either alone. Union also keeps the totals sane: a day can never
exceed 24 hours.

Two caveats the dashboard reports rather than hides:

- **Per-category totals can add up to more than the wall clock.** Categories
  are unioned independently, so a device streaming video while a study tab
  polls in the background counts toward both. Which one held the user's
  attention is not knowable from traffic, so the panel shows the wall-clock
  "active" figure alongside the bars rather than applying an arbitrary
  attribution rule.
- **A single-packet flow has zero duration**, so a burst of short connections
  would otherwise register as no time at all. Each flow is credited at least
  `--min-activity-seconds` (default 5, matching `--idle-timeout` -- already the
  window in which packets count as one activity).

### Organizing activity: category → subcategory → service

Two levels of classification ("Spotify" → "Entertainment") tell you *how
much* Entertainment but not *what kind* -- an hour of background music and an
hour of video land in the same bucket despite meaning very different things.
A third level splits them:

```
Entertainment  1h 40m
  Video          50m
    YouTube        30m
    Netflix        30m
  Music           50m
    Spotify        40m
    YouTube Music  20m
```

Sensible subcategories ship by default. To reorganize them, pass a JSON file:

```json
{
  "Entertainment": {
    "Music": ["Spotify", "YouTube Music"],
    "Video": ["YouTube", "Netflix", "Disney+"]
  },
  "Social Media": { "Feeds": ["Instagram", "Facebook"], "Forums": ["Reddit"] }
}
```

```bash
python3 -m activitygraph.main --demo --taxonomy ~/.activitygraph/taxonomy.json
```

A category you define **replaces** the built-in grouping for that category
rather than merging into it, so the built-in grouping cannot reintroduce
services you deliberately moved or omitted. Categories you don't mention keep
their defaults, and you can define categories of your own. Services that aren't
listed anywhere fall into "Other", so a category's subcategories always
account for the whole category.

**Reorganizing applies retroactively.** Subcategory is never stored -- it's
looked up from the service each time totals are computed, and history is
recorded at service granularity. So editing the file re-buckets data you
already captured, including past days, instead of only affecting traffic
from that point on.

Note the durations above: `Music 50m` is less than Spotify's 40m plus YouTube
Music's 20m because those overlapped in time. Every level is a union of the one
below it, so a total is never inflated by parallel activity.

### Naming your devices

Devices are auto-named where possible (mDNS/.local, NetBIOS, or DHCP
hostnames -- whatever the device broadcasts), but coverage varies a lot by
OS and network setup, since it depends on catching the right broadcast
during the capture window.

For a name pulled straight from the device, without configuring anything,
add `--active-resolve`: for each newly-seen device with no name yet, it
sends a reverse DNS lookup, a direct mDNS query, and a direct NBSTAT
query -- the same techniques your router uses to resolve names for its
own admin page -- and keeps the first answer:

```bash
python3 -m activitygraph.main --live -i "Wi-Fi" --active-resolve
```

It's off by default to keep capture passive/unobtrusive (see "Traffic
Collector" above); turning it on sends a handful of extra unicast packets
per new device, nothing broadcast or intrusive.

For guaranteed names independent of what the device answers to (or to
override a wrong guess), create a small JSON file mapping each device's
MAC address to whatever you want to call it:

```json
{
  "AA:BB:CC:00:00:01": "Alice's Laptop",
  "AA:BB:CC:00:00:05": "Home Router"
}
```

```bash
python3 -m activitygraph.main --demo --device-aliases ~/.activitygraph/devices.json
```

An alias always wins over both a passively-observed hostname and active
resolution. MAC matching is case-insensitive. A missing or malformed file
prints a warning and falls back to auto-naming rather than crashing.

### Tuning session grouping

```bash
python3 -m activitygraph.main --demo --session-gap 600   # 10 min idle gap
```

### Dashboard

```bash
# Demo data, one-shot snapshot:
python3 -m activitygraph.main --serve --serve-source demo

# Live capture, continuously updating -- needs elevated privileges (see
# "Live capture" above for the platform-specific way to get those):
sudo .venv/bin/python3 -m activitygraph.main --serve --serve-source live -i eth0   # Linux/macOS
python -m activitygraph.main --serve --serve-source live -i "Wi-Fi"                 # Windows, Administrator PowerShell

# Combine with --llm for AI-classified long-tail domains:
python3 -m activitygraph.main --serve --serve-source demo --llm
```

Opens `http://127.0.0.1:8420` in your browser automatically (use
`--no-browser` to skip that, or `--port`/`--host` to change the bind
address). Live mode polls the API every 5s so the graph updates as new
traffic comes in.

**Capture health.** The underlying pcap socket can die mid-run --
especially on Windows, where scapy may print `Socket ... failed with
'<error>'. It was closed.` When that happens the capture thread restarts
automatically (with exponential backoff, capped at 60s), and the dashboard
shows a banner saying so, because otherwise a dead capture looks exactly
like a quiet network: the page keeps rendering, just frozen. `/api/health`
reports the same state (`capture_alive`, `capture_restarts`,
`last_capture_error`) for monitoring from the terminal:

```bash
curl -s http://127.0.0.1:8420/api/health
```

### Tracking trends over time

History is opt-in -- nothing is recorded unless you pass `--history-db`.
Works with all three modes: `--demo` and `--live` record their sessions
once, at the end of the run; `--serve --serve-source live` records
continuously in the background, as each session goes quiet:

```bash
# One-shot run, e.g. as a nightly cron job:
python3 -m activitygraph.main --live -i eth0 -d 1800 --history-db ~/.activitygraph/history.db

# Or point the live dashboard at the same file and let it record as you go:
sudo .venv/bin/python3 -m activitygraph.main --serve --serve-source live -i eth0 --history-db ~/.activitygraph/history.db

# View trends (works with --serve-source demo too, reading whatever history exists):
python3 -m activitygraph.main --serve --serve-source demo --history-db ~/.activitygraph/history.db
```

The dashboard's History panel shows a 30-day stacked bar chart by category
and "today vs. your average" comparison cards -- empty and informative
until there's at least a day or two of sessions recorded.

## Running natively on Windows

Live capture from **inside WSL2 doesn't see your real Windows-side
traffic** -- WSL2's `eth0` is its own isolated virtual network, so it only
sees traffic the Linux VM itself generates (background noise like NTP
sync), not your actual browsing on the Windows side. Even WSL2's "mirrored
networking" mode, which shares interface names/IPs with Windows, doesn't
change this. Running ActivityGraph natively on Windows sidesteps the whole
issue.

**1. Install [Npcap](https://npcap.com)** -- check "Install Npcap in
WinPcap API-compatible Mode" during setup.

**2. Get the project onto a native Windows path** (not a `\\wsl.localhost\...`
network path -- venvs don't behave reliably there). From WSL, if that's
where your copy currently lives:
```bash
cp -r ~/activity-graph "/mnt/c/Users/<you>/activity-graph"
```

**3. Install Python from [python.org](https://python.org/downloads)**
(not the Microsoft Store version) -- check "Add python.exe to PATH" during
setup. Use the command `python`, not `python3` -- Windows installs don't
create a `python3.exe` by default.

**4. Open PowerShell as Administrator** (Start menu → search "PowerShell"
→ right-click → "Run as administrator"). This is Windows' equivalent of
`sudo` for raw packet capture -- there's no `sudo` command to run instead.

**5. Set up the venv and install** (same steps as Install above, just with
PowerShell's activation script):
```powershell
cd C:\Users\<you>\activity-graph
python -m venv .venv
.venv\Scripts\Activate.ps1     # if blocked: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
pip install -e .
```

**6. List interfaces and pick your real one:**
```powershell
python -m activitygraph.main --list-interfaces
```
Windows registers a lot of internal filter-driver/virtual-switch
pseudo-interfaces; ActivityGraph filters this list down to ones with an
actual IP address, so what you see should mostly be real, usable adapters
(commonly `Wi-Fi` or `Ethernet`).

**7. Run it** (no `sudo`, no `.venv/bin/...` path -- the elevated PowerShell
session itself grants the privilege, and plain `python` already resolves
to the venv's interpreter once it's activated):
```powershell
python -m activitygraph.main --live -i "Wi-Fi" -d 60
python -m activitygraph.main --serve --serve-source live -i "Wi-Fi"
```

If you want `--llm`, Ollama needs to be installed and running on
**whichever OS you're actually launching ActivityGraph from**. An Ollama
install inside WSL2 won't be reachable from a natively-run Windows
process (and vice versa) unless you've specifically set up networking to
bridge them -- simplest is to install Ollama separately on each side you
plan to use.

## Configuration

Every configuration file is optional; ActivityGraph runs with none of them.
Templates live in [`examples/`](examples/):

| File | Flag | Purpose |
|---|---|---|
| `groups.example.json` | `--device-groups` | Map devices (by MAC) to a person |
| `aliases.example.json` | `--device-aliases` | Rename devices |
| `taxonomy.example.json` | `--taxonomy` | Reorganize subcategories |
| `router-credentials.example.json` | `--router-credentials` | Router login (optional path only) |

The templates reference the MAC addresses used by `--demo`, so they work
as-is and show what each flag does before you own any real configuration:

```bash
activitygraph --demo \
  --device-groups examples/groups.example.json \
  --device-aliases examples/aliases.example.json \
  --taxonomy examples/taxonomy.example.json
```

For real use, copy a template, replace the MACs with your own devices' (the
`Devices` panel and the CLI report both show them), and point the flag at your
copy:

```bash
cp examples/groups.example.json my-groups.json
activitygraph --live -i eth0 --device-groups my-groups.json
```

The unsuffixed filenames (`groups.json`, `aliases.json`, `router.json`, ...)
are listed in `.gitignore` deliberately: they identify your network, and one
of them holds a password. Keep your real configuration out of version control.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

Pytest configuration lives in `pyproject.toml`, so `pytest` alone is enough.
Two tests are skipped on Windows -- they assert POSIX file-permission
behaviour that has no equivalent there.

## Security and privacy

Local-first by design: capture, classification, and storage all happen
on-device.

- **No packet payload is stored** -- only 5-tuple/flow metadata and the
  DNS/SNI hostname already visible in transit.
- **No external API calls.** MAC-vendor lookup uses a bundled offline table;
  there is no "what site is this IP" service.
- **Passive by default.** `--active-resolve`, `--arp-sweep`,
  `--router-devices` and `--dhcp-leases` are each opt-in; without them
  nothing is probed or queried.
- **The optional local LLM stays local** (Ollama on `localhost`), is only
  consulted for domains the rule engine missed, and fails open rather than
  falling back to a cloud API.

Four things to be deliberate about:

- **The dashboard has no authentication.** It binds `127.0.0.1` by default
  because the threat model is your own browser on your own machine. Binding
  elsewhere (`--host 0.0.0.0`) exposes every device's browsing activity to
  anyone who can reach the port; the server prints a warning when you do.
- **The history database is sensitive.** `--history-db` records a durable
  account of what every device on the network did and when. It is gitignored,
  but treat the file itself as private data.
- **Router credentials are stored in plaintext.** Only needed for
  `--router-devices`, which is superseded by `--dhcp-leases` on a gateway.
  If you use it, `chmod 600` the file -- ActivityGraph warns on POSIX when the
  permissions are looser.
- **Live capture needs elevated privileges** (root / `CAP_NET_RAW` /
  Administrator), because opening a raw socket does. Demo mode does not.

## Licence

MIT -- see [LICENSE](LICENSE).

If you publish a fork, update the copyright line in `LICENSE` and the
`[project.urls]` entries in `pyproject.toml` to point at your own account.

## Roadmap

This slice covers **flows tagged with a service + category**, now including
local AI classification for the long tail. Next up, per the original
architecture:

1. ~~**AI Classification**~~ ✅ done -- `llm_classifier.py`, see above.
2. ~~**Activity Graph**~~ ✅ done -- `activity_graph.py`, see above.
3. ~~**Analytics & Dashboard**~~ ✅ done -- `server.py` + `webapp/`, see above.
4. ~~**Digital wellbeing insights (persistence)**~~ ✅ done -- `storage.py`
   now records session-level history from all three modes, including a
   long-running live dashboard (safe via unique `(device_ip, start_time)`
   keys, so a still-growing session is never double-counted).
5. ~~**Device naming & usage ranking**~~ ✅ done -- passive hostname
   discovery + `--device-aliases` (`device_id.py`), and ranked
   devices/services/categories (`analytics.py`), see above.

Still open, longer-term: smarter session naming once there's enough
history to recognize routine patterns ("this looks like your usual
evening wind-down"), and weekly/monthly (not just daily) trend views.

## Project layout

```
activitygraph/
  models.py               # Packet, Flow, Device, ServiceMatch dataclasses
  collector.py            # scapy live capture, DNS/SNI/hostname extraction, ARP sweep
  demo_source.py          # synthetic packet generator for --demo mode
  device_id.py            # device registry: vendor lookup, hostname learning, aliases
  device_groups.py        # map devices to a person/group (MAC-keyed)
  active_resolver.py      # opt-in active hostname lookup: reverse DNS / mDNS / NBSTAT
  dhcp_leases.py          # opt-in: read device names from a DHCP lease table
  router_client.py        # opt-in: pull device names from a router admin interface
  oui_database.py         # bundled offline MAC-vendor-prefix table
  flow_processor.py       # packet -> flow aggregation
  service_rules.py        # domain/port -> service + category rules
  service_detector.py     # DNS/SNI cache + rule matching + LLM hook
  taxonomy.py             # category -> subcategory -> service, user-reorganizable
  analytics.py            # ranked usage by device / service / category (bytes)
  time_analytics.py       # interval-union time totals by category / group / device
  llm_classifier.py       # local LLM (Ollama) fallback for unrecognized domains
  activity_graph.py       # flows -> named Sessions per device
  server.py               # FastAPI dashboard server + background live capture
  storage.py              # SQLite history: byte trends and activity intervals
  webapp/index.html       # dependency-free single-page dashboard frontend
  main.py                 # CLI: wires it all together
docs/
  raspberry-pi-gateway.md # full-network capture on a gateway
examples/                 # configuration templates
tests/                    # pytest suite (conftest.py puts the repo on sys.path)
```
