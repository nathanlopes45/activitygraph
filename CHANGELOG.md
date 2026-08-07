# Changelog

Notable changes, newest first. Dates are when the work landed on `main`.

## Unreleased

### Added

- **`--flow-accounting`**: exact per-flow byte counts and liveness taken
  from the kernel's connection tracker instead of from the packets that got
  past the capture filter. The Pi already does NAT, so every packet is
  already counted by code that sees it anyway; reading that table costs one
  pass over open connections rather than one pass over packets. Makes light
  mode exact rather than sampled, without the throughput cost of full
  capture. Needs `net.netfilter.nf_conntrack_acct=1`, and says so at
  startup when it is missing.

### Changed

- **A daily limit now blocks embedded content too**, matching a blacklist.
  Sparing embed hosts was what let the apps keep working, since an app and
  an embed use the same hosts. The two features now differ in what triggers
  them, not in what they reach.
- `youtube-nocookie.com` is classified as YouTube. It was absent entirely,
  so it was unlabelled in the dashboard as well as unblockable.

### Fixed

- **Claiming a device never put it in its owner's group.** The name people
  chose was applied, because it goes through the alias mechanism, so two
  devices claimed by the same person read "ryan's laptop" and "ryan's
  Nothing-Phone-2" while both sat under Ungrouped.
  `AccountStore.group_map()` existed and had a test; nothing called it. Per
  person totals are the point of the dashboard, so this was the one
  question it could not answer. Claims are layered over any
  `--device-groups` file rather than replacing it, and re-applied on every
  background pass so a device that appears later is grouped without being
  claimed twice.
- **The background thread died on a live gateway**, taking history
  recording, flow closing and blacklist enforcement with it while the
  dashboard carried on looking healthy. The firewall refresh iterated the
  DNS cache that the capture thread writes to, so a device resolving a name
  mid-refresh raised `dictionary changed size during iteration`. It now
  works from a snapshot, and a failing pass no longer ends the loop.
  `/api/health` reports failed passes.
- **`--flow-accounting` reported no connection tracking on the one machine
  it was written for.** Raspberry Pi OS builds its kernel without
  `CONFIG_NF_CONNTRACK_PROCFS`, so `/proc/net/nf_conntrack` is absent even
  while tracking runs and counts. It now falls back to `conntrack -L`, and
  each failure names the command that fixes it.
- **Blocking had no effect on a network with IPv6.** Every rule matched
  IPv4 only, and clients prefer IPv6 when both are offered, so the traffic
  took the family with no rules on it. Addresses were being resolved
  correctly and then discarded one line before use. Both families now get a
  set and a rule.
- **A daily limit did not reach the app.** It blocked front doors only, so
  Instagram kept loading its feed from the CDN while instagram.com sat
  blocked. A limit now covers the whole service and subtracts hosts that
  serve content embedded in other people's pages, so a video in an article
  and a map on a shop's page still work.
- **The admin panel silently showed an empty list** when an API call failed.
  FastAPI reports errors as `{detail: ...}`, which the page did not
  recognise, so an admin fell through to the personal view and saw nothing.

### Added

- `/api/enforcement` (admin only) reports whether anything is being
  dropped and why not: whether nft is present, what each group's lists
  resolved to, and how many addresses its devices hold.

### Changed

- CI pins `actions/checkout@v7` and `actions/setup-python@v7`. The previous
  tags declared node20, which GitHub has retired, so every run was annotated
  with a deprecation warning.
- The README carries a build badge and describes what CI actually runs.

## 1.0.0

The point at which the project does the thing it set out to do: show a
household where its time goes, per person, across every device, and act on
it.

### Added

- **Gateway deployment.** Runs on a Raspberry Pi between the modem and the
  access point, so every device's traffic is visible. A Wi-Fi client cannot
  see other devices' traffic at all, which is why this exists.
  See [docs/raspberry-pi-gateway.md](docs/raspberry-pi-gateway.md).
- **Accounts and groups.** People sign in, claim their own devices and see
  only those; an admin sees everything and claims nothing. A device can only
  be claimed from itself, so nobody can attach hardware they are not holding.
- **Blocking and daily limits.** A group can block a service outright or
  allow itself an hour a day. Enforced with nftables rules scoped to that
  group's devices, in a table of its own, failing open.
- **Light capture mode.** Inspecting every packet in Python cost a Pi 4B most
  of its throughput: 15 Mbps of a 110 Mbps line. Filtering in the kernel
  restores it to about 100 Mbps.
- **Per-person time tracking** with a three-level taxonomy, day-over-day
  history, and a dashboard with filters.
- **IPv6 capture**, and identification of plaintext HTTP by its Host header.

### Notable fixes

- Time was understated because the freshness window cut flows before the
  totals were computed, so an hour of viewing read as zero once it ended.
  The window now applies to what is happening, never to what has happened.
- A device appeared several times over: once per address it held, once at
  `0.0.0.0` from its own DHCP request, and once more for the gateway itself.
  Devices are keyed by MAC.
- Device names came from whatever protocol spoke first, which meant a phone
  showed its model rather than its owner's name for the whole capture. People
  now name their own devices when they claim them.
- Blocking a service missed its app, because a phone app does not visit a
  website: the YouTube app streams from `googlevideo.com` and never touches
  `youtube.com`. A block now covers the whole service; a daily limit still
  does not, so embedded videos keep playing.

### Known limits

- A device with a cached DNS answer reaches a blocked address until that
  cache expires, so a block is firm within about a minute rather than
  instantly.
- Byte totals are an undercount in light capture mode. Time and categories
  are unaffected; `--capture-mode full` trades throughput for exact bytes.
- Device-to-device traffic that never crosses the gateway is invisible, and
  no software on the gateway can change that.
