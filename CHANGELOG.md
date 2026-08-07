# Changelog

Notable changes, newest first. Dates are when the work landed on `main`.

## Unreleased

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
