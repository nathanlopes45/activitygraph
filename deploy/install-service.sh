#!/usr/bin/env bash
# Install or update the systemd unit for a Raspberry Pi gateway.
#
# Safe to re-run: it rewrites the unit from the template every time, which
# is the point. A unit written once by hand drifts as the flags change, and
# the drift only shows up at the next reboot, when whatever was being tested
# by hand silently reverts.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT=/etc/systemd/system/activitygraph.service

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo: sudo $0" >&2
    exit 1
fi

if [[ ! -x "$ROOT/.venv/bin/python" ]]; then
    echo "No virtualenv at $ROOT/.venv" >&2
    echo "Build it first: cd $ROOT && python3 -m venv .venv && .venv/bin/pip install -e ." >&2
    exit 1
fi

if [[ -f $UNIT ]]; then
    cp "$UNIT" "$UNIT.backup"
    echo "Previous unit saved to $UNIT.backup"
fi

sed "s|__PROJECT_ROOT__|$ROOT|g" "$ROOT/deploy/activitygraph.service" > "$UNIT"

echo
echo "Wrote $UNIT:"
grep ExecStart "$UNIT"
echo

# --flow-accounting reads the kernel's per-flow byte counters, which are not
# kept unless this is on. Reported rather than set: it is a system-wide
# setting and changing it silently from an installer is not this script's
# call. Without it the service still runs, with sampled byte totals.
if [[ -r /proc/sys/net/netfilter/nf_conntrack_acct ]] \
   && [[ "$(cat /proc/sys/net/netfilter/nf_conntrack_acct)" != "1" ]]; then
    echo "Note: per-flow byte accounting is off, so byte totals will be a sample."
    echo "To turn it on now and at every boot:"
    echo "    sudo sysctl -w net.netfilter.nf_conntrack_acct=1"
    echo "    echo 'net.netfilter.nf_conntrack_acct=1' | sudo tee /etc/sysctl.d/99-activitygraph.conf"
    echo
fi

systemctl daemon-reload
systemctl enable activitygraph >/dev/null
systemctl restart activitygraph

sleep 2
if systemctl is-active --quiet activitygraph; then
    echo "activitygraph is running."
    echo "Dashboard: http://192.168.50.1:8420"
else
    echo "It did not start. The last few log lines:" >&2
    journalctl -u activitygraph -n 20 --no-pager >&2
    exit 1
fi
