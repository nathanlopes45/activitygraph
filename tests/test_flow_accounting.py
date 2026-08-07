"""Exact byte counts from the kernel instead of from a sample.

Inspecting every packet in Python costs a Pi 4B most of its throughput, and
filtering in the kernel makes the byte totals a sample. Both assume the only
way to know about a packet is to look at it, which on a NAT gateway is not
true: the connection tracker has already counted every one.

The fixture below is real /proc/net/nf_conntrack output, because the format
is the thing being parsed and a tidied-up version would not be evidence.
"""
from datetime import datetime, timedelta, timezone

import pytest

from activitygraph.flow_accounting import (accounting_status, parse_line,
                                           read_flows)
from activitygraph.flow_processor import FlowProcessor
from activitygraph.models import Packet

TCP_LINE = (
    "ipv4     2 tcp      6 431996 ESTABLISHED src=192.168.50.50 "
    "dst=142.250.187.238 sport=52134 dport=443 packets=27 bytes=4321 "
    "src=142.250.187.238 dst=192.168.50.50 sport=443 dport=52134 "
    "packets=31 bytes=39812 [ASSURED] mark=0 zone=0 use=2"
)
UDP_LINE = (
    "ipv4     2 udp      17 29 src=192.168.50.51 dst=142.250.200.14 "
    "sport=51001 dport=443 packets=8 bytes=2900 src=142.250.200.14 "
    "dst=192.168.50.51 sport=443 dport=51001 packets=9 bytes=11500 mark=0 use=1"
)
IPV6_LINE = (
    "ipv6     10 tcp      6 431999 ESTABLISHED src=2a00:beef::99 "
    "dst=2a00:1450:4009::200e sport=40222 dport=443 packets=4 bytes=800 "
    "src=2a00:1450:4009::200e dst=2a00:beef::99 sport=443 dport=40222 "
    "packets=6 bytes=9000 [ASSURED] mark=0 use=1"
)
# Accounting off: the entry is listed, with no counters on it at all.
NO_ACCT_LINE = (
    "ipv4     2 tcp      6 431996 ESTABLISHED src=192.168.50.50 "
    "dst=142.250.187.238 sport=52134 dport=443 "
    "src=142.250.187.238 dst=192.168.50.50 sport=443 dport=52134 "
    "[ASSURED] mark=0 use=2"
)


# ---------------- parsing ----------------

def test_both_directions_are_read():
    flow = parse_line(TCP_LINE)
    assert (flow.src_ip, flow.src_port) == ("192.168.50.50", 52134)
    assert (flow.dst_ip, flow.dst_port) == ("142.250.187.238", 443)
    assert (flow.byte_count, flow.reply_byte_count) == (4321, 39812)
    assert flow.proto == "TCP", "matches how a captured packet names it"


def test_the_download_direction_is_the_larger_one():
    """A sanity check on which tuple is which: the reply carries the bytes."""
    flow = parse_line(TCP_LINE)
    assert flow.reply_byte_count > flow.byte_count


def test_ipv6_entries_parse():
    flow = parse_line(IPV6_LINE)
    assert flow.src_ip == "2a00:beef::99"
    assert flow.reply_byte_count == 9000


def test_udp_entries_parse():
    assert parse_line(UDP_LINE).proto == "UDP"


def test_a_line_without_counters_yields_none_rather_than_zero():
    """Zero would be indistinguishable from an idle flow and would drag
    every total down silently."""
    flow = parse_line(NO_ACCT_LINE)
    assert flow.byte_count is None and flow.reply_byte_count is None


@pytest.mark.parametrize("line", ["", "   ", "some header line", "ipv4 2 unknownproto 99"])
def test_lines_that_are_not_flows_are_skipped(line):
    assert parse_line(line) is None


def test_a_missing_table_is_not_fatal():
    """A laptop run has no conntrack and must still work, with the counters
    capture produced."""
    assert read_flows("/nonexistent/nf_conntrack") == []


# ---------------- what the status message tells you ----------------

def test_a_missing_table_and_an_uncounted_one_are_named_apart(tmp_path):
    """They look identical in the totals and need different fixes."""
    missing = accounting_status(str(tmp_path / "absent"))
    assert missing[0] is False
    assert "conntrack" in missing[1], "the message should carry a command"

    uncounted = tmp_path / "nf_conntrack"
    uncounted.write_text(NO_ACCT_LINE + "\n")
    off = accounting_status(str(uncounted))
    assert off[0] is False
    assert "nf_conntrack_acct=1" in off[1], "the message should carry the fix"


def test_a_working_table_reports_how_many_flows(tmp_path):
    path = tmp_path / "nf_conntrack"
    path.write_text("\n".join([TCP_LINE, UDP_LINE]) + "\n")
    available, message = accounting_status(str(path))
    assert available is True and "2" in message


# ---------------- when the proc file does not exist ----------------

# Raspberry Pi OS builds its kernel without CONFIG_NF_CONNTRACK_PROCFS, so
# /proc/net/nf_conntrack is absent even while connection tracking runs and
# counts. Its absence proves nothing on its own, and reporting "no
# connection tracking on this machine" was wrong on the one machine this
# feature exists for.

# `conntrack -L` prints the same fields without the leading family columns.
COMMAND_OUTPUT = (
    "tcp      6 431996 ESTABLISHED src=192.168.50.50 dst=142.250.187.238 "
    "sport=52134 dport=443 packets=27 bytes=4321 src=142.250.187.238 "
    "dst=192.168.50.50 sport=443 dport=52134 packets=31 bytes=39812 "
    "[ASSURED] mark=0 use=1\n"
)


def test_the_command_output_parses_the_same_way():
    flow = parse_line(COMMAND_OUTPUT.strip())
    assert flow.proto == "TCP"
    assert flow.byte_count == 4321 and flow.reply_byte_count == 39812


def test_the_command_is_used_when_the_file_is_absent(monkeypatch):
    import activitygraph.flow_accounting as module

    monkeypatch.setattr(module, "_read_command", lambda: COMMAND_OUTPUT)
    flows = module.read_flows("/nonexistent/nf_conntrack")
    assert len(flows) == 1 and flows[0].byte_count == 4321


def test_the_file_is_preferred_when_present(tmp_path, monkeypatch):
    """Reading a file needs no subprocess and no extra package, so the
    fallback stays a fallback."""
    import activitygraph.flow_accounting as module

    called = []
    monkeypatch.setattr(module, "_read_command",
                        lambda: called.append(1) or COMMAND_OUTPUT)
    path = tmp_path / "nf_conntrack"
    path.write_text(UDP_LINE + "\n")

    flows = module.read_flows(str(path))
    assert called == [], "the command should not have been run"
    assert flows[0].proto == "UDP"


@pytest.mark.parametrize("tracking_loaded,expected", [
    (True, "apt install -y conntrack"),
    (False, "modprobe nf_conntrack"),
])
def test_an_unreadable_table_names_the_right_fix(monkeypatch, tracking_loaded, expected):
    """Tracking running but unreadable, and tracking not loaded at all, look
    identical in the byte totals and need different commands."""
    import activitygraph.flow_accounting as module

    monkeypatch.setattr(module, "_read_command", lambda: None)
    monkeypatch.setattr(module.Path, "exists", lambda self: tracking_loaded)

    available, message = module.accounting_status("/nonexistent/nf_conntrack")
    assert available is False
    assert expected in message


def test_the_message_names_where_the_numbers_came_from(monkeypatch):
    import activitygraph.flow_accounting as module

    monkeypatch.setattr(module, "_read_command", lambda: COMMAND_OUTPUT)
    available, message = module.accounting_status("/nonexistent/nf_conntrack")
    assert available is True and "conntrack -L" in message


# ---------------- folding it into the flows ----------------

def packet(src, dst, sport, dport, proto="TCP", length=100, at=None):
    return Packet(timestamp=at or datetime.now(timezone.utc), src_ip=src, dst_ip=dst,
                  src_port=sport, dst_port=dport, proto=proto, length=length)


def processor_with_flow():
    flows = FlowProcessor(idle_timeout_seconds=30.0)
    flows.process(packet("192.168.50.50", "142.250.187.238", 52134, 443))
    flows.process(packet("142.250.187.238", "192.168.50.50", 443, 52134))
    return flows


def test_the_kernels_count_replaces_the_sampled_one():
    """The point of the whole module: capture saw two packets, the kernel
    saw all of them."""
    flows = processor_with_flow()
    assert [f.byte_count for f in flows.open_flows()] == [100, 100]

    flows.apply_accounting([parse_line(TCP_LINE)])
    assert sorted(f.byte_count for f in flows.open_flows()) == [4321, 39812]


def test_a_flow_the_kernel_does_not_know_about_is_left_alone():
    flows = processor_with_flow()
    flows.apply_accounting([parse_line(UDP_LINE)])
    assert all(f.byte_count == 100 for f in flows.open_flows())


def test_movement_marks_a_flow_alive():
    """A flow that goes quiet between boundary packets used to be timed out
    while still open, which is where the understated time came from."""
    flows = processor_with_flow()
    stale = datetime.now(timezone.utc) - timedelta(minutes=5)
    for flow in flows.open_flows():
        flow.end_time = stale

    flows.apply_accounting([parse_line(TCP_LINE)])
    assert all(f.end_time > stale for f in flows.open_flows())
    assert flows.flush_idle() == [], "it moved bytes, so it is not idle"


def test_presence_alone_does_not_keep_a_flow_alive():
    """conntrack holds an established TCP entry for days after its last
    packet. Trusting presence would overstate time as badly as sampling
    understates it, and overstating is the worse of the two: it would show
    someone hours they did not spend."""
    flows = processor_with_flow()
    flows.apply_accounting([parse_line(TCP_LINE)])

    stale = datetime.now(timezone.utc) - timedelta(minutes=5)
    for flow in flows.open_flows():
        flow.end_time = stale

    # Same entry, same counters: nothing has moved since the last poll.
    moved = flows.apply_accounting([parse_line(TCP_LINE)])
    assert moved == 0
    assert all(f.end_time == stale for f in flows.open_flows())
    assert len(flows.flush_idle()) == 2, "idle, and should be finalised"


def test_a_recycled_entry_does_not_shrink_a_flow():
    """Counters only ever go up. A smaller number means conntrack reused the
    5-tuple for a new connection, and taking it would make the flow appear
    to lose bytes it had already recorded."""
    flows = processor_with_flow()
    flows.apply_accounting([parse_line(TCP_LINE)])
    before = sorted(f.byte_count for f in flows.open_flows())

    recycled = TCP_LINE.replace("bytes=4321", "bytes=12").replace("bytes=39812", "bytes=40")
    flows.apply_accounting([parse_line(recycled)])
    assert sorted(f.byte_count for f in flows.open_flows()) == before
