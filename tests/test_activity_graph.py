from datetime import datetime, timedelta, timezone

from activitygraph.activity_graph import Session, group_into_sessions
from activitygraph.models import Flow


def _flow(src, dst, start_offset_s, duration_s, byte_count, service, category, dst_port=443):
    now = datetime(2026, 7, 23, 9, 0, 0, tzinfo=timezone.utc)
    start = now + timedelta(seconds=start_offset_s)
    return Flow(
        src_ip=src, dst_ip=dst, src_port=51000, dst_port=dst_port, proto="TCP",
        start_time=start, end_time=start + timedelta(seconds=duration_s),
        byte_count=byte_count, packet_count=10, service=service, category=category,
    )


def test_close_flows_merge_into_one_session():
    flows = [
        _flow("192.168.1.10", "1.1.1.1", 0, 5, 30000, "Canvas LMS", "Study"),
        _flow("192.168.1.10", "2.2.2.2", 10, 5, 15000, "Google Docs", "Productivity"),
        _flow("192.168.1.10", "3.3.3.3", 20, 5, 6000, "Gmail", "Communication"),
    ]
    sessions = group_into_sessions(flows, local_ips={"192.168.1.10"}, session_gap_seconds=300)
    assert len(sessions) == 1
    session = sessions[0]
    assert session.services == ["Canvas LMS", "Gmail", "Google Docs"]
    # Dominant category should be Study, since that flow has the most bytes.
    assert session.dominant_category == "Study"
    assert session.title == "Study Session"


def test_distant_flows_split_into_separate_sessions():
    flows = [
        _flow("192.168.1.10", "1.1.1.1", 0, 5, 10000, "YouTube", "Entertainment"),
        _flow("192.168.1.10", "2.2.2.2", 3600, 5, 10000, "GitHub", "Software Development"),
    ]
    sessions = group_into_sessions(flows, local_ips={"192.168.1.10"}, session_gap_seconds=300)
    assert len(sessions) == 2


def test_infrastructure_flows_are_excluded():
    flows = [
        _flow("192.168.1.10", "1.1.1.1", 0, 5, 5000, "DNS", "Infrastructure", dst_port=53),
        _flow("192.168.1.10", "2.2.2.2", 5, 5, 5000, "DNS", "Infrastructure", dst_port=53),
    ]
    sessions = group_into_sessions(flows, local_ips={"192.168.1.10"}, session_gap_seconds=300)
    assert sessions == []


def test_non_device_initiated_flows_are_excluded():
    # src_ip is a remote server, not a local device -- shouldn't spawn a session.
    flows = [_flow("8.8.8.8", "192.168.1.10", 0, 5, 5000, "Something", "Entertainment")]
    sessions = group_into_sessions(flows, local_ips={"192.168.1.10"}, session_gap_seconds=300)
    assert sessions == []


def test_multiple_devices_get_separate_session_lists():
    flows = [
        _flow("192.168.1.10", "1.1.1.1", 0, 5, 10000, "YouTube", "Entertainment"),
        _flow("192.168.1.11", "2.2.2.2", 0, 5, 10000, "GitHub", "Software Development"),
    ]
    sessions = group_into_sessions(flows, local_ips={"192.168.1.10", "192.168.1.11"}, session_gap_seconds=300)
    assert {s.device_ip for s in sessions} == {"192.168.1.10", "192.168.1.11"}


def test_unclassified_flows_are_excluded_until_classified():
    """Regression test: a flow with category=None (not yet classified by
    the service detector) must not spawn a session. Otherwise a live
    dashboard would show a flickering 'Uncategorized' session for every
    flow the instant it appears, before classification has even run."""
    now = datetime(2026, 7, 23, 9, 0, 0, tzinfo=timezone.utc)
    unclassified = Flow(
        src_ip="192.168.1.10", dst_ip="1.1.1.1", src_port=51000, dst_port=443, proto="TCP",
        start_time=now, end_time=now + timedelta(seconds=5),
        byte_count=5000, packet_count=10, service=None, category=None,
    )
    sessions = group_into_sessions([unclassified], local_ips={"192.168.1.10"}, session_gap_seconds=300)
    assert sessions == []


def test_session_is_stable_once_flow_gets_classified():
    """The other half of the regression: once the same flow is later
    classified, it should appear -- and stay -- as a real session, with no
    further flicker."""
    classified = _flow("192.168.1.10", "1.1.1.1", 0, 5, 5000, "GitHub", "Software Development")
    sessions = group_into_sessions([classified], local_ips={"192.168.1.10"}, session_gap_seconds=300)
    assert len(sessions) == 1
    assert sessions[0].dominant_category == "Software Development"





def test_dominant_category_falls_back_to_time_when_bytes_are_zero():
    """Regression: flows derived from DNS observation carry no byte counts.
    With every byte count at zero, max() over the byte breakdown returns
    whichever category was inserted first, so the same session could be
    labelled Study or Entertainment depending on dict ordering. Time is the
    meaningful signal there."""
    now = datetime(2026, 7, 23, 9, 0, 0, tzinfo=timezone.utc)
    study = _flow("192.168.1.10", "1.1.1.1", 0, 60, 0, "Canvas LMS", "Study")
    fun = _flow("192.168.1.10", "2.2.2.2", 0, 600, 0, "YouTube", "Entertainment")

    forward = Session(device_ip="192.168.1.10", start_time=now, end_time=now, flows=[study, fun])
    reversed_ = Session(device_ip="192.168.1.10", start_time=now, end_time=now, flows=[fun, study])

    assert forward.dominant_category == "Entertainment"
    assert reversed_.dominant_category == "Entertainment"


def test_dominant_category_still_uses_bytes_when_present():
    now = datetime(2026, 7, 23, 9, 0, 0, tzinfo=timezone.utc)
    study = _flow("192.168.1.10", "1.1.1.1", 0, 60, 9999, "Canvas LMS", "Study")
    fun = _flow("192.168.1.10", "2.2.2.2", 0, 600, 10, "YouTube", "Entertainment")
    session = Session(device_ip="192.168.1.10", start_time=now, end_time=now, flows=[study, fun])
    assert session.dominant_category == "Study"
