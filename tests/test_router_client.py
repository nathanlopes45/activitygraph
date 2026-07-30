from unittest.mock import MagicMock, patch

from activitygraph.router_client import (
    RouterDevice,
    create_router_client,
    ingest_router_devices,
    load_router_credentials,
)


def test_load_router_credentials_from_json_file(tmp_path):
    creds_file = tmp_path / "router.json"
    creds_file.write_text('{"brand": "tplink", "host": "192.168.1.1", "username": "admin", "password": "secret"}')
    creds = load_router_credentials(str(creds_file))
    assert creds == {"brand": "tplink", "host": "192.168.1.1", "username": "admin", "password": "secret"}


def test_load_router_credentials_missing_file_returns_none():
    assert load_router_credentials("/nonexistent/router.json") is None


def test_load_router_credentials_malformed_json_returns_none(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not valid json {{{")
    assert load_router_credentials(str(bad_file)) is None


def test_load_router_credentials_missing_required_key_returns_none(tmp_path):
    creds_file = tmp_path / "router.json"
    creds_file.write_text('{"brand": "tplink", "host": "192.168.1.1", "username": "admin"}')
    assert load_router_credentials(str(creds_file)) is None


def test_create_router_client_rejects_unsupported_brand():
    try:
        create_router_client("netgear", "192.168.1.1", "admin", "secret")
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "netgear" in str(exc)
        assert "tplink" in str(exc)


def test_create_router_client_builds_tplink_backend():
    fake_backend = MagicMock(return_value="a-client-instance")
    with patch.dict("activitygraph.router_client._BACKENDS", {"tplink": fake_backend}):
        client = create_router_client("tplink", "192.168.1.1", "admin", "secret")
    assert client == "a-client-instance"
    fake_backend.assert_called_once_with(host="192.168.1.1", username="admin", password="secret")


def test_ingest_router_devices_feeds_devices_through_pipeline(tmp_path):
    creds_file = tmp_path / "router.json"
    creds_file.write_text('{"brand": "tplink", "host": "192.168.1.1", "username": "admin", "password": "secret"}')

    fake_client = MagicMock()
    fake_client.get_devices.return_value = [
        RouterDevice(ip="192.168.1.101", mac="AA:BB:CC:00:00:02", hostname="Alices-Phone"),
        RouterDevice(ip="192.168.1.102", mac="AA:BB:CC:00:00:01", hostname=None),
    ]

    received = []
    pipeline = MagicMock()
    pipeline.ingest.side_effect = received.append

    with patch("activitygraph.router_client.create_router_client", return_value=fake_client):
        ingest_router_devices(pipeline, str(creds_file))

    assert len(received) == 2
    assert received[0].arp_sender_ip == "192.168.1.101"
    assert received[0].arp_sender_mac == "AA:BB:CC:00:00:02"
    assert received[0].hostname_hint == "Alices-Phone"
    assert received[1].hostname_hint is None
    fake_client.close.assert_called_once()


def test_ingest_router_devices_missing_credentials_file_does_not_call_pipeline():
    pipeline = MagicMock()
    ingest_router_devices(pipeline, "/nonexistent/router.json")
    pipeline.ingest.assert_not_called()


def test_ingest_router_devices_survives_auth_failure(tmp_path):
    creds_file = tmp_path / "router.json"
    creds_file.write_text('{"brand": "tplink", "host": "192.168.1.1", "username": "admin", "password": "wrong"}')

    pipeline = MagicMock()
    with patch("activitygraph.router_client.create_router_client", side_effect=RuntimeError("auth failed")):
        ingest_router_devices(pipeline, str(creds_file))  # must not raise
    pipeline.ingest.assert_not_called()


def test_ingest_router_devices_closes_client_even_if_get_devices_fails(tmp_path):
    creds_file = tmp_path / "router.json"
    creds_file.write_text('{"brand": "tplink", "host": "192.168.1.1", "username": "admin", "password": "secret"}')

    fake_client = MagicMock()
    fake_client.get_devices.side_effect = RuntimeError("network unreachable")
    pipeline = MagicMock()

    with patch("activitygraph.router_client.create_router_client", return_value=fake_client):
        ingest_router_devices(pipeline, str(creds_file))  # must not raise

    fake_client.close.assert_called_once()
    pipeline.ingest.assert_not_called()
