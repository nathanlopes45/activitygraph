import json
import urllib.error
from unittest.mock import MagicMock, patch

from activitygraph.llm_classifier import CATEGORY_TAXONOMY, LocalLLMClassifier


def _fake_urlopen_response(response_json: dict):
    """Build a mock context-manager object mimicking urllib.request.urlopen()."""
    body = json.dumps({"response": json.dumps(response_json)}).encode("utf-8")
    mock_resp = MagicMock()
    mock_resp.read.return_value = body
    mock_resp.status = 200
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    return mock_resp


def test_llm_classifier_parses_valid_response():
    classifier = LocalLLMClassifier()
    fake_resp = _fake_urlopen_response({"service": "Figma", "category": "Productivity"})
    with patch("urllib.request.urlopen", return_value=fake_resp):
        match = classifier("figma.com", 443)
    assert match is not None
    assert match.service == "Figma"
    assert match.category == "Productivity"


def test_llm_classifier_rejects_invalid_category():
    classifier = LocalLLMClassifier()
    fake_resp = _fake_urlopen_response({"service": "Mystery Site", "category": "NotARealCategory"})
    with patch("urllib.request.urlopen", return_value=fake_resp):
        match = classifier("mystery.example", 443)
    assert match is not None
    assert match.category == "Uncategorized"
    assert match.category in CATEGORY_TAXONOMY


def test_llm_classifier_returns_none_when_server_unreachable():
    classifier = LocalLLMClassifier()
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("connection refused")):
        match = classifier("anything.example", 443)
    assert match is None


def test_llm_classifier_caches_results_between_calls():
    classifier = LocalLLMClassifier()
    fake_resp = _fake_urlopen_response({"service": "Notion", "category": "Productivity"})
    with patch("urllib.request.urlopen", return_value=fake_resp) as mock_urlopen:
        classifier("notion.so", 443)
        classifier("notion.so", 443)
    # Second call should hit the in-memory cache, not the network again.
    assert mock_urlopen.call_count == 1


def test_llm_classifier_no_hostname_short_circuits():
    classifier = LocalLLMClassifier()
    with patch("urllib.request.urlopen") as mock_urlopen:
        match = classifier(None, 443)
    assert match is None
    mock_urlopen.assert_not_called()


def test_llm_classifier_persists_cache_to_disk(tmp_path):
    cache_file = tmp_path / "llm_cache.json"
    classifier = LocalLLMClassifier(cache_path=str(cache_file))
    fake_resp = _fake_urlopen_response({"service": "Linear", "category": "Productivity"})
    with patch("urllib.request.urlopen", return_value=fake_resp):
        classifier("linear.app", 443)
    assert cache_file.exists()
    saved = json.loads(cache_file.read_text())
    assert saved["linear.app"]["service"] == "Linear"

    # A fresh classifier instance should load the cache from disk.
    classifier2 = LocalLLMClassifier(cache_path=str(cache_file))
    with patch("urllib.request.urlopen") as mock_urlopen:
        match = classifier2("linear.app", 443)
    mock_urlopen.assert_not_called()
    assert match.service == "Linear"
