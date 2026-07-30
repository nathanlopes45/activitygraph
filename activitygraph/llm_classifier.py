"""AI Classification stage: local LLM fallback for unrecognized domains.

This plugs into the `llm_classifier` hook already defined in
`ServiceDetector`. It only ever runs for hostnames that the fast,
deterministic `service_rules` pass didn't match -- the LLM handles the long
tail, not the common case.

Talks to a locally hosted, open-source model via the Ollama HTTP API
(http://localhost:11434 by default). Nothing here ever leaves the device:
if the local server isn't running, classification just falls back to
"Uncategorized" rather than calling out to a cloud API. That's a deliberate
privacy boundary, not a missing feature.

Any Ollama-served model works (llama3.2, qwen2.5, phi3, mistral, ...); a
small (1-3B parameter) instruction-tuned model is plenty for this task and
keeps classification fast on CPU-only hardware.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

from .models import ServiceMatch

# Keep the LLM's output constrained to the same taxonomy the rule engine
# uses, so downstream analytics (category breakdowns, etc.) stay consistent
# regardless of which stage did the classifying.
CATEGORY_TAXONOMY = [
    "Study", "Productivity", "Communication", "Software Development",
    "Entertainment", "Gaming", "Social Media", "Shopping",
    "Web Browsing", "Infrastructure", "System", "Remote Access",
    "File Sharing", "Uncategorized",
]

_PROMPT_TEMPLATE = """You are a network traffic classifier for a personal analytics tool.
Given a domain name, identify the service it belongs to and pick exactly one
category from this fixed list: {categories}

Domain: {hostname}

Respond with ONLY a JSON object, no other text:
{{"service": "<short human-readable service name>", "category": "<one category from the list>"}}
"""


class LocalLLMClassifier:
    """Callable matching the ServiceDetector.LLMClassifier signature.

    Usage:
        classifier = LocalLLMClassifier(model="qwen2.5:1.5b")
        detector = ServiceDetector(llm_classifier=classifier)
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        model: str = "qwen2.5:1.5b",
        timeout: float = 10.0,
        cache_path: Optional[str] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.cache_path = Path(cache_path).expanduser() if cache_path else None
        self._cache: dict[str, dict] = {}
        self._warned_unavailable = False
        if self.cache_path and self.cache_path.exists():
            try:
                self._cache = json.loads(self.cache_path.read_text())
            except (json.JSONDecodeError, OSError):
                self._cache = {}

    # -- public API, matches LLMClassifier signature -----------------------
    def __call__(self, hostname: Optional[str], port: int) -> Optional[ServiceMatch]:
        if not hostname:
            return None  # nothing to classify without a domain

        if hostname in self._cache:
            entry = self._cache[hostname]
            return ServiceMatch(domain=hostname, service=entry["service"], category=entry["category"], confidence=0.7)

        result = self._query(hostname)
        if result is None:
            return None

        service, category = result
        self._cache[hostname] = {"service": service, "category": category}
        self._save_cache()
        return ServiceMatch(domain=hostname, service=service, category=category, confidence=0.7)

    def is_available(self) -> bool:
        try:
            req = urllib.request.Request(f"{self.base_url}/api/tags")
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status == 200
        except (urllib.error.URLError, OSError):
            return False

    # -- internals -----------------------------------------------------------
    def _query(self, hostname: str) -> Optional[tuple[str, str]]:
        prompt = _PROMPT_TEMPLATE.format(categories=", ".join(CATEGORY_TAXONOMY), hostname=hostname)
        payload = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0.0},
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError):
            self._warn_unavailable_once()
            return None

        raw_text = body.get("response", "")
        try:
            parsed = json.loads(raw_text)
            service = str(parsed.get("service", "")).strip() or hostname
            category = str(parsed.get("category", "")).strip()
        except (json.JSONDecodeError, AttributeError):
            return None

        if category not in CATEGORY_TAXONOMY:
            category = "Uncategorized"

        return service, category

    def _save_cache(self) -> None:
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self._cache, indent=2))
        except OSError:
            pass  # cache is a nice-to-have, never fatal

    def _warn_unavailable_once(self) -> None:
        if not self._warned_unavailable:
            print(
                f"[activitygraph] Local LLM at {self.base_url} is unreachable -- "
                f"falling back to rule-based classification only. "
                f"(Is Ollama running? Try: ollama serve)",
                file=sys.stderr,
            )
            self._warned_unavailable = True
