"""Shared pytest configuration.

Puts the repository root on sys.path so tests can import `activitygraph`
without the package being installed, and without each test module repeating
the same path manipulation.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
