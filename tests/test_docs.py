"""Consistency checks on the gateway runbook.

The runbook exists twice: as markdown, and as the script that renders the
PDF. Keeping them in step is manual, and the failure mode is quiet -- a
command that still works but no longer does what the surrounding prose says
it does. That happened with --capture-mode light, which reached the flag
table and the systemd unit but not the command a reader would copy, and it
was spotted by a person rather than by anything here.
"""
import re
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parent.parent / "docs"
MARKDOWN = DOCS / "raspberry-pi-gateway.md"
BUILDER = DOCS / "build_runbook.py"

CONTINUATION = "\\"


def commands_launching_activitygraph(source: str) -> list[str]:
    """Every documented command that runs the tool, joined across
    backslash continuations so a flag on a later line still counts."""
    found = []
    for match in re.finditer(r"activitygraph\.main", source):
        start = source.rfind("\n", 0, match.start()) + 1
        end = start
        while True:
            newline = source.find("\n", end)
            if newline == -1:
                break
            line = source[end:newline]
            end = newline + 1
            if not line.rstrip().endswith(CONTINUATION):
                break
        found.append(source[start:end].strip())
    return found


@pytest.mark.parametrize("path", [MARKDOWN, BUILDER], ids=["markdown", "pdf-builder"])
def test_live_capture_commands_all_request_light_mode(path):
    """On a Pi, the difference between these is 15 Mbps and 100 Mbps.

    A reader copies whichever command is nearest, so it is not enough for
    the flag to be explained elsewhere on the page.
    """
    commands = commands_launching_activitygraph(path.read_text(encoding="utf-8"))
    assert commands, f"no documented commands found in {path.name}"

    missing = [c.splitlines()[0] for c in commands
               if "--demo" not in c and "--capture-mode light" not in c]
    assert missing == [], f"live-capture commands without the flag: {missing}"


@pytest.mark.parametrize("path", [MARKDOWN, BUILDER], ids=["markdown", "pdf-builder"])
def test_the_demo_command_does_not_carry_capture_flags(path):
    """The smoke test reads no packets, so a capture flag there would only
    suggest it does something it cannot."""
    for command in commands_launching_activitygraph(path.read_text(encoding="utf-8")):
        if "--demo" in command:
            assert "--capture-mode" not in command


def test_both_documents_give_the_same_copy_command():
    """The transfer step is the one a reader pastes verbatim, so the two
    renderings drifting apart is worse here than anywhere else."""
    command = ('scp -r "C:\\Nathan Daily\\Study\\Projects\\ActivityGraph\\activitygraph" '
               "nathan@activitygraph.local:~/")
    assert command in MARKDOWN.read_text(encoding="utf-8")
    assert command in BUILDER.read_text(encoding="utf-8")


@pytest.mark.parametrize("path", [MARKDOWN, BUILDER], ids=["markdown", "pdf-builder"])
def test_systemd_units_point_at_an_explicit_account_database(path):
    """Left bare, --accounts resolves to root's home under systemd, so the
    service would not share the database used when running by hand."""
    for command in commands_launching_activitygraph(path.read_text(encoding="utf-8")):
        if "ExecStart=" not in command:
            continue
        assert re.search(r"--accounts\s+\S*accounts\.db", command), \
            f"systemd unit without an explicit accounts path: {command[:80]}"


@pytest.mark.parametrize("path", [MARKDOWN, BUILDER], ids=["markdown", "pdf-builder"])
def test_no_em_dashes(path):
    assert "\u2014" not in path.read_text(encoding="utf-8")
