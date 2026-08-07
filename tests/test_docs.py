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


# ---------------- the deployed unit ----------------

UNIT = DOCS.parent / "deploy" / "activitygraph.service"


def test_the_unit_runs_what_the_runbook_recommends():
    """A unit written once by hand drifts as the flags change, and the drift
    only surfaces at the next reboot, when whatever was being tested by hand
    silently reverts. This is the reason it lives in the repository."""
    exec_line = [line for line in UNIT.read_text(encoding="utf-8").splitlines()
                 if line.startswith("ExecStart")][0]
    for flag in ["--capture-mode light", "--flow-accounting", "--active-within 15",
                 "--enforce-blacklist", "--dhcp-leases", "--accounts", "--history-db"]:
        assert flag in exec_line, f"the deployed unit would run without {flag}"


def test_the_unit_carries_no_machine_specific_path():
    """Paths are filled in at install time. A home directory baked into a
    committed file is wrong for everyone except whoever wrote it."""
    text = UNIT.read_text(encoding="utf-8")
    assert "__PROJECT_ROOT__" in text
    assert "/home/" not in text


def test_the_readme_names_the_versions_ci_actually_tests():
    """The README tells a reader which Python versions are supported, and
    the matrix decides it. Widening or dropping one is a config edit nobody
    thinks of as a documentation change, so the claim goes stale silently."""
    workflow = (DOCS.parent / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    matrix = re.search(r"python-version:\s*\[([^\]]+)\]", workflow)
    assert matrix, "no python-version matrix found in the workflow"

    versions = re.findall(r"\d+\.\d+", matrix.group(1))
    readme = (DOCS.parent / "README.md").read_text(encoding="utf-8")
    section = readme.split("### Continuous integration", 1)
    assert len(section) == 2, "the README no longer describes CI"
    for version in versions:
        assert version in section[1], f"CI tests Python {version}; the README does not say so"


def test_ci_uses_actions_that_are_not_retired():
    """A retired node runtime does not fail the build, it annotates it. That
    is easy to leave in place until the runtime is removed outright and every
    job breaks at once."""
    workflow = (DOCS.parent / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
    stale = {"actions/checkout@v4": "declares node20", "actions/setup-python@v5": "declares node20"}
    for action, why in stale.items():
        assert action not in workflow, f"{action} {why}"


def test_the_installer_is_committed_executable():
    """Without the mode bit in git, the file arrives on the Pi at 644 and
    `sudo path/to/install-service.sh` answers "command not found", which
    reads as a missing file rather than a missing permission. Windows has no
    execute bit to carry, so git's index is the only place it can live."""
    import subprocess

    listing = subprocess.run(
        ["git", "ls-files", "-s", "deploy/install-service.sh"],
        cwd=DOCS.parent, capture_output=True, text=True, check=True).stdout
    assert listing.startswith("100755"), f"committed non-executable: {listing.strip()}"


@pytest.mark.parametrize("path", [MARKDOWN, BUILDER], ids=["markdown", "pdf-builder"])
def test_no_documented_execstart_is_split_across_lines(path):
    """systemd joins a backslash continuation, but a heredoc eats the
    backslash first, so the next line lands inside the command: a unit
    written this way starts the tool with `Restart=always` as an argument
    and exits 2. The guide says as much and then did it anyway in its own
    second example."""
    for line in path.read_text(encoding="utf-8").splitlines():
        if "ExecStart=" not in line:
            continue
        assert not line.rstrip().endswith(CONTINUATION), \
            f"ExecStart continued onto the next line: {line[:70]}"
        assert "\\n" not in line, f"literal escape inside ExecStart: {line[:70]}"


def test_the_installer_is_executable_and_refuses_without_root():
    text = (DOCS.parent / "deploy" / "install-service.sh").read_text(encoding="utf-8")
    assert "set -euo pipefail" in text
    assert "EUID -ne 0" in text, "writing to /etc without root should fail clearly"
    assert "backup" in text, "an existing unit should be recoverable"
