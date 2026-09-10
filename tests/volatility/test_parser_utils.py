from __future__ import annotations

from memsentry.volatility.plugins._parser_utils import (
    optional_pid,
    provenance,
    required_pid,
)


def test_provenance_builds_standard_record() -> None:
    assert provenance("windows.pslist.PsList", 3, 1) == {
        "source_plugin": "windows.pslist.PsList",
        "source_row": 3,
        "source_tree_depth": 1,
    }


def test_required_pid_returns_valid_pid_and_no_warning() -> None:
    warnings: list[str] = []
    pid = required_pid({"pid": "7"}, ("pid",), "pslist", 1, warnings)
    assert pid == 7
    assert warnings == []


def test_required_pid_warns_and_returns_none_when_missing() -> None:
    warnings: list[str] = []
    pid = required_pid({}, ("pid",), "pslist", 4, warnings)
    assert pid is None
    assert warnings == ["pslist row 4 has no valid PID; row skipped."]


def test_required_pid_warns_on_negative_pid() -> None:
    warnings: list[str] = []
    pid = required_pid({"pid": -1}, ("pid",), "handles", 2, warnings)
    assert pid is None
    assert warnings == ["handles row 2 has no valid PID; row skipped."]


def test_optional_pid_allows_absent_value() -> None:
    warnings: list[str] = []
    pid = optional_pid({}, ("pid", "ownerpid"), "netscan", 1, warnings)
    assert pid is None
    assert warnings == []


def test_optional_pid_warns_on_malformed_present_value() -> None:
    warnings: list[str] = []
    pid = optional_pid({"ownerpid": "not-a-number"}, ("pid", "ownerpid"), "netscan", 2, warnings)
    assert pid is None
    assert warnings == ["netscan row 2 has invalid PID; row skipped."]
