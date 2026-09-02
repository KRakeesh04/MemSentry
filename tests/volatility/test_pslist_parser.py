from __future__ import annotations

import json

import pytest

from memsentry.volatility.plugins.pslist_parser import PsListParseError, PsListParser


def test_parses_windows_json_and_preserves_provenance() -> None:
    raw_output = json.dumps(
        [
            {
                "PID": 4,
                "PPID": 0,
                "ImageFileName": "System",
                "Offset(V)": "0xdeadbeef",
                "CreateTime": "2026-08-28T10:00:00",
                "Wow64": False,
            }
        ]
    )

    result = PsListParser().parse(raw_output, "windows")

    assert result.warnings == ()
    process = result.processes[0]
    assert process.pid == 4
    assert process.process_name == "System"
    assert process.ppid == 0
    assert process.offset_virtual == "0xdeadbeef"
    assert process.wow64 is False
    assert process.provenance == {
        "source_plugin": "windows.pslist.PsList",
        "source_row": 1,
        "source_tree_depth": 0,
    }
    assert process.as_repository_kwargs()["original_data"] == json.loads(raw_output)[0]


@pytest.mark.parametrize(
    ("os_type", "row", "expected_name"),
    [
        ("linux", {"PID": "12", "PPID": "1", "COMM": "sshd", "OFFSET (V)": "0x10"}, "sshd"),
        ("mac", {"PID": 23, "PPID": 1, "NAME": "launchd", "OFFSET": "0x20"}, "launchd"),
    ],
)
def test_parses_os_specific_process_names(
    os_type: str, row: dict[str, object], expected_name: str
) -> None:
    result = PsListParser().parse([row], os_type)

    assert result.warnings == ()
    assert result.processes[0].process_name == expected_name
    assert result.processes[0].offset_virtual == row[next(key for key in row if "OFFSET" in key)]


def test_keeps_valid_rows_when_a_nested_row_is_invalid() -> None:
    result = PsListParser().parse(
        [
            {
                "PID": 1,
                "PPID": 0,
                "COMM": "init",
                "__children": [{"PID": "not-a-pid", "COMM": "broken"}],
            }
        ],
        "linux",
    )

    assert [process.pid for process in result.processes] == [1]
    assert result.processes[0].provenance["source_tree_depth"] == 0
    assert result.warnings == ("pslist row 2 has no valid PID; row skipped.",)

