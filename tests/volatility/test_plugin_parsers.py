from __future__ import annotations

import json

import pytest

from memsentry.volatility.plugins._parser_utils import VolatilityPluginParseError
from memsentry.volatility.plugins.cmdline_parser import CmdlineParser
from memsentry.volatility.plugins.malfind_parser import MalfindParser
from memsentry.volatility.plugins.netscan_parser import NetscanParser
from memsentry.volatility.plugins.pstree_parser import PstreeParser


def test_cmdline_accepts_json_lines_and_preserves_command_line() -> None:
    result = CmdlineParser().parse(
        '{"PID": 7, "Process": "bash", "Args": "bash -i"}\n'
        '{"PID": 8, "Process": "sshd", "Args": "sshd -D"}\n',
        "linux",
    )
    assert result.warnings == ()
    assert result.command_lines[0].command_line == "bash -i"
    assert result.command_lines[0].provenance["source_plugin"] == "linux.psaux.PsAux"


def test_pstree_flattens_children_and_warns_for_bad_rows() -> None:
    result = PstreeParser().parse(
        [{"PID": 1, "COMM": "init", "__children": [{"PID": "bad"}]}], "linux"
    )
    assert [item.pid for item in result.processes] == [1]
    assert result.processes[0].provenance["source_tree_depth"] == 0
    assert result.warnings == ("pstree row 2 has no valid PID; row skipped.",)


def test_netscan_normalises_windows_endpoint_fields() -> None:
    result = NetscanParser().parse(
        json.dumps(
            [
                {
                    "Proto": "TCPv4",
                    "LocalAddr": "10.0.0.1",
                    "LocalPort": 443,
                    "ForeignAddr": "8.8.8.8",
                    "ForeignPort": "53",
                    "PID": 42,
                }
            ]
        ),
        "windows",
    )
    connection = result.connections[0]
    assert (connection.local_address, connection.local_port, connection.remote_port) == (
        "10.0.0.1",
        443,
        53,
    )


def test_malfind_normalises_region_and_rejects_other_os() -> None:
    result = MalfindParser().parse(
        [{"PID": 42, "Process": "explorer.exe", "Start VPN": "0x1000", "PrivateMemory": True}],
        "windows",
    )
    assert result.regions[0].start == "0x1000"
    assert result.regions[0].private_memory is True
    with pytest.raises(VolatilityPluginParseError):
        MalfindParser().parse([], "linux")
