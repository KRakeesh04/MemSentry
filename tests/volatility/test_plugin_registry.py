from __future__ import annotations

from memsentry.volatility.plugin_registry import (
    PluginRegistry,
    PluginSelectionError,
    UnsupportedOperatingSystemError,
)

DISCOVERED_PLUGINS = {
    "windows.pslist.PsList": object,
    "linux.pslist.PsList": object,
    "mac.pslist.PsList": object,
    "windows.pstree.PsTree": object,
    "linux.pstree.PsTree": object,
    "windows.cmdline.CmdLine": object,
    "linux.psaux.PsAux": object,
    "mac.psaux.Psaux": object,
    "windows.netscan.NetScan": object,
    "linux.sockstat.Sockstat": object,
    "mac.netstat.Netstat": object,
    "windows.dlllist.DllList": object,
    "linux.elfs.Elfs": object,
    "mac.list_files.List_Files": object,
    "windows.malfind.Malfind": object,
    "windows.handles.Handles": object,
}


def test_available_plugins_only_include_discovered_allowlisted_plugins() -> None:
    registry = PluginRegistry(discovered_plugins=DISCOVERED_PLUGINS)

    assert [plugin.id for plugin in registry.available_plugins("windows")] == [
        "process_list",
        "process_tree",
        "command_line",
        "network_connections",
        "loaded_modules",
        "memory_injection",
        "handles",
    ]
    assert [plugin.id for plugin in registry.unavailable_plugins("windows")] == [
        "system_info"
    ]


def test_mapping_parser_and_selection_are_os_specific() -> None:
    registry = PluginRegistry(discovered_plugins=DISCOVERED_PLUGINS)

    assert registry.parser_for("command_line", "linux") == "cmdline_parser"
    assert set(registry.map_plugins("linux")) == {
        "linux.pslist.PsList",
        "linux.pstree.PsTree",
        "linux.psaux.PsAux",
        "linux.sockstat.Sockstat",
        "linux.elfs.Elfs",
    }
    assert [
        plugin.id
        for plugin in registry.validate_selection("linux", ["process_list", "command_line"])
    ] == ["process_list", "command_line"]


def test_invalid_os_and_unavailable_selection_raise_clear_errors() -> None:
    registry = PluginRegistry(discovered_plugins=DISCOVERED_PLUGINS)

    try:
        registry.available_plugins("android")
    except UnsupportedOperatingSystemError:
        pass
    else:
        raise AssertionError("Expected an unsupported OS error.")

    try:
        registry.validate_selection("linux", ["memory_injection"])
    except PluginSelectionError:
        pass
    else:
        raise AssertionError("Expected an unavailable plugin selection error.")
