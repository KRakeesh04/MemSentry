"""Unit tests for PluginApplicabilityService."""

from __future__ import annotations

from memsentry.models.evidence import EvidenceOS
from memsentry.volatility.plugin_applicability import (
    PluginApplicabilityService,
    PluginCategory,
    PluginMetadata,
)


class TestPluginMetadata:
    """Tests for PluginMetadata data class."""

    def test_plugin_metadata_creation(self) -> None:
        """Test creating a PluginMetadata instance."""
        metadata = PluginMetadata(
            name="windows.pslist",
            supported_os=frozenset([EvidenceOS.WINDOWS]),
            category=PluginCategory.PROCESS,
            description="List processes",
        )
        assert metadata.name == "windows.pslist"
        assert EvidenceOS.WINDOWS in metadata.supported_os
        assert metadata.category == PluginCategory.PROCESS

    def test_plugin_metadata_supports_os(self) -> None:
        """Test supports_os method."""
        windows_metadata = PluginMetadata(
            name="windows.info",
            supported_os=frozenset([EvidenceOS.WINDOWS]),
            category=PluginCategory.SYSTEM_INFO,
            description="System info",
        )
        assert windows_metadata.supports_os(EvidenceOS.WINDOWS)
        assert not windows_metadata.supports_os(EvidenceOS.LINUX)
        assert not windows_metadata.supports_os(EvidenceOS.MACOS)


class TestPluginApplicabilityServiceBasics:
    """Test basic service functionality."""

    def test_get_plugin_metadata_exists(self) -> None:
        """Test retrieving metadata for an existing plugin."""
        metadata = PluginApplicabilityService.get_plugin_metadata("windows.pslist")
        assert metadata is not None
        assert metadata.name == "windows.pslist"
        assert metadata.category == PluginCategory.PROCESS

    def test_get_plugin_metadata_not_exists(self) -> None:
        """Test retrieving metadata for a non-existent plugin."""
        metadata = PluginApplicabilityService.get_plugin_metadata("nonexistent.plugin")
        assert metadata is None

    def test_is_core_plugin_true(self) -> None:
        """Test is_core_plugin returns True for approved plugins."""
        assert PluginApplicabilityService.is_core_plugin("windows.pslist")
        assert PluginApplicabilityService.is_core_plugin("linux.netstat")
        assert PluginApplicabilityService.is_core_plugin("windows.info")

    def test_is_core_plugin_false(self) -> None:
        """Test is_core_plugin returns False for non-approved plugins."""
        assert not PluginApplicabilityService.is_core_plugin("windows.fake")
        assert not PluginApplicabilityService.is_core_plugin("nonexistent.plugin")

    def test_all_plugins_returns_sorted_list(self) -> None:
        """Test all_plugins returns a sorted list."""
        plugins = PluginApplicabilityService.all_plugins()
        assert len(plugins) > 0
        plugin_names = [p.name for p in plugins]
        assert plugin_names == sorted(plugin_names)


class TestWindowsPluginApplicability:
    """Test Windows plugin applicability."""

    def test_windows_plugins_applicable_to_windows(self) -> None:
        """Test that all Windows plugins are applicable to Windows evidence."""
        windows_plugins = [
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.cmdline",
            "windows.netscan",
            "windows.malfind",
            "windows.dlllist",
            "windows.threads",
        ]
        for plugin in windows_plugins:
            assert PluginApplicabilityService.is_plugin_applicable(
                plugin, EvidenceOS.WINDOWS
            ), f"{plugin} should be applicable to Windows"

    def test_windows_plugins_not_applicable_to_linux(self) -> None:
        """Test that Windows plugins are not applicable to Linux."""
        windows_plugins = [
            "windows.info",
            "windows.pslist",
            "windows.pstree",
            "windows.cmdline",
            "windows.netscan",
            "windows.malfind",
            "windows.dlllist",
            "windows.threads",
        ]
        for plugin in windows_plugins:
            assert not PluginApplicabilityService.is_plugin_applicable(
                plugin, EvidenceOS.LINUX
            ), f"{plugin} should not be applicable to Linux"

    def test_get_available_plugins_windows(self) -> None:
        """Test get_available_plugins for Windows evidence."""
        plugins = PluginApplicabilityService.get_available_plugins(EvidenceOS.WINDOWS)
        plugin_names = [p.name for p in plugins]

        expected = [
            "windows.cmdline",
            "windows.dlllist",
            "windows.info",
            "windows.malfind",
            "windows.netscan",
            "windows.pslist",
            "windows.pstree",
            "windows.threads",
        ]
        assert plugin_names == expected

    def test_get_core_plugin_names_windows(self) -> None:
        """Test get_core_plugin_names for Windows evidence."""
        plugin_names = PluginApplicabilityService.get_core_plugin_names(
            EvidenceOS.WINDOWS
        )
        expected = [
            "windows.cmdline",
            "windows.dlllist",
            "windows.info",
            "windows.malfind",
            "windows.netscan",
            "windows.pslist",
            "windows.pstree",
            "windows.threads",
        ]
        assert plugin_names == expected
        assert len(plugin_names) == 8


class TestLinuxPluginApplicability:
    """Test Linux plugin applicability."""

    def test_linux_plugins_applicable_to_linux(self) -> None:
        """Test that all Linux plugins are applicable to Linux evidence."""
        linux_plugins = [
            "linux.info",
            "linux.pslist",
            "linux.pstree",
            "linux.psaux",
            "linux.netstat",
            "linux.elfs",
        ]
        for plugin in linux_plugins:
            assert PluginApplicabilityService.is_plugin_applicable(
                plugin, EvidenceOS.LINUX
            ), f"{plugin} should be applicable to Linux"

    def test_linux_plugins_not_applicable_to_windows(self) -> None:
        """Test that Linux plugins are not applicable to Windows."""
        linux_plugins = [
            "linux.info",
            "linux.pslist",
            "linux.pstree",
            "linux.psaux",
            "linux.netstat",
            "linux.elfs",
        ]
        for plugin in linux_plugins:
            assert not PluginApplicabilityService.is_plugin_applicable(
                plugin, EvidenceOS.WINDOWS
            ), f"{plugin} should not be applicable to Windows"

    def test_get_available_plugins_linux(self) -> None:
        """Test get_available_plugins for Linux evidence."""
        plugins = PluginApplicabilityService.get_available_plugins(EvidenceOS.LINUX)
        plugin_names = [p.name for p in plugins]

        expected = [
            "linux.elfs",
            "linux.info",
            "linux.netstat",
            "linux.psaux",
            "linux.pslist",
            "linux.pstree",
        ]
        assert plugin_names == expected

    def test_get_core_plugin_names_linux(self) -> None:
        """Test get_core_plugin_names for Linux evidence."""
        plugin_names = PluginApplicabilityService.get_core_plugin_names(
            EvidenceOS.LINUX
        )
        expected = [
            "linux.elfs",
            "linux.info",
            "linux.netstat",
            "linux.psaux",
            "linux.pslist",
            "linux.pstree",
        ]
        assert plugin_names == expected
        assert len(plugin_names) == 6


class TestCrossOSApplicability:
    """Test applicability across different OS types."""

    def test_no_plugins_for_macos(self) -> None:
        """Test that no core plugins are defined for macOS (not in MVP scope)."""
        plugins = PluginApplicabilityService.get_available_plugins(EvidenceOS.MACOS)
        assert len(plugins) == 0

    def test_is_plugin_applicable_macos(self) -> None:
        """Test is_plugin_applicable returns False for macOS."""
        assert not PluginApplicabilityService.is_plugin_applicable(
            "windows.pslist", EvidenceOS.MACOS
        )
        assert not PluginApplicabilityService.is_plugin_applicable(
            "linux.pslist", EvidenceOS.MACOS
        )
        assert not PluginApplicabilityService.is_plugin_applicable(
            "nonexistent.plugin", EvidenceOS.MACOS
        )

    def test_windows_only_plugins_not_applicable_to_linux(self) -> None:
        """
        Test that Windows-only plugins (threads, malfind, dlllist) are
        not applicable to Linux per REQUIREMENTS.md FR-03.
        """
        windows_only_plugins = ["windows.threads", "windows.malfind", "windows.dlllist"]
        for plugin in windows_only_plugins:
            assert not PluginApplicabilityService.is_plugin_applicable(
                plugin, EvidenceOS.LINUX
            ), f"{plugin} should not be applicable to Linux"


class TestPluginsByCategory:
    """Test filtering plugins by category."""

    def test_get_plugins_by_category_windows_process(self) -> None:
        """Test get_plugins_by_category for Windows process plugins."""
        plugins = PluginApplicabilityService.get_plugins_by_category(
            EvidenceOS.WINDOWS, PluginCategory.PROCESS
        )
        plugin_names = [p.name for p in plugins]
        expected = ["windows.cmdline", "windows.pslist", "windows.pstree"]
        assert plugin_names == expected

    def test_get_plugins_by_category_linux_process(self) -> None:
        """Test get_plugins_by_category for Linux process plugins."""
        plugins = PluginApplicabilityService.get_plugins_by_category(
            EvidenceOS.LINUX, PluginCategory.PROCESS
        )
        plugin_names = [p.name for p in plugins]
        expected = ["linux.psaux", "linux.pslist", "linux.pstree"]
        assert plugin_names == expected

    def test_get_plugins_by_category_system_info(self) -> None:
        """Test get_plugins_by_category for system info plugins."""
        windows_sys = PluginApplicabilityService.get_plugins_by_category(
            EvidenceOS.WINDOWS, PluginCategory.SYSTEM_INFO
        )
        linux_sys = PluginApplicabilityService.get_plugins_by_category(
            EvidenceOS.LINUX, PluginCategory.SYSTEM_INFO
        )
        assert len(windows_sys) == 1
        assert windows_sys[0].name == "windows.info"
        assert len(linux_sys) == 1
        assert linux_sys[0].name == "linux.info"

    def test_get_plugins_by_category_memory_region_windows_only(self) -> None:
        """Test that memory_region category plugins are Windows-only."""
        windows_mem = PluginApplicabilityService.get_plugins_by_category(
            EvidenceOS.WINDOWS, PluginCategory.MEMORY_REGION
        )
        linux_mem = PluginApplicabilityService.get_plugins_by_category(
            EvidenceOS.LINUX, PluginCategory.MEMORY_REGION
        )
        assert len(windows_mem) == 1
        assert windows_mem[0].name == "windows.malfind"
        assert len(linux_mem) == 0

    def test_get_plugins_by_category_thread_windows_only(self) -> None:
        """Test that thread category plugins are Windows-only."""
        windows_thread = PluginApplicabilityService.get_plugins_by_category(
            EvidenceOS.WINDOWS, PluginCategory.THREAD
        )
        linux_thread = PluginApplicabilityService.get_plugins_by_category(
            EvidenceOS.LINUX, PluginCategory.THREAD
        )
        assert len(windows_thread) == 1
        assert windows_thread[0].name == "windows.threads"
        assert len(linux_thread) == 0

    def test_get_plugins_by_category_network(self) -> None:
        """Test network category plugins are available for both OSes."""
        windows_net = PluginApplicabilityService.get_plugins_by_category(
            EvidenceOS.WINDOWS, PluginCategory.NETWORK
        )
        linux_net = PluginApplicabilityService.get_plugins_by_category(
            EvidenceOS.LINUX, PluginCategory.NETWORK
        )
        assert len(windows_net) == 1
        assert windows_net[0].name == "windows.netscan"
        assert len(linux_net) == 1
        assert linux_net[0].name == "linux.netstat"


class TestPluginMetadataAccuracy:
    """Test that plugin metadata matches REQUIREMENTS.md FR-03."""

    def test_windows_core_plugins_count(self) -> None:
        """Test that Windows core plugin set has 8 plugins as per REQUIREMENTS.md."""
        windows_plugins = PluginApplicabilityService.get_available_plugins(
            EvidenceOS.WINDOWS
        )
        assert len(windows_plugins) == 8

    def test_linux_core_plugins_count(self) -> None:
        """Test that Linux core plugin set has 6 plugins as per REQUIREMENTS.md."""
        linux_plugins = PluginApplicabilityService.get_available_plugins(
            EvidenceOS.LINUX
        )
        assert len(linux_plugins) == 6

    def test_all_plugin_names_are_unique(self) -> None:
        """Test that all plugin names are unique."""
        all_plugins = PluginApplicabilityService.all_plugins()
        plugin_names = [p.name for p in all_plugins]
        assert len(plugin_names) == len(set(plugin_names))

    def test_plugin_descriptions_not_empty(self) -> None:
        """Test that all plugins have non-empty descriptions."""
        for plugin in PluginApplicabilityService.all_plugins():
            assert plugin.description
            assert len(plugin.description) > 0

    def test_plugin_categories_valid(self) -> None:
        """Test that all plugins have valid categories."""
        valid_categories = set(PluginCategory)
        for plugin in PluginApplicabilityService.all_plugins():
            assert plugin.category in valid_categories
