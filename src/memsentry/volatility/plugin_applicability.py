"""Plugin applicability and metadata service for Volatility 3 core plugins."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar

from memsentry.models.evidence import EvidenceOS


class PluginCategory(StrEnum):
    """Category classification for a Volatility plugin."""

    SYSTEM_INFO = "system_info"
    PROCESS = "process"
    MEMORY_REGION = "memory_region"
    MODULE = "module"
    NETWORK = "network"
    THREAD = "thread"
    YARA = "yara"


@dataclass
class PluginMetadata:
    """Metadata for a Volatility 3 core plugin."""

    name: str
    """Plugin name as called in Volatility (e.g., 'windows.pslist')."""

    supported_os: frozenset[EvidenceOS]
    """Operating systems this plugin supports."""

    category: PluginCategory
    """Classification of artifact type produced."""

    description: str
    """User-facing description of what the plugin does."""

    def supports_os(self, evidence_os: EvidenceOS) -> bool:
        """Check if this plugin supports the given evidence OS."""
        return evidence_os in self.supported_os


class PluginApplicabilityService:
    """
    Determine plugin applicability and provide plugin metadata.

    This service defines the approved core Volatility 3 plugins for Windows and
    Linux image analysis and provides methods to query their applicability for
    a given target OS.

    From REQUIREMENTS.md FR-03:
    - Windows core plugins: windows.info, windows.pslist, windows.pstree,
      windows.cmdline, windows.netscan, windows.malfind, windows.dlllist,
      windows.threads
    - Linux core plugins: linux.info, linux.pslist, linux.pstree, linux.psaux,
      linux.netstat, linux.elfs
    - Windows-only memory-region and thread artifacts (malfind, dlllist, threads)
      must be marked "not applicable" for Linux, not missing.
    """

    # Approved core plugins by name and metadata
    _PLUGINS: ClassVar[dict[str, PluginMetadata]] = {
        # Windows plugins
        "windows.info": PluginMetadata(
            name="windows.info",
            supported_os=frozenset([EvidenceOS.WINDOWS]),
            category=PluginCategory.SYSTEM_INFO,
            description="Display system information from Windows memory image",
        ),
        "windows.pslist": PluginMetadata(
            name="windows.pslist",
            supported_os=frozenset([EvidenceOS.WINDOWS]),
            category=PluginCategory.PROCESS,
            description="List running processes from Windows memory image",
        ),
        "windows.pstree": PluginMetadata(
            name="windows.pstree",
            supported_os=frozenset([EvidenceOS.WINDOWS]),
            category=PluginCategory.PROCESS,
            description="Display process tree hierarchy from Windows memory image",
        ),
        "windows.cmdline": PluginMetadata(
            name="windows.cmdline",
            supported_os=frozenset([EvidenceOS.WINDOWS]),
            category=PluginCategory.PROCESS,
            description="Extract command-line arguments from Windows processes",
        ),
        "windows.netscan": PluginMetadata(
            name="windows.netscan",
            supported_os=frozenset([EvidenceOS.WINDOWS]),
            category=PluginCategory.NETWORK,
            description="Scan for network connections and sockets in Windows memory",
        ),
        "windows.malfind": PluginMetadata(
            name="windows.malfind",
            supported_os=frozenset([EvidenceOS.WINDOWS]),
            category=PluginCategory.MEMORY_REGION,
            description="Find injected code and suspicious memory regions in Windows",
        ),
        "windows.dlllist": PluginMetadata(
            name="windows.dlllist",
            supported_os=frozenset([EvidenceOS.WINDOWS]),
            category=PluginCategory.MODULE,
            description="List loaded DLLs (modules) for each process in Windows",
        ),
        "windows.threads": PluginMetadata(
            name="windows.threads",
            supported_os=frozenset([EvidenceOS.WINDOWS]),
            category=PluginCategory.THREAD,
            description="Extract thread information from Windows processes",
        ),
        # Linux plugins
        "linux.info": PluginMetadata(
            name="linux.info",
            supported_os=frozenset([EvidenceOS.LINUX]),
            category=PluginCategory.SYSTEM_INFO,
            description="Display system information from Linux memory image",
        ),
        "linux.pslist": PluginMetadata(
            name="linux.pslist",
            supported_os=frozenset([EvidenceOS.LINUX]),
            category=PluginCategory.PROCESS,
            description="List running processes from Linux memory image",
        ),
        "linux.pstree": PluginMetadata(
            name="linux.pstree",
            supported_os=frozenset([EvidenceOS.LINUX]),
            category=PluginCategory.PROCESS,
            description="Display process tree hierarchy from Linux memory image",
        ),
        "linux.psaux": PluginMetadata(
            name="linux.psaux",
            supported_os=frozenset([EvidenceOS.LINUX]),
            category=PluginCategory.PROCESS,
            description="Extract full command-line and environment from Linux processes",
        ),
        "linux.netstat": PluginMetadata(
            name="linux.netstat",
            supported_os=frozenset([EvidenceOS.LINUX]),
            category=PluginCategory.NETWORK,
            description="Scan for network connections in Linux memory",
        ),
        "linux.elfs": PluginMetadata(
            name="linux.elfs",
            supported_os=frozenset([EvidenceOS.LINUX]),
            category=PluginCategory.MODULE,
            description="List loaded ELF modules from Linux processes",
        ),
    }

    @classmethod
    def get_plugin_metadata(cls, plugin_name: str) -> PluginMetadata | None:
        """
        Retrieve metadata for a core plugin by name.

        Args:
            plugin_name: The plugin name (e.g., 'windows.pslist').

        Returns:
            PluginMetadata if the plugin is in the approved core set, None otherwise.
        """
        return cls._PLUGINS.get(plugin_name)

    @classmethod
    def is_plugin_applicable(cls, plugin_name: str, evidence_os: EvidenceOS) -> bool:
        """
        Determine if a plugin can be run against a given evidence OS.

        Args:
            plugin_name: The plugin name (e.g., 'windows.pslist').
            evidence_os: The target OS of the evidence (windows/linux/macos).

        Returns:
            True if the plugin is in the approved core set and supports the evidence OS.
            False if the plugin is not in the approved set or does not support the OS.
        """
        metadata = cls.get_plugin_metadata(plugin_name)
        if metadata is None:
            return False
        return metadata.supports_os(evidence_os)

    @classmethod
    def get_available_plugins(cls, evidence_os: EvidenceOS) -> list[PluginMetadata]:
        """
        Get all applicable core plugins for a given evidence OS.

        Args:
            evidence_os: The target OS of the evidence (windows/linux/macos).

        Returns:
            List of PluginMetadata for all approved core plugins that support
            this OS, sorted by name.
        """
        applicable = [
            metadata
            for metadata in cls._PLUGINS.values()
            if metadata.supports_os(evidence_os)
        ]
        return sorted(applicable, key=lambda p: p.name)

    @classmethod
    def get_core_plugin_names(cls, evidence_os: EvidenceOS) -> list[str]:
        """
        Get the list of approved core plugin names for a given evidence OS.

        Args:
            evidence_os: The target OS of the evidence (windows/linux/macos).

        Returns:
            Sorted list of plugin names (e.g., ['windows.cmdline', 'windows.info', ...]).
        """
        plugins = cls.get_available_plugins(evidence_os)
        return [p.name for p in plugins]

    @classmethod
    def get_plugins_by_category(
        cls, evidence_os: EvidenceOS, category: PluginCategory
    ) -> list[PluginMetadata]:
        """
        Get all applicable plugins for a given OS and category.

        Args:
            evidence_os: The target OS of the evidence.
            category: The artifact category to filter by.

        Returns:
            List of applicable PluginMetadata matching the category, sorted by name.
        """
        all_applicable = cls.get_available_plugins(evidence_os)
        filtered = [p for p in all_applicable if p.category == category]
        return sorted(filtered, key=lambda p: p.name)

    @classmethod
    def is_core_plugin(cls, plugin_name: str) -> bool:
        """
        Check if a plugin name is in the approved core set.

        Args:
            plugin_name: The plugin name to check.

        Returns:
            True if the plugin is in the approved core set.
        """
        return plugin_name in cls._PLUGINS

    @classmethod
    def all_plugins(cls) -> list[PluginMetadata]:
        """
        Get all core plugins.

        Returns:
            List of all PluginMetadata, sorted by name.
        """
        return sorted(cls._PLUGINS.values(), key=lambda p: p.name)
