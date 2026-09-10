"""Approved Volatility plugin discovery and metadata management."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

from volatility3 import framework, plugins

from memsentry.volatility import os_utils
from memsentry.volatility.os_utils import SUPPORTED_OPERATING_SYSTEMS

_DEFAULT_REGISTRY_FILE = (
    Path(__file__).resolve().parents[3] / "resources" / "plugin_registry.json"
)


class PluginRegistryError(RuntimeError):
    """Base error raised by the plugin registry."""


class PluginMetadataError(PluginRegistryError):
    """Raised when the registry metadata is missing or malformed."""


class UnsupportedOperatingSystemError(PluginRegistryError):
    """Raised when an unsupported operating system is requested."""


class PluginSelectionError(PluginRegistryError):
    """Raised when a requested plugin cannot be selected for an OS."""


@dataclass(frozen=True, slots=True)
class PluginDefinition:
    """MemSentry metadata for one approved analysis capability."""

    id: str
    display_name: str
    description: str
    category: str
    supported_os: tuple[str, ...]
    volatility_plugins: Mapping[str, str]
    parser: str
    default_enabled: bool
    requires_symbols: bool
    experimental: bool

    def volatility_plugin_for(self, os_type: str) -> str | None:
        """Return this capability's Volatility plugin identifier for an OS."""
        return self.volatility_plugins.get(_normalise_os(os_type))

    def as_dict(self, os_type: str | None = None) -> dict[str, Any]:
        """Return GUI-friendly, serialisable metadata."""
        data: dict[str, Any] = {
            "id": self.id,
            "display_name": self.display_name,
            "description": self.description,
            "category": self.category,
            "supported_os": list(self.supported_os),
            "volatility_plugins": dict(self.volatility_plugins),
            "parser": self.parser,
            "default_enabled": self.default_enabled,
            "requires_symbols": self.requires_symbols,
            "experimental": self.experimental,
        }
        if os_type is not None:
            data["volatility_plugin"] = self.volatility_plugin_for(os_type)
        return data


class PluginRegistry:
    """Expose only configured and locally available Volatility plugins.

    The registry is intentionally an allow-list: discovering a Volatility plugin
    does not make it selectable unless it is defined in ``plugin_registry.json``.
    """

    def __init__(
        self,
        registry_path: Path | None = None,
        discovered_plugins: Mapping[str, type[Any]] | None = None,
    ) -> None:
        self._registry_path = registry_path or _DEFAULT_REGISTRY_FILE
        self._import_failures: tuple[str, ...] = ()
        if discovered_plugins is None:
            discovered_plugins = self._discover_plugins()
        self._plugin_list = dict(discovered_plugins)
        self._plugin_metadata = self._load_metadata()
        self._metadata_by_id = {plugin.id: plugin for plugin in self._plugin_metadata}
        self._plugins_by_os: dict[str, tuple[PluginDefinition, ...]] = {}
        self.build_metadata()

    @property
    def import_failures(self) -> tuple[str, ...]:
        """Plugin modules Volatility could not import due to optional dependencies."""
        return self._import_failures

    @property
    def discovered_plugins(self) -> Mapping[str, type[Any]]:
        """Return the Volatility plugins discovered in the local environment."""
        return MappingProxyType(self._plugin_list)

    @property
    def plugin_metadata(self) -> tuple[PluginDefinition, ...]:
        """Return all configured MemSentry plugin definitions."""
        return self._plugin_metadata

    def build_metadata(self) -> None:
        """Filter configured metadata to the plugins available in Volatility."""
        available: dict[str, list[PluginDefinition]] = {
            os_type: [] for os_type in SUPPORTED_OPERATING_SYSTEMS
        }
        for plugin in self._plugin_metadata:
            for os_type in plugin.supported_os:
                volatility_plugin = plugin.volatility_plugins[os_type]
                if volatility_plugin in self._plugin_list:
                    available[os_type].append(plugin)

        self._plugins_by_os = {
            os_type: tuple(definitions) for os_type, definitions in available.items()
        }

    def available_plugins(
        self, os_type: str, *, include_experimental: bool = False
    ) -> tuple[PluginDefinition, ...]:
        """Return approved, discovered plugins selectable for ``os_type``."""
        normalised_os = _normalise_os(os_type)
        plugins_for_os = self._plugins_by_os[normalised_os]
        if include_experimental:
            return plugins_for_os
        return tuple(plugin for plugin in plugins_for_os if not plugin.experimental)

    def unavailable_plugins(self, os_type: str) -> tuple[PluginDefinition, ...]:
        """Return configured plugins that are not available for ``os_type``."""
        normalised_os = _normalise_os(os_type)
        return tuple(
            plugin
            for plugin in self._plugin_metadata
            if normalised_os in plugin.supported_os
            and plugin.volatility_plugins[normalised_os] not in self._plugin_list
        )

    def get_plugin(self, plugin_id: str) -> PluginDefinition:
        """Return configured metadata for a MemSentry plugin ID."""
        try:
            return self._metadata_by_id[plugin_id]
        except KeyError as error:
            raise PluginSelectionError(f"Unknown plugin ID: {plugin_id}") from error

    def get_volatility_plugin(self, plugin_id: str, os_type: str) -> type[Any]:
        """Return an approved, discovered Volatility plugin class.

        Raises ``PluginSelectionError`` when the capability is unavailable for
        the requested operating system.
        """
        plugin = self.get_plugin(plugin_id)
        volatility_plugin_name = plugin.volatility_plugin_for(os_type)
        if volatility_plugin_name is None:
            raise PluginSelectionError(
                f"Plugin '{plugin_id}' is not supported for {_normalise_os(os_type)}."
            )
        try:
            return self._plugin_list[volatility_plugin_name]
        except KeyError as error:
            raise PluginSelectionError(
                f"Plugin '{plugin_id}' requires unavailable Volatility plugin "
                f"'{volatility_plugin_name}'."
            ) from error

    def parser_for(self, plugin_id: str, os_type: str) -> str:
        """Return a parser name after verifying the plugin is selectable."""
        self.get_volatility_plugin(plugin_id, os_type)
        return self.get_plugin(plugin_id).parser

    def map_plugins(self, os_type: str) -> Mapping[str, PluginDefinition]:
        """Map available Volatility plugin names to MemSentry metadata."""
        mappings: dict[str, PluginDefinition] = {}
        for plugin in self.available_plugins(os_type, include_experimental=True):
            volatility_plugin = plugin.volatility_plugin_for(os_type)
            if volatility_plugin is not None:
                mappings[volatility_plugin] = plugin
        return MappingProxyType(mappings)

    def validate_selection(
        self, os_type: str, plugin_ids: Sequence[str]
    ) -> tuple[PluginDefinition, ...]:
        """Validate a user selection and return the selected definitions.

        Empty selections and duplicate IDs are rejected because they make an
        analysis run ambiguous and impair reproducibility.
        """
        normalised_os = _normalise_os(os_type)
        if not plugin_ids:
            raise PluginSelectionError("Select at least one plugin before analysis.")
        if len(set(plugin_ids)) != len(plugin_ids):
            raise PluginSelectionError("A plugin can only be selected once.")

        selected: list[PluginDefinition] = []
        for plugin_id in plugin_ids:
            self.get_volatility_plugin(plugin_id, normalised_os)
            selected.append(self.get_plugin(plugin_id))
        return tuple(selected)

    def _discover_plugins(self) -> Mapping[str, type[Any]]:
        self._import_failures = tuple(framework.import_files(plugins, ignore_errors=True))
        return cast(Mapping[str, type[Any]], framework.list_plugins())

    def _load_metadata(self) -> tuple[PluginDefinition, ...]:
        try:
            with self._registry_path.open(encoding="utf-8") as registry_file:
                data = json.load(registry_file)
        except FileNotFoundError as error:
            raise PluginMetadataError(
                f"Plugin registry file was not found: {self._registry_path}"
            ) from error
        except json.JSONDecodeError as error:
            raise PluginMetadataError(
                f"Plugin registry contains invalid JSON: {self._registry_path}"
            ) from error

        if not isinstance(data, dict) or not isinstance(data.get("plugins"), list):
            raise PluginMetadataError("Plugin registry must contain a 'plugins' list.")

        definitions = tuple(_parse_plugin_metadata(item) for item in data["plugins"])
        plugin_ids = [plugin.id for plugin in definitions]
        if len(plugin_ids) != len(set(plugin_ids)):
            raise PluginMetadataError("Plugin registry contains duplicate plugin IDs.")
        return definitions


def _normalise_os(os_type: str) -> str:
    try:
        return os_utils.normalise_os(os_type)
    except os_utils.UnsupportedOperatingSystemError as error:
        raise UnsupportedOperatingSystemError(str(error)) from error


def _parse_plugin_metadata(value: Any) -> PluginDefinition:
    if not isinstance(value, dict):
        raise PluginMetadataError("Each plugin registry entry must be an object.")

    required_fields = {
        "id",
        "display_name",
        "description",
        "category",
        "supported_os",
        "volatility_plugins",
        "parser",
        "default_enabled",
        "requires_symbols",
        "experimental",
    }
    missing_fields = required_fields - value.keys()
    if missing_fields:
        raise PluginMetadataError(
            f"Plugin metadata is missing fields: {', '.join(sorted(missing_fields))}."
        )

    string_fields = ("id", "display_name", "description", "category", "parser")
    for field in string_fields:
        if not isinstance(value[field], str) or not value[field].strip():
            raise PluginMetadataError(f"Plugin field '{field}' must be a non-empty string.")
    for field in ("default_enabled", "requires_symbols", "experimental"):
        if not isinstance(value[field], bool):
            raise PluginMetadataError(f"Plugin field '{field}' must be a boolean.")

    supported_os_value = value["supported_os"]
    if not isinstance(supported_os_value, list) or not supported_os_value:
        raise PluginMetadataError("Plugin field 'supported_os' must be a non-empty list.")
    supported_os = tuple(_normalise_os(os_type) for os_type in supported_os_value)
    if len(supported_os) != len(set(supported_os)):
        raise PluginMetadataError("Plugin field 'supported_os' contains duplicate values.")

    volatility_plugins = value["volatility_plugins"]
    if not isinstance(volatility_plugins, dict):
        raise PluginMetadataError("Plugin field 'volatility_plugins' must be an object.")
    normalised_volatility_plugins = {
        _normalise_os(os_type): plugin_name
        for os_type, plugin_name in volatility_plugins.items()
    }
    if set(normalised_volatility_plugins) != set(supported_os):
        raise PluginMetadataError(
            "Plugin 'supported_os' and 'volatility_plugins' must contain the same OS values."
        )
    if any(
        not isinstance(plugin_name, str) or not plugin_name.strip()
        for plugin_name in normalised_volatility_plugins.values()
    ):
        raise PluginMetadataError(
            "Each 'volatility_plugins' value must be a non-empty string."
        )

    return PluginDefinition(
        id=value["id"],
        display_name=value["display_name"],
        description=value["description"],
        category=value["category"],
        supported_os=supported_os,
        volatility_plugins=MappingProxyType(normalised_volatility_plugins),
        parser=value["parser"],
        default_enabled=value["default_enabled"],
        requires_symbols=value["requires_symbols"],
        experimental=value["experimental"],
    )
