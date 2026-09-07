"""Application-level orchestration of a Volatility analysis run."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Any

from memsentry.correlation.engine import CorrelationEngine
from memsentry.volatility.adapter import VolatilityAdapter
from memsentry.volatility.plugin_registry import PluginRegistry
from memsentry.volatility.plugin_runner import PluginRunner
from memsentry.yara.scanner import YaraScanResult, YaraScanner


class AnalysisService:
    """Coordinates selected Volatility plugins for a single evidence image.

    The service delegates execution and persistence to the ``PluginRunner``
    and then hands the produced artifacts to the correlation engine.
    """

    def __init__(
        self,
        volatility_adapter: VolatilityAdapter,
        plugin_registry: PluginRegistry,
        plugin_runner: PluginRunner,
        correlation_engine: CorrelationEngine | None = None,
        os_type: str = "windows",
        dump_path: str = "",
        yara_scanner: YaraScanner | None = None,
    ) -> None:
        self.volatility_adapter = volatility_adapter
        self.plugin_registry = plugin_registry
        self.plugin_runner = plugin_runner
        self.correlation_engine = correlation_engine
        self.os_type = os_type
        self.dump_path = dump_path
        self.yara_scanner = yara_scanner

    def run(
        self,
        analysis_run_id: Any,
        plugin_ids: Sequence[str],
        yara_rule_paths: Sequence[str | Path] = (),
    ) -> list[dict[str, Any]]:
        """Analyze the evidence using the specified Volatility plugins.

        For each ``plugin_id`` the underlying :class:`PluginRunner` executes the
        plugin against the read-only image, persists the raw output and
        normalized artifacts, and returns a per-plugin result dict.
        """
        selected = self.plugin_registry.validate_selection(self.os_type, plugin_ids)
        results: list[dict[str, Any]] = []
        for plugin in selected:
            results.append(
                self.plugin_runner.run_plugin(
                    evidence_path=self.dump_path,
                    analysis_run_id=analysis_run_id,
                    plugin_id=plugin.id,
                    os_type=self.os_type,
                )
            )

        if yara_rule_paths:
            if self.yara_scanner is None:
                raise ValueError("YARA rules were supplied but no YaraScanner is configured.")
            yara_result = self.yara_scanner.scan(
                self.dump_path,
                analysis_run_id,
                tuple(yara_rule_paths),
                self.os_type,
            )
        else:
            yara_result = YaraScanResult(False, None, None, {}, ())
        results.append({"yara": yara_result})

        # TODO: Correlate the artifacts from all plugins and persist the results.

        return results
