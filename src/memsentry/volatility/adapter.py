from __future__ import annotations

import contextlib
import io
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import volatility3.plugins
from volatility3 import framework
from volatility3.cli import text_renderer
from volatility3.framework import (
    automagic,
    constants,
    contexts,
    exceptions,
    interfaces,
    plugins,
)
from volatility3.framework.automagic import stacker
from volatility3.framework.configuration import requirements

from memsentry.volatility.os_utils import UnsupportedOperatingSystemError
from memsentry.volatility.os_utils import normalise_os as _normalise_os_name
from memsentry.volatility.symbol_manager import SymbolManager, SymbolManagerError

logger = logging.getLogger(__name__)


class VolatilityAdapterError(RuntimeError):
    """Base error raised by the Volatility adapter."""


class VolatilityUnsupportedOSError(VolatilityAdapterError):
    """Raised when an unsupported operating system is requested."""


class VolatilitySymbolError(VolatilityAdapterError):
    """Raised when the required symbols are unavailable or cannot be loaded."""


class VolatilityPluginError(VolatilityAdapterError):
    """Raised when a Volatility plugin cannot be constructed or executed."""


class EvidenceNotFoundError(VolatilityAdapterError):
    """Raised when the evidence image path does not exist or is not readable."""


@dataclass(frozen=True, slots=True)
class PluginExecutionResult:
    """Standardised result of a single Volatility plugin execution."""

    plugin_name: str
    raw_output: str
    volatility_version: str
    duration_seconds: float
    output_files: tuple[str, ...] = ()


class VolatilityAdapter:
    """Adapter for interacting with Volatility 3."""

    def __init__(
        self,
        symbol_manager: SymbolManager,
        output_dir: str | Path | None = None,
        progress_callback: Any | None = None,
    ) -> None:
        self.symbol_manager = symbol_manager
        self._output_dir = Path(output_dir) if output_dir else None
        self._progress_callback = progress_callback
        self._initialized = False

    def initialize(self, os_type: str) -> None:
        """Initialize the Volatility environment for the specified OS type.

        Imports the locally installed Volatility plugin modules so that plugins
        become discoverable, then loads the required symbols.
        """
        normalised_os = self._normalise_os(os_type)
        framework.import_files(volatility3.plugins, ignore_errors=True)
        self.load_symbols(normalised_os)
        self._initialized = True

    def load_symbols(self, os_type: str) -> Path:
        """Load symbols for the specified OS type.

        Symbols are managed by the :class:`SymbolManager`. Ensures the symbol
        directory is configured so Volatility can resolve definitions.
        """
        normalised_os = self._normalise_os(os_type)
        try:
            symbol_path = self.symbol_manager.ensure_symbols(normalised_os)
        except SymbolManagerError as error:
            raise VolatilitySymbolError(str(error)) from error

        used_by = self.symbol_manager.symbols_used_by(normalised_os)
        if used_by:
            logger.debug(
                "Loaded symbols from %s for: %s",
                symbol_path,
                ", ".join(sorted(used_by)),
            )
        return symbol_path

    def run_plugin(self, plugin_name: str, evidence_path: str) -> PluginExecutionResult:
        """Run a Volatility plugin against the evidence image.

        The evidence image is opened read-only and is never modified. The
        plugin output is captured as JSON and returned in a
        :class:`PluginExecutionResult`.

        Raises :class:`VolatilityAdapterError` (via a subclass) when the
        adapter is not initialized, the evidence is invalid, the plugin cannot
        be resolved, or the plugin fails to execute.
        """
        self._assert_initialized()
        evidence = Path(evidence_path)
        self._verify_evidence(evidence)

        plugin_class = self._resolve_plugin(plugin_name)
        start_time = time.perf_counter()

        context = contexts.Context()
        automagics = self._prepare_automagics(context, plugin_class)

        try:
            single_location = requirements.URIRequirement.location_from_file(
                str(evidence)
            )
            context.config["automagic.LayerStacker.single_location"] = single_location
        except ValueError as error:
            raise VolatilityAdapterError(
                f"Could not open evidence image '{evidence}' read-only: {error}"
            ) from error

        try:
            constructed = plugins.construct_plugin(
                context,
                automagics,
                plugin_class,
                "plugins",
                self._progress_callback,
                self._file_handler_class(),
            )
            grid = constructed.run()
            raw_output = self._render_json(grid)
        except exceptions.UnsatisfiedRequirementException as error:
            raise VolatilitySymbolError(
                f"Volatility 3 could not resolve required symbols for '{evidence}': {error}"
            ) from error
        except exceptions.VolatilityException as error:
            raise VolatilityPluginError(
                f"Unable to run plugin '{plugin_name}' on '{evidence}': {error}"
            ) from error

        duration_seconds = time.perf_counter() - start_time
        volatility_version = constants.PACKAGE_VERSION

        logger.info(
            "Ran plugin '%s' in %.2fs (Volatility %s)",
            plugin_name,
            duration_seconds,
            volatility_version,
        )
        return PluginExecutionResult(
            plugin_name=plugin_name,
            raw_output=raw_output,
            volatility_version=volatility_version,
            duration_seconds=duration_seconds,
        )

    def _prepare_automagics(self, context: Any, plugin_class: type[Any]) -> list[Any]:
        automagics = automagic.available(context)
        automagics = automagic.choose_automagic(automagics, plugin_class)
        if context.config.get("automagic.LayerStacker.stackers", None) is None:
            context.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(
                plugin_class
            )
        return automagics

    @staticmethod
    def _render_json(grid: Any) -> str:
        renderer = text_renderer.JsonRenderer()
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            renderer.render(grid)
        return buffer.getvalue()

    def _file_handler_class(self) -> type[Any]:
        """Return a FileHandler that stores plugin-created files.

        When ``output_dir`` is set, these files (for example memory regions
        dumped by ``malfind``) are written to that directory. Otherwise they
        are discarded in memory.
        """
        output_dir = self._output_dir

        if output_dir is None:

            class NullFileHandler(io.BytesIO, interfaces.plugins.FileHandlerInterface):
                def __init__(self, filename: str) -> None:
                    io.BytesIO.__init__(self)
                    interfaces.plugins.FileHandlerInterface.__init__(self, filename)

                def close(self) -> None:
                    if self.closed:
                        return None
                    self._committed = True
                    io.BytesIO.close(self)

            return NullFileHandler

        class DirectoryFileHandler(
            io.BytesIO, interfaces.plugins.FileHandlerInterface
        ):
            def __init__(self, filename: str) -> None:
                io.BytesIO.__init__(self)
                interfaces.plugins.FileHandlerInterface.__init__(self, filename)

            def close(self) -> None:
                if self.closed:
                    return None
                self.seek(0)
                final_filename = self._final_filename(self.preferred_filename)
                output = Path(final_filename)
                output.parent.mkdir(parents=True, exist_ok=True)
                with output.open("wb") as file_handle:
                    file_handle.write(self.read())
                self._committed = True
                io.BytesIO.close(self)

            @staticmethod
            def _final_filename(preferred_filename: str) -> str:
                assert output_dir is not None
                output_filename = os.path.join(str(output_dir), preferred_filename)
                filename, extension = os.path.splitext(output_filename)
                counter = 1
                while os.path.exists(output_filename):
                    output_filename = f"{filename}-{counter}{extension}"
                    counter += 1
                return output_filename

        return DirectoryFileHandler

    def _resolve_plugin(self, plugin_name: str) -> type[Any]:
        try:
            return framework.list_plugins()[plugin_name]
        except KeyError as error:
            raise VolatilityPluginError(
                f"Plugin '{plugin_name}' is not installed or not discoverable."
            ) from error

    @staticmethod
    def _verify_evidence(evidence: Path) -> None:
        if not evidence.exists():
            raise EvidenceNotFoundError(f"Evidence image does not exist: {evidence}")
        if not evidence.is_file():
            raise EvidenceNotFoundError(f"Evidence path is not a file: {evidence}")
        if not os.access(evidence, os.R_OK):
            raise EvidenceNotFoundError(f"Evidence image is not readable: {evidence}")

    def _assert_initialized(self) -> None:
        if not self._initialized:
            raise VolatilityAdapterError(
                "VolatilityAdapter.initialize() must be called before running a plugin."
            )

    @classmethod
    def _normalise_os(cls, os_type: str) -> str:
        try:
            return _normalise_os_name(os_type)
        except UnsupportedOperatingSystemError as error:
            raise VolatilityUnsupportedOSError(str(error)) from error
