from __future__ import annotations

from pathlib import Path
from typing import ClassVar

import pytest

from memsentry.volatility.adapter import (
    EvidenceNotFoundError,
    VolatilityAdapter,
    VolatilityAdapterError,
    VolatilitySymbolError,
    VolatilityUnsupportedOSError,
)
from memsentry.volatility.symbol_manager import SymbolManager


def _adapter(tmp_path: Path, with_symbols: bool = True) -> VolatilityAdapter:
    symbol_manager = SymbolManager(str(tmp_path / "symbols"))
    if with_symbols:
        symbol_dir = symbol_manager.get_symbol_path("windows")
        symbol_dir.mkdir(parents=True, exist_ok=True)
        (symbol_dir / "kernel.json").write_text("{}")
    return VolatilityAdapter(symbol_manager)


def test_initialize_rejects_unsupported_os(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    with pytest.raises(VolatilityUnsupportedOSError):
        adapter.initialize("android")


def test_initialize_requires_available_symbols(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path, with_symbols=False)
    with pytest.raises(VolatilitySymbolError):
        adapter.initialize("linux")


def test_load_symbols_returns_symbol_path_when_available(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    path = adapter.load_symbols("windows")
    assert path.is_dir()
    assert path.name == "windows"


def test_load_symbols_raises_when_unavailable(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path, with_symbols=False)
    with pytest.raises(VolatilitySymbolError):
        adapter.load_symbols("windows")


def test_run_plugin_requires_initialization(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    with pytest.raises(VolatilityAdapterError):
        adapter.run_plugin("windows.info.Info", "/tmp/unused.img")


def test_run_plugin_rejects_missing_evidence(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    adapter.initialize("windows")
    with pytest.raises(EvidenceNotFoundError):
        adapter.run_plugin("windows.info.Info", "/tmp/no-such-image.img")


def test_run_plugin_rejects_directory_evidence(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    adapter.initialize("windows")
    directory = tmp_path / "not-an-image"
    directory.mkdir()
    with pytest.raises(EvidenceNotFoundError):
        adapter.run_plugin("windows.info.Info", str(directory))


def test_run_plugin_resolves_unknown_plugin(tmp_path: Path) -> None:
    adapter = _adapter(tmp_path)
    adapter.initialize("windows")
    evidence = tmp_path / "image.img"
    evidence.write_bytes(b"dummy")
    with pytest.raises(VolatilityAdapterError):
        adapter.run_plugin("nope.nope.DoesNotExist", str(evidence))


def test_run_plugin_executes_and_returns_typed_result(tmp_path: Path, monkeypatch) -> None:
    adapter = _adapter(tmp_path)
    adapter.initialize("windows")
    evidence = tmp_path / "image.img"
    evidence.write_bytes(b"dummy")

    class FakeTree:
        path = None
        parent = None
        values = (1,)

    class FakeGrid:
        populated = True
        columns: ClassVar[list[str]] = ["PID"]
        filter = None
        column_hide_list: ClassVar[list[str]] = []

        def visit(self, node, function, initial_accumulator):
            return initial_accumulator

    class FakeConstructed:
        version = (1, 0, 0)

        def run(self) -> FakeGrid:
            return FakeGrid()

    def fake_construct_plugin(*args, **kwargs):
        return FakeConstructed()

    def fake_prepare(context, plugin_class):
        return []

    monkeypatch.setattr(adapter, "_prepare_automagics", fake_prepare)

    import memsentry.volatility.adapter as adapter_module

    monkeypatch.setattr(adapter_module.plugins, "construct_plugin", fake_construct_plugin)

    result = adapter.run_plugin("windows.info.Info", str(evidence))
    assert result.plugin_name == "windows.info.Info"
    assert result.volatility_version
    assert result.duration_seconds >= 0
    assert isinstance(result.raw_output, str)


def test_render_json_outputs_valid_list(tmp_path: Path, monkeypatch) -> None:
    import json

    from memsentry.volatility.adapter import VolatilityAdapter

    adapter_module = __import__("memsentry.volatility.adapter", fromlist=["adapter"])
    renderer_calls: list = []

    class FakeRenderer:
        def render(self, grid) -> None:
            renderer_calls.append(grid)
            import sys

            sys.stdout.write('[\n  {\n    "PID": 1\n  }\n]\n')

        def __init__(self) -> None:
            renderer_calls.clear()

    monkeypatch.setattr(adapter_module.text_renderer, "JsonRenderer", FakeRenderer)

    output = VolatilityAdapter._render_json(object())
    assert json.loads(output) == [{"PID": 1}]


def test_symbol_manager_symbols_used_by_lists_symbol_tables(tmp_path: Path) -> None:
    manager = SymbolManager(str(tmp_path / "symbols"))
    symbol_dir = manager.get_symbol_path("linux")
    symbol_dir.mkdir(parents=True, exist_ok=True)
    (symbol_dir / "kernel.json").touch()
    (symbol_dir / "userspace.json").touch()

    assert set(manager.symbols_used_by("linux")) == {"kernel", "userspace"}
    assert manager.symbols_used_by("mac") == []
    assert not manager.symbols_available("mac")


def test_symbol_manager_normalises_os_and_rejects_unknown(tmp_path: Path) -> None:
    manager = SymbolManager(str(tmp_path / "symbols"))
    assert manager.get_symbol_path("WINDOWS") == manager.symbol_dir / "windows"
    with pytest.raises(ValueError):
        manager.get_symbol_path("android")
    assert manager.get_status() == {"windows": False, "linux": False, "mac": False}
