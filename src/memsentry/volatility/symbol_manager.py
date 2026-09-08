from __future__ import annotations

from pathlib import Path

from memsentry.volatility.os_utils import normalise_os


class SymbolManager:
    """Manages Volatility 3 symbol tables used by MemSentry."""

    def __init__(self, symbol_dir: str | None = None) -> None:
        self.symbol_dir = (
            Path(symbol_dir)
            if symbol_dir
            else Path(__file__).resolve().parent / "symbols"
        )

        self.symbol_dir.mkdir(parents=True, exist_ok=True)

    def get_symbol_path(self, os_name: str) -> Path:
        """Return the directory containing symbols for an OS."""
        return self.symbol_dir / normalise_os(os_name)

    def symbols_available(self, os_name: str) -> bool:
        """Check whether symbols for the requested OS exist."""
        path = self.get_symbol_path(os_name)
        if not path.exists():
            return False

        return any(path.iterdir())

    def symbols_used_by(self, os_name: str) -> list[str]:
        """Return the names of locally installed symbol tables for an OS.

        Each entry corresponds to one symbol table (e.g. a kernel or a
        process/application) that Volatility can resolve for the given OS.
        """
        path = self.get_symbol_path(os_name)
        if not path.exists():
            return []

        symbols = []
        for symbol_file in path.rglob("*"):
            if symbol_file.is_file():
                name = symbol_file.stem
                if name and name not in symbols:
                    symbols.append(name)
        return symbols

    def list_symbols(self, os_name: str) -> list[Path]:
        """List symbol files available for an OS."""
        path = self.get_symbol_path(os_name)
        if not path.exists():
            return []

        return [p for p in path.rglob("*") if p.is_file()]

    def get_status(self) -> dict:
        """Return availability status for supported operating systems."""
        return {
            "windows": self.symbols_available("windows"),
            "linux": self.symbols_available("linux"),
            "mac": self.symbols_available("mac"),
        }
