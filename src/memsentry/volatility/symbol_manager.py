from pathlib import Path
from typing import Optional

class SymbolManager:
    """Manages Volatility 3 symbol tables used by MemSentry."""

    def __init__(self, symbol_dir: Optional[str] = None):
        self.symbol_dir = (
            Path(symbol_dir)
            if symbol_dir
            else Path(__file__).resolve().parent / "symbols"
        )

        self.symbol_dir.mkdir(parents=True, exist_ok=True)

    def get_symbol_path(self, os_name: str) -> Path:
        """Return the directory containing symbols for an OS."""
        return self.symbol_dir / os_name.lower()

    def symbols_available(self, os_name: str) -> bool:
        """Check whether symbols for the requested OS exist."""
        path = self.get_symbol_path(os_name)
        if not path.exists():
            return False

        return any(path.iterdir())

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