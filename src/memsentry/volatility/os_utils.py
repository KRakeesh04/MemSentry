"""Shared operating-system helpers for the Volatility boundary.

The volatility package consistently needs to validate and normalise the
operating-system name (``windows``, ``linux``, ``mac``) that a plugin or
symbol set targets. These helpers are the single source of truth for that
logic so it is not re-implemented in every module.
"""

from __future__ import annotations

WINDOWS_OS = "windows"
LINUX_OS = "linux"
MAC_OS = "mac"
SUPPORTED_OPERATING_SYSTEMS = frozenset({WINDOWS_OS, LINUX_OS, MAC_OS})


class UnsupportedOperatingSystemError(ValueError):
    """Raised when an operating system is not supported by MemSentry."""


def normalise_os(os_type: str) -> str:
    """Normalise and validate an operating-system name.

    Accepts case-insensitive input (for example ``"WINDOWS"``) and returns the
    canonical lowercase name. Raises :class:`UnsupportedOperatingSystemError`
    for anything outside the supported set.
    """
    if not isinstance(os_type, str):
        raise UnsupportedOperatingSystemError("Operating system must be a string.")
    normalised = os_type.strip().lower()
    if normalised not in SUPPORTED_OPERATING_SYSTEMS:
        raise UnsupportedOperatingSystemError(
            f"Unsupported operating system '{os_type}'. "
            f"Supported values: {supported_os_text()}."
        )
    return normalised


def supported_os_text() -> str:
    """Return a human-readable list of the supported operating systems."""
    return ", ".join(sorted(SUPPORTED_OPERATING_SYSTEMS))
