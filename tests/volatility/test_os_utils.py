from __future__ import annotations

import pytest

from memsentry.volatility.os_utils import (
    SUPPORTED_OPERATING_SYSTEMS,
    UnsupportedOperatingSystemError,
    normalise_os,
    supported_os_text,
)


def test_normalise_os_accepts_case_insensitive_input() -> None:
    assert normalise_os("WINDOWS") == "windows"
    assert normalise_os(" Linux ") == "linux"
    assert normalise_os("MAC") == "mac"


def test_normalise_os_returns_canonical_supported_values() -> None:
    assert set(SUPPORTED_OPERATING_SYSTEMS) == {"windows", "linux", "mac"}
    for value in SUPPORTED_OPERATING_SYSTEMS:
        assert normalise_os(value) == value


def test_normalise_os_rejects_unsupported_value() -> None:
    with pytest.raises(UnsupportedOperatingSystemError):
        normalise_os("android")
    with pytest.raises(UnsupportedOperatingSystemError):
        normalise_os("")
    with pytest.raises(UnsupportedOperatingSystemError):
        normalise_os(None)


def test_supported_os_text_is_deterministic() -> None:
    assert supported_os_text() == "linux, mac, windows"
