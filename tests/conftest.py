"""Select host-specific tests while keeping shared coverage on every OS."""

import sys

import pytest

pytest_plugins = ["pytester"]


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--test-os",
        choices=("linux", "windows", "macos"),
        help="Require this host OS; shared tests and matching OS tests will run.",
    )


def pytest_configure(config: pytest.Config) -> None:
    host = {"linux": "linux", "win32": "windows", "darwin": "macos"}.get(
        sys.platform, sys.platform
    )
    requested = config.getoption("--test-os")
    if requested and requested != host:
        raise pytest.UsageError(f"--test-os={requested} requires {requested}; host is {host}")


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        for marker, platform in (
            ("linux", "linux"),
            ("windows", "win32"),
            ("macos", "darwin"),
        ):
            if item.get_closest_marker(marker) and sys.platform != platform:
                item.add_marker(pytest.mark.skip(reason=f"Requires a {marker} host"))
