import sys
from pathlib import Path

import pytest


@pytest.fixture
def platform_suite(pytester: pytest.Pytester) -> pytest.Pytester:
    pytester.makeconftest(Path(__file__).with_name("conftest.py").read_text(encoding="utf-8"))
    pytester.makeini(
        "[pytest]\nmarkers =\n"
        "    windows: Windows host\n"
        "    linux: Linux host\n"
        "    macos: macOS host\n"
    )
    pytester.makepyfile(
        """
        import pytest

        def test_shared():
            pass

        @pytest.mark.windows
        def test_windows():
            pass

        @pytest.mark.linux
        def test_linux():
            pass

        @pytest.mark.macos
        def test_macos():
            pass
        """
    )
    return pytester


@pytest.mark.parametrize("explicit", [False, True])
def test_only_host_and_shared_tests_run(platform_suite, explicit):
    host = {"linux": "linux", "win32": "windows", "darwin": "macos"}[sys.platform]
    args = [f"--test-os={host}"] if explicit else []
    result = platform_suite.runpytest_subprocess(*args, "-q")
    result.assert_outcomes(passed=2, skipped=2)


def test_wrong_host_command_fails_clearly(platform_suite):
    other = "linux" if sys.platform == "win32" else "windows"
    result = platform_suite.runpytest_subprocess(f"--test-os={other}", "-q")
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines([f"*--test-os={other} requires {other}; host is *"])
