"""Expose Volatility's runtime plugin search path to PyInstaller's analyzer."""

from pathlib import Path

from PyInstaller.utils.hooks import get_package_paths


def pre_safe_import_module(api):
    api.append_package_path(str(Path(get_package_paths("volatility3")[1]) / "framework/plugins"))
