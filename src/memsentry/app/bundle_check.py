"""Check a built distribution without opening user workspaces or evidence."""

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from PySide6.QtWidgets import QApplication

import yara
from memsentry.correlation.rule_loader import get_default_rules_path, load_rules_from_yaml
from memsentry.gui.branding import application_icon
from memsentry.gui.pages.investigation_graph import create_page
from memsentry.resource_paths import resource_directory
from memsentry.storage.database import Database
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.volatility.plugin_registry import PluginRegistry


def check_bundle() -> None:
    app = QApplication.instance() or QApplication([])
    if application_icon().pixmap(64, 64).isNull():
        raise RuntimeError("Application icon is missing or cannot be rendered.")
    resources = resource_directory()
    for relative in ("plugin_registry.json", "rules/correlation_rules.yaml",
                     "yara/memsentry_process_indicators.yara"):
        if not (resources / relative).is_file():
            raise RuntimeError(f"Missing bundled resource: {relative}")
    registry = PluginRegistry()
    for plugin in ("windows.pslist.PsList", "windows.netscan.NetScan", "linux.pslist.PsList"):
        if plugin not in registry.discovered_plugins:
            raise RuntimeError(f"Bundled Volatility plugin could not be discovered: {plugin}")
    if not load_rules_from_yaml(get_default_rules_path()):
        raise RuntimeError("Bundled correlation rules could not be loaded.")
    yara.compile(filepath=str(resources / "yara/memsentry_process_indicators.yara"))
    with TemporaryDirectory(prefix="memsentry-bundle-check-") as folder:
        database = Database(Path(folder) / "check.sqlite3")
        database.initialize()
        ArtifactRepository(database).list_by_analysis_run(uuid4())
    page = create_page()
    page.show()
    app.processEvents()
    page.close()
    result = json.dumps({"status": "ok", "plugins": len(registry.discovered_plugins),
                         "icon": True, "resources": True, "database_migrations": True})
    # Windowed Windows applications have no stdout; the build check also uses the exit code.
    if sys.stdout is not None:
        print(result)
