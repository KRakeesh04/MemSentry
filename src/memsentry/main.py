from pathlib import Path

from memsentry.gui.application import create_application
from memsentry.storage.database import Database
from memsentry.storage.repositories.case_repository import CaseRepository


def main() -> None:
    database = Database(Path("runtime/database/case.sqlite3"))
    database.initialize()
    app = create_application(CaseRepository(database))
    app.exec()
