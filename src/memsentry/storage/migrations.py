from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from memsentry.storage.database import Database


logger = logging.getLogger(__name__)


SCHEMA_DIRECTORY = Path(__file__).resolve().parent / "schema"


class MigrationError(RuntimeError):
    """Raised when a database migration cannot be applied."""


class MigrationManager:
    """Discover and apply SQLite schema migrations."""

    def __init__(self, database: Database) -> None:
        self.database = database

    def apply_pending_migrations(self) -> None:
        """Apply all migrations that have not already been executed."""

        with self.database.connection() as connection:
            self._create_migration_table(connection)

            applied_versions = self._get_applied_versions(connection)

            for migration_path in self._discover_migrations():
                version = self._get_migration_version(migration_path)

                if version in applied_versions:
                    continue

                self._apply_migration(
                    connection,
                    migration_path,
                    version,
                )

    @staticmethod
    def _create_migration_table(
        connection: sqlite3.Connection,
    ) -> None:
        """Create the table that records applied migrations."""

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                applied_at TEXT NOT NULL
            )
            """
        )

    @staticmethod
    def _get_applied_versions(
        connection: sqlite3.Connection,
    ) -> set[int]:
        """Return migration versions already applied to the database."""

        rows = connection.execute(
            """
            SELECT version
            FROM schema_migrations
            """
        ).fetchall()

        return {int(row["version"]) for row in rows}

    @staticmethod
    def _discover_migrations() -> list[Path]:
        """Return migration SQL files in filename order."""

        if not SCHEMA_DIRECTORY.exists():
            raise MigrationError(
                f"Schema directory does not exist: {SCHEMA_DIRECTORY}"
            )

        return sorted(SCHEMA_DIRECTORY.glob("*.sql"))

    @staticmethod
    def _get_migration_version(
        migration_path: Path,
    ) -> int:
        """
        Extract the migration version from a filename.

        Example:
            001_create_cases.sql -> 1
        """

        prefix = migration_path.stem.split("_", maxsplit=1)[0]

        try:
            return int(prefix)

        except ValueError as exc:
            raise MigrationError(
                f"Invalid migration filename: {migration_path.name}"
            ) from exc

    @staticmethod
    def _apply_migration(
        connection: sqlite3.Connection,
        migration_path: Path,
        version: int,
    ) -> None:
        """Apply one migration and record it as completed."""

        migration_sql = migration_path.read_text(
            encoding="utf-8"
        )

        migration_name = migration_path.name.replace("'", "''")

        script = f"""
        BEGIN IMMEDIATE;

        {migration_sql}

        INSERT INTO schema_migrations (
            version,
            name,
            applied_at
        )
        VALUES (
            {version},
            '{migration_name}',
            strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        );

        COMMIT;
        """

        try:
            connection.executescript(script)

            logger.info(
                "Applied migration %s",
                migration_path.name,
            )

        except (sqlite3.Error, OSError) as exc:
            if connection.in_transaction:
                connection.rollback()

            logger.exception(
                "Failed to apply migration %s",
                migration_path.name,
            )

            raise MigrationError(
                f"Could not apply migration: "
                f"{migration_path.name}"
            ) from exc
