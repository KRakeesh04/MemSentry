from __future__ import annotations

import logging
import re
import sqlite3
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from memsentry.storage.database import Database

logger = logging.getLogger(__name__)

MIGRATION_FILENAME_PATTERN = re.compile(
    r"^(?P<version>\d{4})_(?P<name>[a-z0-9_]+)\.sql$"
)


class MigrationError(RuntimeError):
    """Raised when a database migration cannot be completed."""


@dataclass(frozen=True, slots=True)
class Migration:
    """Represent a single ordered SQL migration."""

    version: int
    name: str
    path: Path

    @property
    def identifier(self) -> str:
        """Return a stable migration identifier."""
        return f"{self.version:04d}_{self.name}"


class MigrationManager:
    """Discover and apply ordered SQLite schema migrations."""

    def __init__(
        self,
        database: Database,
        migrations_directory: Path | None = None,
    ) -> None:
        self.database = database
        self.migrations_directory = migrations_directory

    def apply_pending_migrations(self) -> None:
        """Apply all migrations newer than the current schema version."""
        self._ensure_migration_table()

        applied_versions = self._get_applied_versions()
        migrations = self.discover_migrations()

        for migration in migrations:
            if migration.version in applied_versions:
                continue

            self._apply_migration(migration)

    def discover_migrations(self) -> list[Migration]:
        """Load valid migration files and return them in version order."""
        migration_directory = self._resolve_migrations_directory()
        migrations: list[Migration] = []
        versions_seen: set[int] = set()

        if not migration_directory.exists():
            raise MigrationError(
                f"Migration directory does not exist: {migration_directory}"
            )

        for path in migration_directory.iterdir():
            if not path.is_file():
                continue

            match = MIGRATION_FILENAME_PATTERN.match(path.name)

            if match is None:
                continue

            version = int(match.group("version"))
            name = match.group("name")

            if version in versions_seen:
                raise MigrationError(
                    f"Duplicate migration version detected: {version:04d}"
                )

            versions_seen.add(version)

            migrations.append(
                Migration(
                    version=version,
                    name=name,
                    path=path,
                )
            )

        migrations.sort(key=lambda migration: migration.version)
        self._validate_sequence(migrations)

        return migrations

    def current_version(self) -> int:
        """Return the highest successfully applied migration version."""
        self._ensure_migration_table()

        row = self.database.fetch_one(
            """
            SELECT COALESCE(MAX(version), 0) AS current_version
            FROM schema_migrations
            """
        )

        if row is None:
            return 0

        return int(row["current_version"])

    def applied_migrations(self) -> list[sqlite3.Row]:
        """Return all applied migrations in version order."""
        self._ensure_migration_table()

        return self.database.fetch_all(
            """
            SELECT
                version,
                name,
                checksum,
                applied_at
            FROM schema_migrations
            ORDER BY version
            """
        )

    def _ensure_migration_table(self) -> None:
        """Create the migration history table when missing."""
        statement = """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TEXT NOT NULL
                DEFAULT (
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                )
        )
        """

        self.database.execute(statement)

    def _get_applied_versions(self) -> set[int]:
        """Return migration versions already recorded in the database."""
        rows = self.database.fetch_all(
            """
            SELECT version
            FROM schema_migrations
            ORDER BY version
            """
        )

        return {int(row["version"]) for row in rows}

    def _apply_migration(self, migration: Migration) -> None:
        """Apply one migration and record its checksum."""
        import hashlib

        try:
            sql = migration.path.read_text(encoding="utf-8")
        except OSError as exc:
            raise MigrationError(
                f"Could not read migration: {migration.path}"
            ) from exc

        checksum = hashlib.sha256(sql.encode("utf-8")).hexdigest()

        logger.info(
            "Applying database migration %s",
            migration.identifier,
        )

        connection = self.database.connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.executescript(sql)

            connection.execute(
                """
                INSERT INTO schema_migrations (
                    version,
                    name,
                    checksum
                )
                VALUES (?, ?, ?)
                """,
                (
                    migration.version,
                    migration.name,
                    checksum,
                ),
            )

            connection.commit()

        except sqlite3.Error as exc:
            connection.rollback()

            logger.exception(
                "Migration failed: %s",
                migration.identifier,
            )

            raise MigrationError(
                f"Migration failed: {migration.identifier}"
            ) from exc

        finally:
            connection.close()

        logger.info(
            "Migration completed: %s",
            migration.identifier,
        )

    def _resolve_migrations_directory(self) -> Path:
        """Resolve either a supplied or package-bundled migration directory."""
        if self.migrations_directory is not None:
            return self.migrations_directory.resolve()

        resource = files("memsentry.storage.schema").joinpath("migrations")

        with as_file(resource) as path:
            return Path(path)

    @staticmethod
    def _validate_sequence(migrations: list[Migration]) -> None:
        """Reject duplicate, zero, or unordered migration versions."""
        if not migrations:
            raise MigrationError("No database migrations were discovered.")

        previous_version = 0

        for migration in migrations:
            if migration.version <= 0:
                raise MigrationError(
                    "Migration versions must be positive integers."
                )

            if migration.version <= previous_version:
                raise MigrationError(
                    "Migration versions must be strictly increasing."
                )

            previous_version = migration.version
