from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from memsentry.storage.migrations import MigrationManager

logger = logging.getLogger(__name__)


class DatabaseError(RuntimeError):
    """Base exception for MemSentry database operations."""


class DatabaseConnectionError(DatabaseError):
    """Raised when a database connection cannot be opened."""


class DatabaseInitializationError(DatabaseError):
    """Raised when database initialization fails."""


class Database:
    """Manage SQLite connections and transactions for a MemSentry case."""

    def __init__(
        self,
        database_path: Path,
        *,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.database_path = database_path.resolve()
        self.timeout_seconds = timeout_seconds

    def initialize(self) -> None:
        """Create the database and apply all pending migrations."""
        try:
            self.database_path.parent.mkdir(parents=True, exist_ok=True)

            with self.connection() as connection:
                self._configure_database(connection)

            migration_manager = MigrationManager(self)
            migration_manager.apply_pending_migrations()

            logger.info(
                "Database initialized successfully: %s",
                self.database_path,
            )

        except (OSError, sqlite3.Error) as exc:
            logger.exception(
                "Failed to initialize database: %s",
                self.database_path,
            )
            raise DatabaseInitializationError(
                f"Could not initialize database: {self.database_path}"
            ) from exc

    def connect(self) -> sqlite3.Connection:
        """Open and configure a new SQLite connection."""
        try:
            connection = sqlite3.connect(
                self.database_path,
                timeout=self.timeout_seconds,
                isolation_level=None,
            )

            connection.row_factory = sqlite3.Row
            self._configure_connection(connection)

            return connection

        except sqlite3.Error as exc:
            logger.exception(
                "Failed to open database connection: %s",
                self.database_path,
            )
            raise DatabaseConnectionError(
                f"Could not connect to database: {self.database_path}"
            ) from exc

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Provide a database connection and always close it afterward."""
        connection = self.connect()

        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """
        Run database operations inside a transaction.

        The transaction is committed when the block succeeds and rolled
        back when an exception occurs.
        """
        connection = self.connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()

        except Exception:
            connection.rollback()
            logger.exception(
                "Database transaction rolled back: %s",
                self.database_path,
            )
            raise

        finally:
            connection.close()

    def execute(
        self,
        statement: str,
        parameters: tuple[Any, ...] | dict[str, Any] = (),
    ) -> int:
        """
        Execute a single write statement.

        Returns the number of affected rows.
        """
        with self.transaction() as connection:
            cursor = connection.execute(statement, parameters)
            return cursor.rowcount

    def execute_insert(
        self,
        statement: str,
        parameters: tuple[Any, ...] | dict[str, Any] = (),
    ) -> int:
        """
        Execute an INSERT statement.

        Returns SQLite's generated row identifier. This is mainly useful for
        tables using INTEGER PRIMARY KEY. MemSentry normally uses UUID strings.
        """
        with self.transaction() as connection:
            cursor = connection.execute(statement, parameters)

            if cursor.lastrowid is None:
                raise DatabaseError(
                    "Insert completed without producing a row identifier."
                )

            return int(cursor.lastrowid)

    def execute_many(
        self,
        statement: str,
        parameter_rows: list[tuple[Any, ...]],
    ) -> int:
        """Execute the same write statement for multiple parameter rows."""
        if not parameter_rows:
            return 0

        with self.transaction() as connection:
            cursor = connection.executemany(statement, parameter_rows)
            return cursor.rowcount

    def fetch_one(
        self,
        statement: str,
        parameters: tuple[Any, ...] | dict[str, Any] = (),
    ) -> sqlite3.Row | None:
        """Execute a query and return one row."""
        with self.connection() as connection:
            cursor = connection.execute(statement, parameters)
            return cursor.fetchone()

    def fetch_all(
        self,
        statement: str,
        parameters: tuple[Any, ...] | dict[str, Any] = (),
    ) -> list[sqlite3.Row]:
        """Execute a query and return all matching rows."""
        with self.connection() as connection:
            cursor = connection.execute(statement, parameters)
            return list(cursor.fetchall())

    def execute_script(self, script: str) -> None:
        """Execute a trusted SQL script inside a transaction."""
        connection = self.connect()

        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.executescript(script)
            connection.commit()

        except sqlite3.Error:
            connection.rollback()
            logger.exception(
                "Failed to execute SQL script against: %s",
                self.database_path,
            )
            raise

        finally:
            connection.close()

    def integrity_check(self) -> tuple[bool, str]:
        """Run SQLite's built-in integrity check."""
        row = self.fetch_one("PRAGMA integrity_check")

        if row is None:
            return False, "No integrity-check result was returned."

        result = str(row[0])
        return result.lower() == "ok", result

    def foreign_key_check(self) -> list[sqlite3.Row]:
        """Return any foreign-key violations."""
        return self.fetch_all("PRAGMA foreign_key_check")

    def vacuum(self) -> None:
        """
        Rebuild and compact the SQLite database.

        This should not be run while an analysis worker is actively writing.
        """
        with self.connection() as connection:
            connection.execute("VACUUM")

    def checkpoint_wal(self) -> None:
        """Flush the write-ahead log into the main database file."""
        with self.connection() as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    @staticmethod
    def _configure_connection(connection: sqlite3.Connection) -> None:
        """Apply connection-specific SQLite settings."""
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA temp_store = MEMORY")

    @staticmethod
    def _configure_database(connection: sqlite3.Connection) -> None:
        """Apply persistent database-level SQLite settings."""
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")


def create_case_database(database_path: Path) -> Database:
    """Create and initialize a MemSentry case database."""
    database = Database(database_path)
    database.initialize()
    return database
