from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)


class DatabaseError(RuntimeError):
    """Base exception for MemSentry database operations."""


class DatabaseConnectionError(DatabaseError):
    """Raised when a database connection cannot be opened."""


class Database:
    """Manage connections to the MemSentry SQLite database."""

    def __init__(
        self,
        database_path: Path,
        *,
        timeout_seconds: float = 30.0,
    ) -> None:
        self.database_path = database_path.expanduser().resolve()
        self.timeout_seconds = timeout_seconds

    def initialize(self) -> None:
        """Create the database and apply pending migrations."""

        self.database_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self.connection():
            pass

        from memsentry.storage.migrations import MigrationManager

        migration_manager = MigrationManager(self)
        migration_manager.apply_pending_migrations()

        logger.info(
            "Database initialized: %s",
            self.database_path,
        )

    def connect(self) -> sqlite3.Connection:
        """Open and configure a SQLite connection."""

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
                "Failed to connect to database: %s",
                self.database_path,
            )

            raise DatabaseConnectionError(
                f"Could not connect to database: "
                f"{self.database_path}"
            ) from exc

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Provide a connection and always close it afterward."""

        connection = self.connect()

        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """
        Run database operations inside one transaction.

        Commit when successful.
        Roll back if an exception occurs.
        """

        connection = self.connect()

        try:
            connection.execute("BEGIN")

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

    @staticmethod
    def _configure_connection(
        connection: sqlite3.Connection,
    ) -> None:
        """Apply settings required for every SQLite connection."""

        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
