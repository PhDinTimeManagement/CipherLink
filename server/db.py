from __future__ import annotations

import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator


logger = logging.getLogger("cipherlink_server.db")


class Database:
    def __init__(self, db_path: Path, schema_path: Path):
        self.db_path = db_path
        self.schema_path = schema_path

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        schema_sql = self.schema_path.read_text(encoding="utf-8")
        with self.connect() as connection:
            if self._has_user_tables(connection):
                self._apply_compatibility_migrations(connection)
            connection.executescript(schema_sql)
            connection.commit()

    def _has_user_tables(self, connection: sqlite3.Connection) -> bool:
        row = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' LIMIT 1"
        ).fetchone()
        return row is not None

    def _table_exists(self, connection: sqlite3.Connection, table_name: str) -> bool:
        row = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        ).fetchone()
        return row is not None

    def _column_names(self, connection: sqlite3.Connection, table_name: str) -> set[str]:
        if not self._table_exists(connection, table_name):
            return set()
        rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {str(row["name"]) for row in rows}

    def _ensure_column(self, connection: sqlite3.Connection, table_name: str, column_name: str, declaration: str) -> bool:
        if not self._table_exists(connection, table_name):
            return False
        columns = self._column_names(connection, table_name)
        if column_name in columns:
            return False
        connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {declaration}")
        logger.info("Applied compatibility migration: added %s.%s", table_name, column_name)
        return True

    @staticmethod
    def _utc_now_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def _apply_compatibility_migrations(self, connection: sqlite3.Connection) -> None:
        now = self._utc_now_iso()

        # users
        self._ensure_column(connection, "users", "active_key_fingerprint", "TEXT")
        self._ensure_column(connection, "users", "updated_at", "TEXT")
        self._ensure_column(connection, "users", "is_active", "INTEGER")
        user_columns = self._column_names(connection, "users")
        if user_columns:
            if "updated_at" in user_columns:
                if "created_at" in user_columns:
                    connection.execute(
                        "UPDATE users SET updated_at = COALESCE(NULLIF(updated_at, ''), created_at, ?) WHERE updated_at IS NULL OR updated_at = ''",
                        (now,),
                    )
                else:
                    connection.execute(
                        "UPDATE users SET updated_at = ? WHERE updated_at IS NULL OR updated_at = ''",
                        (now,),
                    )
            if "is_active" in user_columns:
                connection.execute("UPDATE users SET is_active = 1 WHERE is_active IS NULL")

        # key_bundles
        self._ensure_column(connection, "key_bundles", "is_active", "INTEGER")
        self._ensure_column(connection, "key_bundles", "created_at", "TEXT")
        self._ensure_column(connection, "key_bundles", "revoked_at", "TEXT")
        key_bundle_columns = self._column_names(connection, "key_bundles")
        if key_bundle_columns:
            if "is_active" in key_bundle_columns:
                connection.execute("UPDATE key_bundles SET is_active = 1 WHERE is_active IS NULL")
            if "created_at" in key_bundle_columns:
                connection.execute(
                    "UPDATE key_bundles SET created_at = ? WHERE created_at IS NULL OR created_at = ''",
                    (now,),
                )
        if user_columns and key_bundle_columns and {"active_key_fingerprint", "id"}.issubset(user_columns) and {
            "user_id",
            "fingerprint",
        }.issubset(key_bundle_columns):
            if "is_active" in key_bundle_columns:
                connection.execute(
                    """
                    UPDATE users
                    SET active_key_fingerprint = COALESCE(
                        active_key_fingerprint,
                        (
                            SELECT kb.fingerprint
                            FROM key_bundles kb
                            WHERE kb.user_id = users.id AND kb.is_active = 1
                            ORDER BY kb.id DESC
                            LIMIT 1
                        )
                    )
                    WHERE active_key_fingerprint IS NULL
                    """
                )
            else:
                connection.execute(
                    """
                    UPDATE users
                    SET active_key_fingerprint = COALESCE(
                        active_key_fingerprint,
                        (
                            SELECT kb.fingerprint
                            FROM key_bundles kb
                            WHERE kb.user_id = users.id
                            ORDER BY kb.id DESC
                            LIMIT 1
                        )
                    )
                    WHERE active_key_fingerprint IS NULL
                    """
                )

        # sessions
        self._ensure_column(connection, "sessions", "last_seen_at", "TEXT")
        session_columns = self._column_names(connection, "sessions")
        if session_columns and "last_seen_at" in session_columns:
            if "created_at" in session_columns:
                connection.execute(
                    "UPDATE sessions SET last_seen_at = COALESCE(NULLIF(last_seen_at, ''), created_at, ?) WHERE last_seen_at IS NULL OR last_seen_at = ''",
                    (now,),
                )
            else:
                connection.execute(
                    "UPDATE sessions SET last_seen_at = ? WHERE last_seen_at IS NULL OR last_seen_at = ''",
                    (now,),
                )

        # friend_requests
        self._ensure_column(connection, "friend_requests", "status", "TEXT")
        self._ensure_column(connection, "friend_requests", "note", "TEXT")
        self._ensure_column(connection, "friend_requests", "updated_at", "TEXT")
        friend_request_columns = self._column_names(connection, "friend_requests")
        if friend_request_columns:
            if "status" in friend_request_columns:
                connection.execute(
                    "UPDATE friend_requests SET status = 'pending' WHERE status IS NULL OR status = ''"
                )
            if "updated_at" in friend_request_columns:
                if "created_at" in friend_request_columns:
                    connection.execute(
                        "UPDATE friend_requests SET updated_at = COALESCE(NULLIF(updated_at, ''), created_at, ?) WHERE updated_at IS NULL OR updated_at = ''",
                        (now,),
                    )
                else:
                    connection.execute(
                        "UPDATE friend_requests SET updated_at = ? WHERE updated_at IS NULL OR updated_at = ''",
                        (now,),
                    )

        # friendships
        self._ensure_column(connection, "friendships", "status", "TEXT")
        self._ensure_column(connection, "friendships", "updated_at", "TEXT")
        friendship_columns = self._column_names(connection, "friendships")
        if friendship_columns:
            if "status" in friendship_columns:
                connection.execute(
                    "UPDATE friendships SET status = 'accepted' WHERE status IS NULL OR status = ''"
                )
            if "updated_at" in friendship_columns:
                if "created_at" in friendship_columns:
                    connection.execute(
                        "UPDATE friendships SET updated_at = COALESCE(NULLIF(updated_at, ''), created_at, ?) WHERE updated_at IS NULL OR updated_at = ''",
                        (now,),
                    )
                else:
                    connection.execute(
                        "UPDATE friendships SET updated_at = ? WHERE updated_at IS NULL OR updated_at = ''",
                        (now,),
                    )

        # blocks
        self._ensure_column(connection, "blocks", "created_at", "TEXT")
        block_columns = self._column_names(connection, "blocks")
        if block_columns and "created_at" in block_columns:
            connection.execute(
                "UPDATE blocks SET created_at = ? WHERE created_at IS NULL OR created_at = ''",
                (now,),
            )

        # messages
        self._ensure_column(connection, "messages", "payload_version", "INTEGER")
        self._ensure_column(connection, "messages", "counter", "INTEGER")
        self._ensure_column(connection, "messages", "ttl_seconds", "INTEGER")
        self._ensure_column(connection, "messages", "sender_key_fingerprint", "TEXT")
        self._ensure_column(connection, "messages", "receiver_key_fingerprint", "TEXT")
        self._ensure_column(connection, "messages", "related_message_id", "TEXT")
        self._ensure_column(connection, "messages", "expires_at", "TEXT")
        self._ensure_column(connection, "messages", "canonical_expires_at", "TEXT")
        self._ensure_column(connection, "messages", "submitted_at", "TEXT")
        self._ensure_column(connection, "messages", "consumed_at", "TEXT")
        self._ensure_column(connection, "messages", "delivered_at", "TEXT")
        self._ensure_column(connection, "messages", "deleted_at", "TEXT")
        self._ensure_column(connection, "messages", "last_pushed_at", "TEXT")
        self._ensure_column(connection, "messages", "size_bytes", "INTEGER")
        message_columns = self._column_names(connection, "messages")
        if message_columns:
            if "payload_version" in message_columns:
                connection.execute(
                    "UPDATE messages SET payload_version = 1 WHERE payload_version IS NULL OR payload_version = 0"
                )
            if "counter" in message_columns:
                if "id" in message_columns:
                    connection.execute(
                        "UPDATE messages SET counter = COALESCE(counter, id, 1) WHERE counter IS NULL"
                    )
                else:
                    connection.execute("UPDATE messages SET counter = 1 WHERE counter IS NULL")
            if "submitted_at" in message_columns:
                if "created_at" in message_columns:
                    connection.execute(
                        "UPDATE messages SET submitted_at = COALESCE(NULLIF(submitted_at, ''), created_at, ?) WHERE submitted_at IS NULL OR submitted_at = ''",
                        (now,),
                    )
                else:
                    connection.execute(
                        "UPDATE messages SET submitted_at = ? WHERE submitted_at IS NULL OR submitted_at = ''",
                        (now,),
                    )
            if "canonical_expires_at" in message_columns and {"submitted_at", "ttl_seconds"}.issubset(message_columns):
                rows = connection.execute(
                    "SELECT rowid, submitted_at, ttl_seconds FROM messages WHERE ttl_seconds IS NOT NULL AND (canonical_expires_at IS NULL OR canonical_expires_at = '')"
                ).fetchall()
                for row in rows:
                    submitted_at = row["submitted_at"]
                    ttl_seconds = row["ttl_seconds"]
                    if not submitted_at or ttl_seconds is None:
                        continue
                    try:
                        submitted_dt = datetime.fromisoformat(str(submitted_at).replace("Z", "+00:00")).astimezone(timezone.utc)
                        canonical_expires_at = (submitted_dt + timedelta(seconds=int(ttl_seconds))).replace(microsecond=0).isoformat().replace("+00:00", "Z")
                    except Exception:
                        continue
                    connection.execute(
                        "UPDATE messages SET canonical_expires_at = ? WHERE rowid = ?",
                        (canonical_expires_at, row["rowid"]),
                    )
            if "size_bytes" in message_columns:
                if {"ciphertext", "nonce"}.issubset(message_columns):
                    connection.execute(
                        "UPDATE messages SET size_bytes = COALESCE(size_bytes, length(COALESCE(ciphertext, '')) + length(COALESCE(nonce, ''))) WHERE size_bytes IS NULL"
                    )
                else:
                    connection.execute("UPDATE messages SET size_bytes = 0 WHERE size_bytes IS NULL")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
