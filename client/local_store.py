from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from shared.crypto_utils import decrypt_local_blob, encrypt_local_blob
from shared.utils import history_retention_boundary, isoformat_z, next_history_retention_cutoff, parse_datetime, utc_now

LOCAL_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS contact_state (
    username TEXT PRIMARY KEY,
    current_fingerprint TEXT,
    verified INTEGER NOT NULL DEFAULT 0,
    trust_state TEXT NOT NULL DEFAULT 'unverified' CHECK(trust_state IN ('unverified', 'verified', 'key_change_pending')),
    trust_reason TEXT NOT NULL DEFAULT '',
    key_change_detected_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contact_bundles (
    username TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    identity_public_key TEXT NOT NULL,
    chat_public_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    PRIMARY KEY (username, fingerprint)
);

CREATE TABLE IF NOT EXISTS messages (
    local_id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL UNIQUE,
    conversation_id TEXT NOT NULL,
    contact_username TEXT NOT NULL,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('in', 'out', 'system')),
    kind TEXT NOT NULL,
    counter INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    ttl_seconds INTEGER,
    sent_status TEXT NOT NULL DEFAULT 'Sent',
    delivered_at TEXT,
    unread INTEGER NOT NULL DEFAULT 0,
    ack_for TEXT,
    sender_key_fingerprint TEXT NOT NULL,
    receiver_key_fingerprint TEXT NOT NULL,
    local_nonce TEXT,
    local_ciphertext TEXT,
    last_error TEXT
);

CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(contact_username, local_id DESC);
CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages(contact_username, unread);

CREATE TABLE IF NOT EXISTS seen_envelopes (
    message_id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    counter INTEGER NOT NULL,
    kind TEXT NOT NULL,
    accepted_at TEXT NOT NULL,
    UNIQUE(sender, conversation_id, counter)
);

CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contact_username TEXT NOT NULL,
    event_type TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL,
    resolved INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class LocalStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, check_same_thread=False)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def initialize(self) -> None:
        with self.connect() as connection:
            connection.executescript(LOCAL_SCHEMA)
            contact_state_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(contact_state)").fetchall()
            }
            if "trust_reason" not in contact_state_columns:
                connection.execute("ALTER TABLE contact_state ADD COLUMN trust_reason TEXT NOT NULL DEFAULT ''")
            message_columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(messages)").fetchall()
            }
            if "delivered_at" not in message_columns:
                connection.execute("ALTER TABLE messages ADD COLUMN delivered_at TEXT")
            connection.commit()

    def refresh_current_bundle(self, username: str, bundle: dict[str, Any]) -> str:
        """Cache the currently active bundle.

        Returns one of: new_contact, unchanged, key_changed, updated_unverified.
        """
        now = isoformat_z(utc_now())
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO contact_bundles (
                    username, fingerprint, identity_public_key, chat_public_key,
                    signature, is_active, first_seen_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username, fingerprint)
                DO UPDATE SET
                    identity_public_key = excluded.identity_public_key,
                    chat_public_key = excluded.chat_public_key,
                    signature = excluded.signature,
                    is_active = excluded.is_active,
                    last_seen_at = excluded.last_seen_at
                """,
                (
                    username,
                    bundle["fingerprint"],
                    bundle["identity_public_key"],
                    bundle["chat_public_key"],
                    bundle["signature"],
                    1 if bundle.get("is_active", True) else 0,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                "SELECT * FROM contact_state WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO contact_state (
                        username, current_fingerprint, verified, trust_state, trust_reason,
                        key_change_detected_at, created_at, updated_at
                    ) VALUES (?, ?, 0, 'unverified', '', NULL, ?, ?)
                    """,
                    (username, bundle["fingerprint"], now, now),
                )
                connection.commit()
                return "new_contact"
            if row["current_fingerprint"] == bundle["fingerprint"]:
                connection.execute(
                    "UPDATE contact_state SET updated_at = ? WHERE username = ?",
                    (now, username),
                )
                connection.commit()
                return "unchanged"
            prior_trust_state = str(row["trust_state"] or "").strip().lower()
            prior_trust_reason = str(row["trust_reason"] or "").strip().lower()
            previously_trusted = bool(row["verified"]) and prior_trust_state == "verified"
            if previously_trusted or prior_trust_reason == "remote_key_change":
                connection.execute(
                    """
                    UPDATE contact_state
                    SET current_fingerprint = ?, verified = 0, trust_state = 'key_change_pending', trust_reason = 'remote_key_change',
                        key_change_detected_at = ?, updated_at = ?
                    WHERE username = ?
                    """,
                    (bundle["fingerprint"], now, now, username),
                )
                connection.commit()
                self.ensure_security_event(
                    username,
                    "key_change",
                    f"Contact {username} changed identity fingerprint to {bundle['fingerprint']}",
                )
                return "key_changed"
            connection.execute(
                """
                UPDATE contact_state
                SET current_fingerprint = ?, verified = 0, trust_state = 'unverified', trust_reason = '',
                    key_change_detected_at = NULL, updated_at = ?
                WHERE username = ?
                """,
                (bundle["fingerprint"], now, username),
            )
            connection.commit()
            return "updated_unverified"

    def cache_historical_bundle(self, username: str, bundle: dict[str, Any]) -> None:
        now = isoformat_z(utc_now())
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO contact_bundles (
                    username, fingerprint, identity_public_key, chat_public_key,
                    signature, is_active, first_seen_at, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username, fingerprint)
                DO UPDATE SET
                    identity_public_key = excluded.identity_public_key,
                    chat_public_key = excluded.chat_public_key,
                    signature = excluded.signature,
                    is_active = excluded.is_active,
                    last_seen_at = excluded.last_seen_at
                """,
                (
                    username,
                    bundle["fingerprint"],
                    bundle["identity_public_key"],
                    bundle["chat_public_key"],
                    bundle["signature"],
                    1 if bundle.get("is_active", True) else 0,
                    now,
                    now,
                ),
            )
            connection.commit()

    def get_cached_bundle(self, username: str, fingerprint: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM contact_bundles WHERE username = ? AND fingerprint = ?",
                (username, fingerprint),
            ).fetchone()
            return dict(row) if row else None

    def get_contact_state(self, username: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM contact_state WHERE username = ?", (username,)).fetchone()
            return dict(row) if row else None

    def mark_contact_verified(self, username: str) -> None:
        now = isoformat_z(utc_now())
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE contact_state
                SET verified = 1, trust_state = 'verified', trust_reason = '', key_change_detected_at = NULL, updated_at = ?
                WHERE username = ?
                """,
                (now, username),
            )
            connection.execute(
                """
                UPDATE security_events
                SET resolved = 1
                WHERE contact_username = ? AND resolved = 0 AND event_type IN ('verification_required', 'key_change')
                """,
                (username,),
            )
            connection.commit()

    def ensure_security_event(self, contact_username: str, event_type: str, detail: str) -> bool:
        normalized = str(contact_username or "").strip().lower()
        normalized_event_type = str(event_type or "").strip().lower()
        detail_text = str(detail or "").strip()
        if not normalized or not normalized_event_type or not detail_text:
            return False
        now = isoformat_z(utc_now())
        with self.connect() as connection:
            existing = connection.execute(
                """
                SELECT id, detail FROM security_events
                WHERE contact_username = ? AND event_type = ? AND resolved = 0
                ORDER BY created_at DESC, id DESC
                LIMIT 1
                """,
                (normalized, normalized_event_type),
            ).fetchone()
            if existing is not None:
                if str(existing["detail"] or "") != detail_text:
                    connection.execute(
                        "UPDATE security_events SET detail = ?, created_at = ? WHERE id = ?",
                        (detail_text, now, int(existing["id"])),
                    )
                    connection.commit()
                return False
            connection.execute(
                """
                INSERT INTO security_events (contact_username, event_type, detail, created_at, resolved)
                VALUES (?, ?, ?, ?, 0)
                """,
                (normalized, normalized_event_type, detail_text, now),
            )
            connection.commit()
            return True

    def resolve_security_events(self, contact_username: str, event_types: list[str] | tuple[str, ...] | set[str] | None = None) -> int:
        normalized = str(contact_username or "").strip().lower()
        if not normalized:
            return 0
        event_type_values = [str(value or "").strip().lower() for value in (event_types or []) if str(value or "").strip()]
        with self.connect() as connection:
            if event_type_values:
                placeholders = ", ".join("?" for _ in event_type_values)
                cursor = connection.execute(
                    f"UPDATE security_events SET resolved = 1 WHERE contact_username = ? AND resolved = 0 AND event_type IN ({placeholders})",
                    (normalized, *event_type_values),
                )
            else:
                cursor = connection.execute(
                    "UPDATE security_events SET resolved = 1 WHERE contact_username = ? AND resolved = 0",
                    (normalized,),
                )
            connection.commit()
            return int(cursor.rowcount or 0)

    def require_reverification(
        self,
        username: str,
        *,
        reason: str,
        detail: str,
        event_type: str,
        current_fingerprint: str | None = None,
    ) -> None:
        normalized = str(username or "").strip().lower()
        if not normalized:
            return
        normalized_reason = str(reason or "").strip().lower()
        now = isoformat_z(utc_now())
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM contact_state WHERE username = ?",
                (normalized,),
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO contact_state (
                        username, current_fingerprint, verified, trust_state, trust_reason,
                        key_change_detected_at, created_at, updated_at
                    ) VALUES (?, ?, 0, 'key_change_pending', ?, ?, ?, ?)
                    """,
                    (normalized, current_fingerprint, normalized_reason, now, now, now),
                )
            else:
                fingerprint_value = current_fingerprint if current_fingerprint is not None else row["current_fingerprint"]
                connection.execute(
                    """
                    UPDATE contact_state
                    SET current_fingerprint = ?, verified = 0, trust_state = 'key_change_pending',
                        trust_reason = ?, key_change_detected_at = ?, updated_at = ?
                    WHERE username = ?
                    """,
                    (fingerprint_value, normalized_reason, now, now, normalized),
                )
            connection.commit()
        self.ensure_security_event(normalized, event_type, detail)

    def record_seen_envelope(self, message_id: str, sender: str, conversation_id: str, counter: int, kind: str) -> bool:
        now = isoformat_z(utc_now())
        with self.connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO seen_envelopes (message_id, sender, conversation_id, counter, kind, accepted_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (message_id, sender, conversation_id, counter, kind, now),
                )
                connection.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def _store_message(
        self,
        storage_key: bytes,
        message_id: str,
        conversation_id: str,
        contact_username: str,
        sender: str,
        receiver: str,
        direction: str,
        kind: str,
        counter: int,
        created_at: str,
        expires_at: str | None,
        ttl_seconds: int | None,
        sender_key_fingerprint: str,
        receiver_key_fingerprint: str,
        plaintext_payload: dict[str, Any],
        sent_status: str,
        delivered_at: str | None,
        unread: int,
        ack_for: str | None = None,
        last_error: str | None = None,
    ) -> None:
        aad = message_id.encode("utf-8")
        nonce, ciphertext = encrypt_local_blob(storage_key, plaintext_payload, aad)
        with self.connect() as connection:
            connection.execute(
                """
                INSERT OR REPLACE INTO messages (
                    message_id, conversation_id, contact_username, sender, receiver,
                    direction, kind, counter, created_at, expires_at, ttl_seconds,
                    sent_status, delivered_at, unread, ack_for, sender_key_fingerprint,
                    receiver_key_fingerprint, local_nonce, local_ciphertext, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    conversation_id,
                    contact_username,
                    sender,
                    receiver,
                    direction,
                    kind,
                    counter,
                    created_at,
                    expires_at,
                    ttl_seconds,
                    sent_status,
                    delivered_at,
                    unread,
                    ack_for,
                    sender_key_fingerprint,
                    receiver_key_fingerprint,
                    nonce,
                    ciphertext,
                    last_error,
                ),
            )
            connection.commit()

    def store_outgoing_chat(
        self,
        storage_key: bytes,
        *,
        message_id: str,
        conversation_id: str,
        contact_username: str,
        sender: str,
        receiver: str,
        counter: int,
        created_at: str,
        expires_at: str | None,
        ttl_seconds: int | None,
        sender_key_fingerprint: str,
        receiver_key_fingerprint: str,
        plaintext_payload: dict[str, Any],
    ) -> None:
        self._store_message(
            storage_key,
            message_id=message_id,
            conversation_id=conversation_id,
            contact_username=contact_username,
            sender=sender,
            receiver=receiver,
            direction="out",
            kind="chat",
            counter=counter,
            created_at=created_at,
            expires_at=expires_at,
            ttl_seconds=ttl_seconds,
            sender_key_fingerprint=sender_key_fingerprint,
            receiver_key_fingerprint=receiver_key_fingerprint,
            plaintext_payload=plaintext_payload,
            sent_status="Sent",
            delivered_at=None,
            unread=0,
        )

    def store_incoming_chat(
        self,
        storage_key: bytes,
        *,
        message_id: str,
        conversation_id: str,
        contact_username: str,
        sender: str,
        receiver: str,
        counter: int,
        created_at: str,
        expires_at: str | None,
        ttl_seconds: int | None,
        sender_key_fingerprint: str,
        receiver_key_fingerprint: str,
        plaintext_payload: dict[str, Any],
        mark_read: bool = False,
    ) -> None:
        self._store_message(
            storage_key,
            message_id=message_id,
            conversation_id=conversation_id,
            contact_username=contact_username,
            sender=sender,
            receiver=receiver,
            direction="in",
            kind="chat",
            counter=counter,
            created_at=created_at,
            expires_at=expires_at,
            ttl_seconds=ttl_seconds,
            sender_key_fingerprint=sender_key_fingerprint,
            receiver_key_fingerprint=receiver_key_fingerprint,
            plaintext_payload=plaintext_payload,
            sent_status="Received",
            delivered_at=None,
            unread=0 if mark_read else 1,
        )

    def mark_message_delivered(self, related_message_id: str, delivered_at: str | None = None) -> bool:
        effective_delivered_at = delivered_at
        with self.connect() as connection:
            if effective_delivered_at:
                row = connection.execute(
                    "SELECT created_at FROM messages WHERE message_id = ? AND direction = 'out'",
                    (related_message_id,),
                ).fetchone()
                created_at = row["created_at"] if row else None
                created_dt = parse_datetime(created_at)
                delivered_dt = parse_datetime(effective_delivered_at)
                if created_dt is not None and delivered_dt is not None and delivered_dt < created_dt:
                    effective_delivered_at = created_at
            result = connection.execute(
                """
                UPDATE messages
                SET sent_status = 'Delivered',
                    delivered_at = COALESCE(delivered_at, ?)
                WHERE message_id = ? AND direction = 'out'
                """,
                (effective_delivered_at, related_message_id),
            )
            connection.commit()
            return result.rowcount > 0

    def mark_incoming_message_delivered(self, message_id: str) -> bool:
        with self.connect() as connection:
            result = connection.execute(
                "UPDATE messages SET sent_status = 'Delivered' WHERE message_id = ? AND direction = 'in'",
                (message_id,),
            )
            connection.commit()
            return result.rowcount > 0

    def pending_delivery_receipts(self, contact_username: str | None = None) -> list[dict[str, Any]]:
        params: list[Any] = []
        contact_clause = ""
        now = isoformat_z(utc_now())
        if contact_username is not None:
            contact_clause = " AND contact_username = ?"
            params.append(contact_username)
        with self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT message_id, conversation_id, contact_username, sender, receiver,
                       sender_key_fingerprint, receiver_key_fingerprint, counter, created_at,
                       expires_at, ttl_seconds, sent_status, unread
                FROM messages
                WHERE direction = 'in'
                  AND kind = 'chat'
                  AND unread = 0
                  AND sent_status != 'Delivered'
                  AND (expires_at IS NULL OR expires_at > ?)
                  {contact_clause}
                ORDER BY local_id ASC
                """,
                (now, *tuple(params)),
            ).fetchall()
            return [dict(row) for row in rows]

    def mark_conversation_read(self, contact_username: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "UPDATE messages SET unread = 0 WHERE contact_username = ? AND direction = 'in' AND unread = 1",
                (contact_username,),
            )
            connection.commit()

    def has_messages_for_contact(self, contact_username: str) -> bool:
        normalized = str(contact_username or "").strip().lower()
        if not normalized:
            return False
        with self.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM messages WHERE contact_username = ? LIMIT 1",
                (normalized,),
            ).fetchone()
            return row is not None

    def has_initial_note_message(self, contact_username: str) -> bool:
        normalized = str(contact_username or "").strip().lower()
        if not normalized:
            return False
        with self.connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM messages WHERE contact_username = ? AND kind = 'initial_note' LIMIT 1",
                (normalized,),
            ).fetchone()
            return row is not None

    def ensure_initial_note_message(
        self,
        storage_key: bytes,
        *,
        conversation_id: str,
        contact_username: str,
        sender: str,
        receiver: str,
        direction: str,
        created_at: str,
        note: str,
    ) -> bool:
        normalized_contact = str(contact_username or "").strip().lower()
        note_text = str(note or "").strip()
        if not normalized_contact or not note_text:
            return False
        created_value = str(created_at or isoformat_z(utc_now()))
        message_id = f"initial-note:{conversation_id}:{created_value}"
        aad = message_id.encode("utf-8")
        nonce, ciphertext = encrypt_local_blob(storage_key, {"text": note_text}, aad)
        with self.connect() as connection:
            result = connection.execute(
                """
                INSERT OR IGNORE INTO messages (
                    message_id, conversation_id, contact_username, sender, receiver,
                    direction, kind, counter, created_at, expires_at, ttl_seconds,
                    sent_status, delivered_at, unread, ack_for, sender_key_fingerprint,
                    receiver_key_fingerprint, local_nonce, local_ciphertext, last_error
                ) VALUES (?, ?, ?, ?, ?, ?, 'initial_note', 0, ?, NULL, NULL, '', NULL, 0, NULL, '', '', ?, ?, NULL)
                """,
                (
                    message_id,
                    conversation_id,
                    normalized_contact,
                    sender,
                    receiver,
                    direction,
                    created_value,
                    nonce,
                    ciphertext,
                ),
            )
            connection.commit()
            return result.rowcount > 0

    def list_conversations(self) -> list[dict[str, Any]]:
        now = isoformat_z(utc_now())
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT m.contact_username,
                       MAX(m.created_at) AS last_activity_at,
                       SUM(CASE WHEN m.unread = 1 AND (m.expires_at IS NULL OR m.expires_at > ?) THEN 1 ELSE 0 END) AS unread_count,
                       MAX(m.local_id) AS last_local_id
                FROM messages m
                GROUP BY m.contact_username
                ORDER BY last_activity_at DESC
                """,
                (now,),
            ).fetchall()
            return [dict(row) for row in rows]

    def load_history(
        self,
        storage_key: bytes,
        contact_username: str,
        limit: int = 20,
        before_local_id: int | None = None,
        *,
        include_unread: bool = True,
    ) -> tuple[list[dict[str, Any]], int | None]:
        params: list[Any] = [contact_username]
        before_clause = ""
        if before_local_id is not None:
            before_clause = " AND local_id < ?"
            params.append(before_local_id)
        unread_clause = ""
        if not include_unread:
            unread_clause = " AND (direction != 'in' OR unread = 0)"
        params.append(limit)
        with self.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT * FROM messages
                WHERE contact_username = ?
                  AND kind IN ('chat', 'initial_note')
                  {before_clause}
                  {unread_clause}
                ORDER BY local_id DESC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
        history: list[dict[str, Any]] = []
        next_before = None
        for row in rows:
            if row["local_nonce"] is None or row["local_ciphertext"] is None:
                payload = {}
            else:
                payload = decrypt_local_blob(storage_key, row["local_nonce"], row["local_ciphertext"], row["message_id"].encode("utf-8"))
            history.append({**dict(row), "payload": payload})
            next_before = int(row["local_id"])
        history.reverse()
        return history, next_before

    def purge_expired_messages(self) -> int:
        retention_boundary = isoformat_z(history_retention_boundary(now=utc_now()))
        with self.connect() as connection:
            deleted_messages = connection.execute(
                "DELETE FROM messages WHERE created_at < ?",
                (retention_boundary,),
            )
            connection.execute(
                "DELETE FROM seen_envelopes WHERE accepted_at < ?",
                (retention_boundary,),
            )
            connection.commit()
            return int(deleted_messages.rowcount or 0)

    def retention_boundary_at(self) -> str:
        return isoformat_z(history_retention_boundary(now=utc_now()))

    def next_retention_cutoff_at(self, contact_username: str | None = None) -> str | None:
        params: list[Any] = []
        contact_clause = ""
        if contact_username is not None:
            contact_clause = "WHERE contact_username = ?"
            params.append(contact_username)
        with self.connect() as connection:
            row = connection.execute(
                f"""
                SELECT 1
                FROM messages
                {contact_clause}
                LIMIT 1
                """,
                tuple(params),
            ).fetchone()
            if row is None:
                return None
        return isoformat_z(next_history_retention_cutoff(now=utc_now()))

    def next_expiry_at(self, contact_username: str | None = None) -> str | None:
        now = isoformat_z(utc_now())
        params: list[Any] = [now]
        contact_clause = ""
        if contact_username is not None:
            contact_clause = " AND contact_username = ?"
            params.append(contact_username)
        with self.connect() as connection:
            row = connection.execute(
                f"""
                SELECT MIN(expires_at) AS next_expiry_at
                FROM messages
                WHERE kind = 'chat'
                  AND expires_at IS NOT NULL
                  AND expires_at > ?
                  {contact_clause}
                """,
                tuple(params),
            ).fetchone()
            if row is None:
                return None
            value = row["next_expiry_at"]
            return str(value) if value else None

    def get_and_increment_counter(self, conversation_id: str) -> int:
        key = f"send_counter:{conversation_id}"
        with self.connect() as connection:
            row = connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            current = int(row["value"]) if row else 0
            next_value = current + 1
            connection.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, str(next_value)),
            )
            connection.commit()
            return next_value

    def unresolved_security_events(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM security_events WHERE resolved = 0 ORDER BY created_at DESC"
            ).fetchall()
            return [dict(row) for row in rows]

    def friendship_artifact_contacts(self) -> set[str]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT contact_username AS username FROM messages
                UNION
                SELECT DISTINCT contact_username AS username FROM security_events
                """
            ).fetchall()
            return {str(row["username"]).strip().lower() for row in rows if row["username"]}

    def verified_contacts(self) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT username, current_fingerprint, trust_state, trust_reason, verified
                FROM contact_state
                WHERE trust_state = 'verified' AND verified = 1
                ORDER BY username ASC
                """
            ).fetchall()
            return [dict(row) for row in rows]

    def clear_friendship_state(self, contact_username: str, *, conversation_id: str | None = None) -> None:
        normalized = str(contact_username or "").strip().lower()
        if not normalized:
            return
        with self.connect() as connection:
            connection.execute("DELETE FROM messages WHERE contact_username = ?", (normalized,))
            connection.execute("DELETE FROM security_events WHERE contact_username = ?", (normalized,))
            connection.execute("DELETE FROM contact_state WHERE username = ?", (normalized,))
            connection.execute("DELETE FROM contact_bundles WHERE username = ?", (normalized,))
            if conversation_id:
                connection.execute("DELETE FROM seen_envelopes WHERE conversation_id = ?", (conversation_id,))
            connection.commit()
