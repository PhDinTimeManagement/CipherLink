from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from shared.protocol import FriendRequestRecord, PublicKeyBundle
from shared.utils import isoformat_z, parse_datetime, utc_now

from server.db import Database


@dataclass(slots=True)
class AuthenticatedUser:
    id: int
    username: str
    active_key_fingerprint: str
    session_token_hash: str | None = None
    session_expires_at: str | None = None


class RepositoryError(Exception):
    pass


class DuplicateError(RepositoryError):
    pass


class NotFoundError(RepositoryError):
    pass


class UnauthorizedError(RepositoryError):
    pass


class ConflictError(RepositoryError):
    pass


class Repository:
    def __init__(self, db: Database):
        self.db = db

    @staticmethod
    def normalize_username(username: str) -> str:
        return username.strip().lower()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return dict(row) if row is not None else None

    @staticmethod
    def ordered_pair(user_a: int, user_b: int) -> tuple[int, int]:
        return (user_a, user_b) if user_a < user_b else (user_b, user_a)

    def create_user(
        self,
        username: str,
        password_hash: str,
        otp_secret_ciphertext: str,
        otp_secret_nonce: str,
        bundle: PublicKeyBundle,
    ) -> dict[str, Any]:
        username = self.normalize_username(username)
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            existing = connection.execute(
                "SELECT id FROM users WHERE lower(username) = lower(?)",
                (username,),
            ).fetchone()
            if existing is not None:
                raise DuplicateError("Username is already registered.")
            cursor = connection.execute(
                """
                INSERT INTO users (
                    username, password_hash, otp_secret_ciphertext, otp_secret_nonce,
                    otp_confirmed, active_key_fingerprint, created_at, updated_at, is_active
                ) VALUES (?, ?, ?, ?, 0, ?, ?, ?, 1)
                """,
                (
                    username,
                    password_hash,
                    otp_secret_ciphertext,
                    otp_secret_nonce,
                    bundle.fingerprint,
                    now,
                    now,
                ),
            )
            user_id = int(cursor.lastrowid)
            connection.execute(
                """
                INSERT INTO key_bundles (
                    user_id, fingerprint, identity_public_key, chat_public_key,
                    signature, is_active, created_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, 1, ?, NULL)
                """,
                (
                    user_id,
                    bundle.fingerprint,
                    bundle.identity_public_key,
                    bundle.chat_public_key,
                    bundle.signature,
                    now,
                ),
            )
            return {
                "id": user_id,
                "username": username,
                "active_key_fingerprint": bundle.fingerprint,
                "created_at": now,
            }

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        username = self.normalize_username(username)
        with self.db.connect() as connection:
            row = connection.execute(
                "SELECT * FROM users WHERE lower(username) = lower(?)",
                (username,),
            ).fetchone()
            return self._row_to_dict(row)

    def get_contact_by_username(self, user_id: int, username: str) -> dict[str, Any] | None:
        username = self.normalize_username(username)
        with self.db.connect() as connection:
            candidate = connection.execute(
                "SELECT * FROM users WHERE lower(username) = lower(?)",
                (username,),
            ).fetchone()
            if candidate is None:
                return None

            other_id = int(candidate["id"])
            if other_id == user_id:
                return None

            friendship_row = self._friendship_row(connection, user_id, other_id)
            if friendship_row is None or str(friendship_row["status"] or "").strip().lower() != "accepted":
                return None

            return self._row_to_dict(candidate)

    def get_user_by_id(self, user_id: int) -> dict[str, Any] | None:
        with self.db.connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            return self._row_to_dict(row)

    def mark_otp_confirmed(self, user_id: int) -> None:
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            connection.execute(
                "UPDATE users SET otp_confirmed = 1, updated_at = ? WHERE id = ?",
                (now, user_id),
            )

    def create_session(self, user_id: int, token_hash: str, expires_at: str) -> None:
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            connection.execute(
                """
                INSERT INTO sessions (user_id, token_hash, created_at, expires_at, revoked_at, last_seen_at)
                VALUES (?, ?, ?, ?, NULL, ?)
                """,
                (user_id, token_hash, now, expires_at, now),
            )

    def get_user_for_token(self, token_hash: str) -> AuthenticatedUser | None:
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            row = connection.execute(
                """
                SELECT u.id AS user_id, u.username, u.active_key_fingerprint,
                       s.token_hash, s.expires_at, s.revoked_at
                FROM sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.token_hash = ? AND s.revoked_at IS NULL
                  AND s.expires_at > ?
                  AND u.is_active = 1
                """,
                (token_hash, now),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
                (now, token_hash),
            )
            return AuthenticatedUser(
                id=int(row["user_id"]),
                username=row["username"],
                active_key_fingerprint=row["active_key_fingerprint"],
                session_token_hash=row["token_hash"],
                session_expires_at=row["expires_at"],
            )

    def revoke_session(self, token_hash: str) -> None:
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            connection.execute(
                "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                (now, token_hash),
            )

    def add_key_bundle(self, user_id: int, bundle: PublicKeyBundle) -> None:
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            connection.execute(
                "UPDATE key_bundles SET is_active = 0, revoked_at = ? WHERE user_id = ? AND is_active = 1",
                (now, user_id),
            )
            connection.execute(
                """
                INSERT INTO key_bundles (
                    user_id, fingerprint, identity_public_key, chat_public_key, signature,
                    is_active, created_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, 1, ?, NULL)
                """,
                (
                    user_id,
                    bundle.fingerprint,
                    bundle.identity_public_key,
                    bundle.chat_public_key,
                    bundle.signature,
                    now,
                ),
            )
            connection.execute(
                "UPDATE users SET active_key_fingerprint = ?, updated_at = ? WHERE id = ?",
                (bundle.fingerprint, now, user_id),
            )

    def get_active_bundle(self, username: str) -> dict[str, Any] | None:
        username = self.normalize_username(username)
        with self.db.connect() as connection:
            row = connection.execute(
                """
                SELECT u.username, kb.fingerprint, kb.identity_public_key, kb.chat_public_key,
                       kb.signature, kb.created_at, kb.is_active
                FROM users u
                JOIN key_bundles kb ON kb.user_id = u.id AND kb.is_active = 1
                WHERE lower(u.username) = lower(?)
                """,
                (username,),
            ).fetchone()
            return self._row_to_dict(row)

    def get_bundle_by_fingerprint(self, username: str, fingerprint: str) -> dict[str, Any] | None:
        username = self.normalize_username(username)
        with self.db.connect() as connection:
            row = connection.execute(
                """
                SELECT u.username, kb.fingerprint, kb.identity_public_key, kb.chat_public_key,
                       kb.signature, kb.created_at, kb.is_active
                FROM users u
                JOIN key_bundles kb ON kb.user_id = u.id
                WHERE lower(u.username) = lower(?) AND kb.fingerprint = ?
                """,
                (username, fingerprint),
            ).fetchone()
            return self._row_to_dict(row)

    def _friendship_row(self, connection: sqlite3.Connection, user_a: int, user_b: int) -> sqlite3.Row | None:
        low, high = self.ordered_pair(user_a, user_b)
        return connection.execute(
            "SELECT * FROM friendships WHERE user_low_id = ? AND user_high_id = ?",
            (low, high),
        ).fetchone()

    def block_relationship(self, user_a: int, user_b: int) -> dict[str, bool]:
        with self.db.connect() as connection:
            row = connection.execute(
                """
                SELECT
                    EXISTS(
                        SELECT 1 FROM blocks WHERE blocker_id = ? AND blocked_id = ?
                    ) AS user_a_blocked_user_b,
                    EXISTS(
                        SELECT 1 FROM blocks WHERE blocker_id = ? AND blocked_id = ?
                    ) AS user_b_blocked_user_a
                """,
                (user_a, user_b, user_b, user_a),
            ).fetchone()
            assert row is not None
            return {
                "user_a_blocked_user_b": bool(row["user_a_blocked_user_b"]),
                "user_b_blocked_user_a": bool(row["user_b_blocked_user_a"]),
            }

    def is_blocked(self, user_a: int, user_b: int) -> bool:
        relationship = self.block_relationship(user_a, user_b)
        return relationship["user_a_blocked_user_b"] or relationship["user_b_blocked_user_a"]

    def are_friends(self, user_a: int, user_b: int) -> bool:
        with self.db.connect() as connection:
            row = self._friendship_row(connection, user_a, user_b)
            return row is not None and row["status"] == "accepted"

    def create_friend_request(self, sender_id: int, receiver_id: int, note: str | None = None) -> dict[str, Any]:
        if sender_id == receiver_id:
            raise ConflictError("You cannot friend yourself.")
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            if self.is_blocked(sender_id, receiver_id):
                raise UnauthorizedError("Cannot send friend request because one user has blocked the other.")
            if self._friendship_row(connection, sender_id, receiver_id) is not None:
                existing = self._friendship_row(connection, sender_id, receiver_id)
                if existing and existing["status"] == "accepted":
                    raise ConflictError("Users are already friends.")
            reverse_pending = connection.execute(
                "SELECT id FROM friend_requests WHERE sender_id = ? AND receiver_id = ? AND status = 'pending'",
                (receiver_id, sender_id),
            ).fetchone()
            if reverse_pending is not None:
                raise ConflictError("The target user has already sent you a friend request. Accept that request instead.")
            try:
                cursor = connection.execute(
                    """
                    INSERT INTO friend_requests (sender_id, receiver_id, status, note, created_at, updated_at)
                    VALUES (?, ?, 'pending', ?, ?, ?)
                    """,
                    (sender_id, receiver_id, note, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("A pending friend request already exists.") from exc
            row = connection.execute(
                """
                SELECT fr.id, su.username AS sender_username, ru.username AS receiver_username,
                       fr.status, fr.note, fr.created_at, fr.updated_at
                FROM friend_requests fr
                JOIN users su ON su.id = fr.sender_id
                JOIN users ru ON ru.id = fr.receiver_id
                WHERE fr.id = ?
                """,
                (cursor.lastrowid,),
            ).fetchone()
            return dict(row)

    def list_friend_requests(self, user_id: int) -> dict[str, list[dict[str, Any]]]:
        with self.db.connect() as connection:
            incoming = connection.execute(
                """
                SELECT fr.id, su.username AS sender_username, ru.username AS receiver_username,
                       fr.status, fr.note, fr.created_at, fr.updated_at
                FROM friend_requests fr
                JOIN users su ON su.id = fr.sender_id
                JOIN users ru ON ru.id = fr.receiver_id
                WHERE fr.receiver_id = ? AND fr.status = 'pending'
                ORDER BY fr.created_at DESC
                """,
                (user_id,),
            ).fetchall()
            outgoing = connection.execute(
                """
                SELECT fr.id, su.username AS sender_username, ru.username AS receiver_username,
                       fr.status, fr.note, fr.created_at, fr.updated_at
                FROM friend_requests fr
                JOIN users su ON su.id = fr.sender_id
                JOIN users ru ON ru.id = fr.receiver_id
                WHERE fr.sender_id = ? AND fr.status = 'pending'
                ORDER BY fr.created_at DESC
                """,
                (user_id,),
            ).fetchall()
            return {
                "incoming": [dict(row) for row in incoming],
                "outgoing": [dict(row) for row in outgoing],
            }

    def accept_friend_request(self, request_id: int, receiver_id: int) -> dict[str, Any]:
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            request_row = connection.execute(
                "SELECT * FROM friend_requests WHERE id = ?",
                (request_id,),
            ).fetchone()
            if request_row is None or request_row["receiver_id"] != receiver_id:
                raise NotFoundError("Friend request not found.")
            if request_row["status"] != "pending":
                raise ConflictError("Friend request is no longer pending.")
            if self.is_blocked(int(request_row["sender_id"]), int(request_row["receiver_id"])):
                raise UnauthorizedError("Cannot accept a request because one user has blocked the other.")
            connection.execute(
                "UPDATE friend_requests SET status = 'accepted', updated_at = ? WHERE id = ?",
                (now, request_id),
            )
            low, high = self.ordered_pair(int(request_row["sender_id"]), int(request_row["receiver_id"]))
            connection.execute(
                """
                INSERT INTO friendships (user_low_id, user_high_id, status, created_at, updated_at)
                VALUES (?, ?, 'accepted', ?, ?)
                ON CONFLICT(user_low_id, user_high_id)
                DO UPDATE SET status = 'accepted', updated_at = excluded.updated_at
                """,
                (low, high, now, now),
            )
            self._clear_contact_verifications_for_pair(
                connection,
                int(request_row["sender_id"]),
                int(request_row["receiver_id"]),
            )
            row = connection.execute(
                """
                SELECT fr.id, su.username AS sender_username, ru.username AS receiver_username,
                       fr.status, fr.note, fr.created_at, fr.updated_at
                FROM friend_requests fr
                JOIN users su ON su.id = fr.sender_id
                JOIN users ru ON ru.id = fr.receiver_id
                WHERE fr.id = ?
                """,
                (request_id,),
            ).fetchone()
            return dict(row)

    def decline_friend_request(self, request_id: int, receiver_id: int) -> dict[str, Any]:
        return self._update_friend_request_status(request_id, actor_user_id=receiver_id, actor_role="receiver", new_status="declined")

    def cancel_friend_request(self, request_id: int, sender_id: int) -> dict[str, Any]:
        return self._update_friend_request_status(request_id, actor_user_id=sender_id, actor_role="sender", new_status="cancelled")

    def _update_friend_request_status(
        self,
        request_id: int,
        actor_user_id: int,
        actor_role: str,
        new_status: str,
    ) -> dict[str, Any]:
        now = isoformat_z(utc_now())
        field_name = "sender_id" if actor_role == "sender" else "receiver_id"
        with self.db.transaction() as connection:
            request_row = connection.execute("SELECT * FROM friend_requests WHERE id = ?", (request_id,)).fetchone()
            if request_row is None or int(request_row[field_name]) != actor_user_id:
                raise NotFoundError("Friend request not found.")
            if request_row["status"] != "pending":
                raise ConflictError("Friend request is no longer pending.")
            connection.execute(
                "UPDATE friend_requests SET status = ?, updated_at = ? WHERE id = ?",
                (new_status, now, request_id),
            )
            row = connection.execute(
                """
                SELECT fr.id, su.username AS sender_username, ru.username AS receiver_username,
                       fr.status, fr.note, fr.created_at, fr.updated_at
                FROM friend_requests fr
                JOIN users su ON su.id = fr.sender_id
                JOIN users ru ON ru.id = fr.receiver_id
                WHERE fr.id = ?
                """,
                (request_id,),
            ).fetchone()
            return dict(row)

    def _clear_contact_verifications_for_pair(self, connection: sqlite3.Connection, user_a: int, user_b: int) -> None:
        connection.execute(
            """
            DELETE FROM contact_verifications
            WHERE (verifier_user_id = ? AND verified_user_id = ?)
               OR (verifier_user_id = ? AND verified_user_id = ?)
            """,
            (user_a, user_b, user_b, user_a),
        )

    def _clear_blocks_for_pair(self, connection: sqlite3.Connection, user_a: int, user_b: int) -> None:
        connection.execute(
            """
            DELETE FROM blocks
            WHERE (blocker_id = ? AND blocked_id = ?)
               OR (blocker_id = ? AND blocked_id = ?)
            """,
            (user_a, user_b, user_b, user_a),
        )

    def _verification_state(
        self,
        connection: sqlite3.Connection,
        *,
        verifier_id: int,
        verified_id: int,
        verified_user_fingerprint: str | None,
    ) -> str:
        row = connection.execute(
            """
            SELECT verified_fingerprint
            FROM contact_verifications
            WHERE verifier_user_id = ? AND verified_user_id = ?
            """,
            (verifier_id, verified_id),
        ).fetchone()
        if row is None:
            return "missing"
        stored_fingerprint = str(row["verified_fingerprint"] or "").strip()
        current_fingerprint = str(verified_user_fingerprint or "").strip()
        if current_fingerprint and stored_fingerprint == current_fingerprint:
            return "verified"
        return "identity_changed"

    def verification_states_for_pair(self, user_id: int, other_id: int) -> dict[str, str]:
        with self.db.connect() as connection:
            me = connection.execute(
                "SELECT active_key_fingerprint FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            other = connection.execute(
                "SELECT active_key_fingerprint FROM users WHERE id = ?",
                (other_id,),
            ).fetchone()
            my_fingerprint = None if me is None else str(me["active_key_fingerprint"] or "").strip() or None
            other_fingerprint = None if other is None else str(other["active_key_fingerprint"] or "").strip() or None
            return {
                "my_verification_state": self._verification_state(
                    connection,
                    verifier_id=user_id,
                    verified_id=other_id,
                    verified_user_fingerprint=other_fingerprint,
                ),
                "friend_verification_state": self._verification_state(
                    connection,
                    verifier_id=other_id,
                    verified_id=user_id,
                    verified_user_fingerprint=my_fingerprint,
                ),
            }

    def record_contact_verification(self, verifier_id: int, verified_id: int, fingerprint: str) -> dict[str, Any]:
        if verifier_id == verified_id:
            raise ConflictError("You cannot verify yourself.")
        normalized_fingerprint = str(fingerprint or "").strip()
        if not normalized_fingerprint:
            raise ConflictError("Fingerprint is required.")
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            target = connection.execute(
                "SELECT active_key_fingerprint FROM users WHERE id = ?",
                (verified_id,),
            ).fetchone()
            if target is None:
                raise NotFoundError("Target user not found.")
            if not self.are_friends(verifier_id, verified_id):
                raise UnauthorizedError("Only accepted friends may be verified.")
            active_fingerprint = str(target["active_key_fingerprint"] or "").strip()
            if normalized_fingerprint != active_fingerprint:
                raise ConflictError("The supplied fingerprint does not match the contact's current active key.")
            connection.execute(
                """
                INSERT INTO contact_verifications (verifier_user_id, verified_user_id, verified_fingerprint, verified_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(verifier_user_id, verified_user_id)
                DO UPDATE SET verified_fingerprint = excluded.verified_fingerprint, verified_at = excluded.verified_at
                """,
                (verifier_id, verified_id, active_fingerprint, now),
            )
            return {
                "verifier_user_id": verifier_id,
                "verified_user_id": verified_id,
                "verified_fingerprint": active_fingerprint,
                "verified_at": now,
            }

    def list_contacts(self, user_id: int) -> list[dict[str, Any]]:
        with self.db.connect() as connection:
            current_user = connection.execute(
                "SELECT active_key_fingerprint FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            current_user_fingerprint = None if current_user is None else str(current_user["active_key_fingerprint"] or "").strip() or None
            rows = connection.execute(
                """
                WITH direct_contacts AS (
                    SELECT
                        f.user_high_id AS other_user_id,
                        f.status AS friendship_status,
                        f.updated_at AS since
                    FROM friendships f
                    WHERE f.user_low_id = ? AND f.status = 'accepted'

                    UNION ALL

                    SELECT
                        f.user_low_id AS other_user_id,
                        f.status AS friendship_status,
                        f.updated_at AS since
                    FROM friendships f
                    WHERE f.user_high_id = ? AND f.status = 'accepted'
                )
                SELECT
                    u.username AS username,
                    u.active_key_fingerprint AS other_active_key_fingerprint,
                    dc.other_user_id AS other_user_id,
                    dc.friendship_status,
                    dc.since,
                    EXISTS(
                        SELECT 1
                        FROM blocks b
                        WHERE b.blocker_id = ? AND b.blocked_id = u.id
                    ) AS blocked_by_me,
                    EXISTS(
                        SELECT 1
                        FROM blocks b
                        WHERE b.blocker_id = u.id AND b.blocked_id = ?
                    ) AS blocked_me
                FROM direct_contacts dc
                JOIN users u ON u.id = dc.other_user_id
                ORDER BY u.username COLLATE NOCASE ASC
                """,
                (user_id, user_id, user_id, user_id),
            ).fetchall()

            contacts: list[dict[str, Any]] = []
            for row in rows:
                record = dict(row)
                other_user_id = int(record.pop("other_user_id"))
                other_active_key_fingerprint = str(record.pop("other_active_key_fingerprint") or "").strip() or None
                record["my_verification_state"] = self._verification_state(
                    connection,
                    verifier_id=user_id,
                    verified_id=other_user_id,
                    verified_user_fingerprint=other_active_key_fingerprint,
                )
                record["friend_verification_state"] = self._verification_state(
                    connection,
                    verifier_id=other_user_id,
                    verified_id=user_id,
                    verified_user_fingerprint=current_user_fingerprint,
                )
                note_row = connection.execute(
                    """
                    SELECT
                        fr.note AS initial_note,
                        fr.created_at AS initial_note_created_at,
                        CASE WHEN fr.sender_id = ? THEN 'out' ELSE 'in' END AS initial_note_direction
                    FROM friend_requests fr
                    WHERE fr.status = 'accepted'
                      AND ((fr.sender_id = ? AND fr.receiver_id = ?) OR (fr.sender_id = ? AND fr.receiver_id = ?))
                    ORDER BY fr.updated_at DESC, fr.id DESC
                    LIMIT 1
                    """,
                    (user_id, user_id, other_user_id, other_user_id, user_id),
                ).fetchone()
                if note_row is not None:
                    note_value = str(note_row["initial_note"] or "").strip() or None
                    if note_value is not None:
                        record["initial_note"] = note_value
                        record["initial_note_created_at"] = note_row["initial_note_created_at"]
                        record["initial_note_direction"] = note_row["initial_note_direction"]
                contacts.append(record)
            return contacts

    def block_user(self, blocker_id: int, blocked_id: int) -> None:
        if blocker_id == blocked_id:
            raise ConflictError("You cannot block yourself.")
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            connection.execute(
                "INSERT OR IGNORE INTO blocks (blocker_id, blocked_id, created_at) VALUES (?, ?, ?)",
                (blocker_id, blocked_id, now),
            )

    def unblock_user(self, blocker_id: int, blocked_id: int) -> None:
        with self.db.transaction() as connection:
            connection.execute(
                "DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?",
                (blocker_id, blocked_id),
            )

    def remove_friend(self, user_id: int, other_id: int) -> None:
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            friendship_row = self._friendship_row(connection, user_id, other_id)
            if friendship_row is None or str(friendship_row["status"] or "").strip().lower() != "accepted":
                return
            low, high = self.ordered_pair(user_id, other_id)
            connection.execute(
                "UPDATE friendships SET status = 'removed', updated_at = ? WHERE user_low_id = ? AND user_high_id = ?",
                (now, low, high),
            )
            self._clear_blocks_for_pair(connection, user_id, other_id)
            connection.execute(
                """
                UPDATE messages
                SET deleted_at = COALESCE(deleted_at, ?)
                WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
                """,
                (now, user_id, other_id, other_id, user_id),
            )
            self._clear_contact_verifications_for_pair(connection, user_id, other_id)

    def insert_message(self, sender_id: int, receiver_id: int, envelope: dict[str, Any]) -> dict[str, Any]:
        header = envelope["header"]
        now_dt = utc_now()
        now = isoformat_z(now_dt)
        ttl_seconds = header.get("ttl_seconds")
        canonical_expires_at = (
            isoformat_z(now_dt + timedelta(seconds=int(ttl_seconds)))
            if header.get("kind") == "chat" and ttl_seconds is not None
            else None
        )
        size_bytes = len(envelope["ciphertext"].encode("utf-8")) + len(envelope["nonce"].encode("utf-8"))
        with self.db.transaction() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO messages (
                        message_id, conversation_id, sender_id, receiver_id, kind, payload_version,
                        counter, ttl_seconds, sender_key_fingerprint, receiver_key_fingerprint, related_message_id,
                        created_at, expires_at, canonical_expires_at, nonce, ciphertext, submitted_at,
                        consumed_at, delivered_at, deleted_at, last_pushed_at, size_bytes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, ?)
                    """,
                    (
                        header["message_id"],
                        header["conversation_id"],
                        sender_id,
                        receiver_id,
                        header["kind"],
                        int(header.get("payload_version", 1)),
                        int(header["counter"]),
                        ttl_seconds,
                        header["sender_key_fingerprint"],
                        header["receiver_key_fingerprint"],
                        header.get("related_message_id"),
                        header["created_at"],
                        header.get("expires_at"),
                        canonical_expires_at,
                        envelope["nonce"],
                        envelope["ciphertext"],
                        now,
                        size_bytes,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DuplicateError("Duplicate message_id or counter detected.") from exc
            if header["kind"] == "delivery_ack" and header.get("related_message_id"):
                connection.execute(
                    """
                    UPDATE messages
                    SET delivered_at = ?, deleted_at = COALESCE(deleted_at, ?)
                    WHERE message_id = ? AND receiver_id = ?
                    """,
                    (now, now, header["related_message_id"], sender_id),
                )
            row = connection.execute(
                "SELECT * FROM messages WHERE message_id = ?",
                (header["message_id"],),
            ).fetchone()
            return dict(row)

    def fetch_pending_messages(self, receiver_id: int, limit: int = 50, cursor: str | None = None) -> list[dict[str, Any]]:
        now = isoformat_z(utc_now())
        params: list[Any] = [receiver_id, now]
        cursor_clause = ""
        if cursor:
            cursor_clause = " AND submitted_at < ?"
            params.append(cursor)
        params.append(limit)
        with self.db.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT message_id, conversation_id, sender_id, receiver_id, kind, payload_version, counter,
                       ttl_seconds, sender_key_fingerprint, receiver_key_fingerprint, related_message_id,
                       created_at, expires_at, canonical_expires_at, nonce, ciphertext, submitted_at
                FROM messages
                WHERE receiver_id = ?
                  AND consumed_at IS NULL
                  AND deleted_at IS NULL
                  AND (canonical_expires_at IS NULL OR canonical_expires_at > ?)
                  {cursor_clause}
                ORDER BY submitted_at DESC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
            return [dict(row) for row in rows]

    def mark_message_pushed(self, message_id: str) -> None:
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            connection.execute(
                "UPDATE messages SET last_pushed_at = ? WHERE message_id = ?",
                (now, message_id),
            )

    def consume_message(self, receiver_id: int, message_id: str) -> None:
        now = isoformat_z(utc_now())
        with self.db.transaction() as connection:
            updated = connection.execute(
                "UPDATE messages SET consumed_at = ?, deleted_at = COALESCE(deleted_at, ?) WHERE message_id = ? AND receiver_id = ?",
                (now, now, message_id, receiver_id),
            )
            if updated.rowcount == 0:
                raise NotFoundError("Message not found for current user.")

    def get_message_parties(self, message_id: str) -> dict[str, Any] | None:
        with self.db.connect() as connection:
            row = connection.execute(
                "SELECT * FROM messages WHERE message_id = ?",
                (message_id,),
            ).fetchone()
            return self._row_to_dict(row)

    def pending_message_count(self, user_id: int) -> int:
        now = isoformat_z(utc_now())
        with self.db.connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM messages WHERE receiver_id = ? AND consumed_at IS NULL AND deleted_at IS NULL AND (canonical_expires_at IS NULL OR canonical_expires_at > ?)",
                (user_id, now),
            ).fetchone()
            return int(row["count"])

    def purge_expired_and_old_messages(self, pending_retention_hours: int, consumed_retention_hours: int) -> int:
        now_dt = utc_now()
        now = isoformat_z(now_dt)
        pending_cutoff = isoformat_z(now_dt - timedelta(hours=pending_retention_hours))
        consumed_cutoff = isoformat_z(now_dt - timedelta(hours=consumed_retention_hours))
        with self.db.transaction() as connection:
            updated = connection.execute(
                """
                UPDATE messages
                SET deleted_at = COALESCE(deleted_at, ?)
                WHERE deleted_at IS NULL AND (
                    (canonical_expires_at IS NOT NULL AND canonical_expires_at <= ?) OR
                    (consumed_at IS NULL AND submitted_at <= ?) OR
                    (consumed_at IS NOT NULL AND consumed_at <= ?)
                )
                """,
                (now, now, pending_cutoff, consumed_cutoff),
            )
            return int(updated.rowcount)

    def usernames_for_ids(self, user_ids: list[int]) -> dict[int, str]:
        if not user_ids:
            return {}
        placeholders = ",".join("?" for _ in user_ids)
        with self.db.connect() as connection:
            rows = connection.execute(
                f"SELECT id, username FROM users WHERE id IN ({placeholders})",
                tuple(user_ids),
            ).fetchall()
            return {int(row["id"]): row["username"] for row in rows}
