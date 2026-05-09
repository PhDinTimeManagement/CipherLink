from __future__ import annotations

import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from websockets.sync.client import connect as ws_connect

from client.api import APIError, ServerAPI
from client.crypto import (
    create_keypair,
    decrypt_envelope,
    prepare_chat_envelope,
    prepare_delivery_ack_envelope,
    verified_bundle,
)
from client.local_store import LocalStore
from client.profile import LocalVault, ProfileConfig, ProfileError, normalize_profile_name, profile_paths
from shared.protocol import LoginRequest, MessageEnvelope, PublicKeyBundle, RegisterRequest, RegistrationOTPConfirmRequest
from shared.trust_logic import (
    REASON_FRIEND_HAS_NOT_VERIFIED_YOU,
    REASON_FRIEND_IDENTITY_CHANGED,
    REASON_YOU_HAVE_NOT_VERIFIED_FRIEND,
    REASON_YOUR_IDENTITY_CHANGED,
    evaluate_contact_messaging_status,
)
from shared.utils import (
    conversation_id_for_users,
    friendly_fingerprint,
    history_retention_boundary,
    isoformat_z,
    parse_datetime,
    utc_now,
)


class ClientOperationError(Exception):
    pass


@dataclass(slots=True)
class FingerprintInfo:
    username: str
    fingerprint: str
    display: str
    trust_state: str
    verified: bool


class ClientRuntime:
    def __init__(self, profile_name: str, base_dir: str | Path | None = None, transport=None, verify_override: str | bool | None = None) -> None:
        self.paths = profile_paths(profile_name, base_dir)
        self.profile = ProfileConfig(self.paths)
        self.vault = LocalVault(self.paths)
        self.store = LocalStore(self.paths.local_db_path)
        self.transport = transport
        self.verify_override = verify_override
        self._api: ServerAPI | None = None

    def close(self) -> None:
        if self._api is not None:
            self._api.close()
            self._api = None

    def _require_profile(self) -> dict[str, Any]:
        return self.profile.load()

    def _require_unlocked(self) -> None:
        if not self.vault.is_unlocked:
            raise ClientOperationError("Unlock the local vault first by providing the device passphrase.")

    def _ensure_api(self) -> ServerAPI:
        config = self._require_profile()
        if self._api is None:
            verify = self.verify_override if self.verify_override is not None else config["ca_cert_path"]
            token = None
            if self.vault.is_unlocked and self.vault.session() is not None:
                token = self.vault.session()["token"]
            self._api = ServerAPI(config["server_url"], verify, token=token, transport=self.transport)
        else:
            if self.vault.is_unlocked:
                session = self.vault.session()
                self._api.set_token(session["token"] if session else None)
        return self._api

    @staticmethod
    def _normalize_username(username: str) -> str:
        normalized = str(username or "").strip().lower()
        if not normalized:
            raise ClientOperationError("Username is required.")
        return normalized

    def _normalized_profile_name(self) -> str:
        return normalize_profile_name(self.paths.profile_dir.name)

    def _require_profile_username_match(self, username: str) -> str:
        normalized_username = self._normalize_username(username)
        normalized_profile = self._normalized_profile_name()
        if normalized_profile != normalized_username:
            raise ClientOperationError(
                "Profile name and username must match after lowercase normalization. "
                f"Use profile '{normalized_username}' for username '{normalized_username}'."
            )
        return normalized_username

    def _validate_loaded_profile_identity(self) -> None:
        if not self.vault.is_unlocked:
            return
        normalized_profile = self._normalized_profile_name()
        normalized_username = self._normalize_username(self.vault.username())
        if normalized_profile != normalized_username:
            raise ClientOperationError(
                "Profile name and username must match after lowercase normalization. "
                f"This profile is '{normalized_profile}' but belongs to '{normalized_username}'."
            )

    def initialize_profile(
        self,
        username: str,
        device_passphrase: str,
        server_url: str | None = None,
        ca_cert_path: str | None = None,
        bootstrap_path: str | Path | None = None,
    ) -> None:
        normalized = self._require_profile_username_match(username)
        self.close()
        if bootstrap_path is not None:
            self.profile.save_from_bootstrap(bootstrap_path)
        else:
            if not server_url or not ca_cert_path:
                raise ClientOperationError("Either bootstrap_path or both server_url and ca_cert_path are required.")
            self.profile.save(server_url=server_url, ca_cert_path=ca_cert_path)
        if not self.vault.exists():
            self.vault.create(normalized, device_passphrase)
        self.vault.unlock(device_passphrase)
        if self.vault.username() != normalized:
            raise ClientOperationError(
                f"Profile {self.paths.profile_dir.name} belongs to {self.vault.username()}, not {normalized}. Use a different profile name."
            )

    def unlock(self, device_passphrase: str) -> None:
        self.vault.unlock(device_passphrase)
        self._validate_loaded_profile_identity()
        if self._api is not None:
            session = self.vault.session()
            self._api.set_token(session["token"] if session else None)

    def active_key_record(self) -> dict[str, Any]:
        self._require_unlocked()
        return self.vault.key_record()

    def all_key_records(self) -> dict[str, Any]:
        self._require_unlocked()
        return self.vault.all_key_records()

    def active_bundle(self) -> PublicKeyBundle:
        record = self.active_key_record()
        return PublicKeyBundle(
            username=self.vault.username(),
            fingerprint=self.vault.active_key_fingerprint(),
            identity_public_key=record["identity_public_key"],
            chat_public_key=record["chat_public_key"],
            signature=record["signature"],
            created_at=record["created_at"],
            is_active=True,
        )

    def register(
        self,
        username: str,
        password: str,
        device_passphrase: str,
        server_url: str | None = None,
        ca_cert_path: str | None = None,
        bootstrap_path: str | Path | None = None,
    ) -> dict[str, Any]:
        self.initialize_profile(
            username=username,
            device_passphrase=device_passphrase,
            server_url=server_url,
            ca_cert_path=ca_cert_path,
            bootstrap_path=bootstrap_path,
        )
        if self.vault.active_key_fingerprint() is None:
            keypair = create_keypair()
            self.vault.add_keypair(keypair, created_at=isoformat_z(utc_now()), make_active=True)
        bundle = self.active_bundle()
        api = self._ensure_api()
        normalized_username = self._require_profile_username_match(username)
        response = api.register(RegisterRequest(username=normalized_username, password=password, bundle=bundle))
        return response

    def confirm_registration_otp(self, username: str, password: str, otp_code: str, device_passphrase: str) -> dict[str, Any]:
        normalized_username = self._require_profile_username_match(username)
        self.unlock(device_passphrase)
        api = self._ensure_api()
        return api.confirm_registration_otp(
            RegistrationOTPConfirmRequest(username=normalized_username, password=password, otp_code=otp_code)
        )

    def login(self, username: str, password: str, otp_code: str, device_passphrase: str) -> dict[str, Any]:
        normalized_username = self._require_profile_username_match(username)
        self.unlock(device_passphrase)
        api = self._ensure_api()
        response = api.login(LoginRequest(username=normalized_username, password=password, otp_code=otp_code))
        self.vault.set_session(response["token"], response["expires_at"])
        api.set_token(response["token"])
        return response

    def logout(self) -> dict[str, Any]:
        self._require_unlocked()
        api = self._ensure_api()
        response = api.logout()
        self.vault.clear_session()
        api.set_token(None)
        return response

    def force_local_logout(self) -> dict[str, Any]:
        self._require_unlocked()
        self.vault.clear_session()
        if self._api is not None:
            self._api.set_token(None)
        return {"message": "Session cleared locally. Sign in again to continue."}

    def me(self) -> dict[str, Any]:
        self._require_unlocked()
        return self._ensure_api().me()

    def username(self) -> str:
        self._require_unlocked()
        return self.vault.username()

    def session_info(self) -> dict[str, Any] | None:
        self._require_unlocked()
        return self.vault.session()

    def server_config(self) -> dict[str, Any]:
        return self._require_profile()

    def active_key_fingerprint_display(self) -> str | None:
        self._require_unlocked()
        fingerprint = self.vault.active_key_fingerprint()
        if fingerprint is None:
            return None
        return friendly_fingerprint(fingerprint)

    def rotate_keys(self) -> dict[str, Any]:
        self._require_unlocked()
        api = self._ensure_api()
        keypair = create_keypair()
        created_at = isoformat_z(utc_now())
        self.vault.add_keypair(keypair, created_at=created_at, make_active=False)
        bundle = keypair.as_public_bundle(self.vault.username(), created_at=created_at, is_active=True)
        response = api.rotate_keys(bundle)
        self.vault.set_active_fingerprint(keypair.fingerprint)
        return response

    def list_contacts(self) -> dict[str, Any]:
        response = self._ensure_api().list_contacts()
        contacts = response.get("contacts", [])
        self._sync_local_contacts_from_server(contacts)
        return response

    def list_requests(self) -> dict[str, Any]:
        return self._ensure_api().list_friend_requests()

    def send_friend_request(self, username: str, note: str | None = None) -> dict[str, Any]:
        normalized = username.lower()
        result = self._ensure_api().send_friend_request(normalized, note)
        self._clear_local_friendship_state(normalized)
        return result

    def accept_request(self, request_id: int) -> dict[str, Any]:
        result = self._ensure_api().accept_friend_request(request_id)
        peer_username = str(result.get("sender_username") or "").strip().lower()
        if peer_username:
            self._clear_local_friendship_state(peer_username)
            self._seed_initial_note_message(
                contact_username=peer_username,
                note=result.get("note"),
                created_at=result.get("created_at"),
                direction="in",
            )
        return result

    def decline_request(self, request_id: int) -> dict[str, Any]:
        return self._ensure_api().decline_friend_request(request_id)

    def cancel_request(self, request_id: int) -> dict[str, Any]:
        return self._ensure_api().cancel_friend_request(request_id)

    def block_user(self, username: str) -> dict[str, Any]:
        return self._ensure_api().block_user(username.lower())

    def unblock_user(self, username: str) -> dict[str, Any]:
        return self._ensure_api().unblock_user(username.lower())

    def remove_friend(self, username: str) -> dict[str, Any]:
        normalized = username.lower()
        result = self._ensure_api().remove_friend(normalized)
        self._clear_local_friendship_state(normalized)
        return result

    def _clear_local_friendship_state(self, username: str) -> None:
        normalized = str(username or "").strip().lower()
        if not normalized:
            return
        conversation_id = None
        if getattr(self.vault, "is_unlocked", True):
            conversation_id = conversation_id_for_users(self.vault.username(), normalized)
        self.store.clear_friendship_state(normalized, conversation_id=conversation_id)

    def _reconcile_local_friendship_state(self, accepted_usernames: set[str]) -> None:
        stale_contacts = sorted(self.store.friendship_artifact_contacts() - set(accepted_usernames))
        for username in stale_contacts:
            self._clear_local_friendship_state(username)

    def _seed_initial_note_message(
        self,
        *,
        contact_username: str,
        note: str | None,
        created_at: str | None,
        direction: str | None,
    ) -> bool:
        self._require_unlocked()
        normalized = str(contact_username or "").strip().lower()
        note_text = str(note or "").strip()
        if not normalized or not note_text:
            return False
        created_value = str(created_at or isoformat_z(utc_now()))
        if self._message_outside_history_retention(created_value):
            return False
        normalized_direction = str(direction or "").strip().lower()
        if normalized_direction == "out":
            sender = self.vault.username()
            receiver = normalized
        else:
            normalized_direction = "in"
            sender = normalized
            receiver = self.vault.username()
        return self.store.ensure_initial_note_message(
            self.vault.local_storage_key(),
            conversation_id=conversation_id_for_users(self.vault.username(), normalized),
            contact_username=normalized,
            sender=sender,
            receiver=receiver,
            direction=normalized_direction,
            created_at=created_value,
            note=note_text,
        )

    def _sync_local_contacts_from_server(
        self,
        contacts: list[dict[str, Any]],
        *,
        only_username: str | None = None,
    ) -> None:
        accepted_usernames = {
            str(row.get("username") or "").strip().lower()
            for row in contacts
            if str(row.get("friendship_status") or "accepted").strip().lower() == "accepted"
        }
        self._reconcile_local_friendship_state(accepted_usernames)
        target = str(only_username or "").strip().lower() or None
        for contact in contacts:
            username = str(contact.get("username") or "").strip().lower()
            if not username:
                continue
            if target is not None and username != target:
                continue
            if str(contact.get("friendship_status") or "").strip().lower() == "accepted":
                self._seed_initial_note_message(
                    contact_username=username,
                    note=contact.get("initial_note"),
                    created_at=contact.get("initial_note_created_at") or contact.get("since"),
                    direction=contact.get("initial_note_direction"),
                )
            self._sync_contact_security_events(contact)

    def _refresh_contacts_for_initial_note(self, username: str | None = None) -> None:
        contacts_response = self._ensure_api().list_contacts()
        contacts = contacts_response.get("contacts", [])
        self._sync_local_contacts_from_server(contacts, only_username=username)

    def _ensure_initial_note_seeded(self, username: str) -> None:
        normalized = str(username or "").strip().lower()
        if not normalized or self.store.has_initial_note_message(normalized):
            return
        self._refresh_contacts_for_initial_note(normalized)

    def _get_private_chat_key_bytes(self, fingerprint: str | None = None) -> bytes:
        record = self.vault.key_record(fingerprint)
        from shared.utils import b64d  # local import to keep module boundaries light

        return b64d(record["chat_private_key"])

    def _get_public_chat_key_bytes(self, key_record: dict[str, Any]) -> bytes:
        from shared.utils import b64d

        return b64d(key_record["chat_public_key"])

    def _fetch_current_bundle(self, username: str) -> dict[str, Any]:
        bundle = self._ensure_api().get_current_bundle(username.lower())
        verified = verified_bundle(bundle)
        status = self.store.refresh_current_bundle(username.lower(), bundle)
        return {
            "bundle": bundle,
            "verified_bundle": verified,
            "status": status,
        }

    def _bundle_by_fingerprint(self, username: str, fingerprint: str) -> dict[str, Any]:
        username = username.lower()
        cached = self.store.get_cached_bundle(username, fingerprint)
        if cached is not None:
            return {"bundle": cached, "verified_bundle": verified_bundle(cached), "status": "cached"}
        bundle = self._ensure_api().get_bundle_by_fingerprint(username, fingerprint)
        verified = verified_bundle(bundle)
        if bundle.get("is_active", True):
            status = self.store.refresh_current_bundle(username, bundle)
        else:
            self.store.cache_historical_bundle(username, bundle)
            status = "historical"
        if status == "key_changed" and fingerprint == bundle["fingerprint"]:
            raise ClientOperationError(
                f"Security warning: {username} changed keys. Run verify-contact before accepting the new active key."
            )
        return {"bundle": bundle, "verified_bundle": verified, "status": status}

    def fingerprint_info(self, username: str) -> FingerprintInfo:
        username = username.lower()
        result = self._fetch_current_bundle(username)
        bundle = result["bundle"]
        state = self.store.get_contact_state(username) or {
            "trust_state": "unverified",
            "verified": 0,
            "current_fingerprint": bundle["fingerprint"],
        }
        return FingerprintInfo(
            username=username,
            fingerprint=bundle["fingerprint"],
            display=friendly_fingerprint(bundle["fingerprint"]),
            trust_state=state["trust_state"],
            verified=bool(state["verified"]),
        )

    def verify_contact(self, username: str) -> FingerprintInfo:
        normalized = username.lower()
        info = self.fingerprint_info(normalized)
        self._ensure_api().verify_contact(normalized, info.fingerprint)
        self.store.mark_contact_verified(normalized)
        contact = self._accepted_contact_record(normalized)
        if contact is not None:
            self._sync_contact_security_events(contact)
        return self.fingerprint_info(normalized)

    def _server_created_at(self, payload: dict[str, Any] | MessageEnvelope) -> str | None:
        if isinstance(payload, MessageEnvelope):
            return payload.submitted_at
        if isinstance(payload, dict):
            return payload.get("submitted_at")
        return None

    def _canonical_expires_at(self, payload: dict[str, Any] | MessageEnvelope) -> str | None:
        if isinstance(payload, MessageEnvelope):
            return payload.canonical_expires_at or payload.header.expires_at
        if isinstance(payload, dict):
            return payload.get("canonical_expires_at") or payload.get("header", {}).get("expires_at")
        return None

    def _canonical_created_at(self, payload: dict[str, Any] | MessageEnvelope) -> str | None:
        if isinstance(payload, MessageEnvelope):
            return payload.submitted_at or payload.header.created_at
        if isinstance(payload, dict):
            header = payload.get("header", {}) if isinstance(payload, dict) else {}
            return payload.get("submitted_at") or header.get("created_at")
        return None

    def _accepted_contact_record(self, username: str) -> dict[str, Any] | None:
        normalized = str(username or "").strip().lower()
        if not normalized:
            return None
        contacts = self.list_contacts().get("contacts", [])
        for row in contacts:
            if str(row.get("username") or "").strip().lower() != normalized:
                continue
            if str(row.get("friendship_status") or "").strip().lower() == "accepted":
                return row
        return None

    def _record_verification_required_alert(
        self,
        username: str,
        *,
        event_type: str,
        detail: str,
        reason: str | None = None,
        current_fingerprint: str | None = None,
    ) -> None:
        normalized = str(username or "").strip().lower()
        if not normalized:
            return
        if reason:
            self.store.require_reverification(
                normalized,
                reason=reason,
                event_type=event_type,
                current_fingerprint=current_fingerprint,
                detail=detail,
            )
        else:
            self.store.ensure_security_event(normalized, event_type, detail)

    def _sync_contact_security_events(self, contact: dict[str, Any] | None) -> None:
        if contact is None:
            return
        username = str(contact.get("username") or "").strip().lower()
        if not username:
            return
        status = evaluate_contact_messaging_status(contact)
        reasons = set(status.reasons)
        if REASON_FRIEND_IDENTITY_CHANGED not in reasons:
            self.store.resolve_security_events(username, ["key_change"])
        if REASON_YOU_HAVE_NOT_VERIFIED_FRIEND not in reasons:
            self.store.resolve_security_events(username, ["verification_required"])
        if REASON_YOUR_IDENTITY_CHANGED not in reasons:
            self.store.resolve_security_events(username, ["local_key_change"])
        if REASON_FRIEND_HAS_NOT_VERIFIED_YOU not in reasons:
            self.store.resolve_security_events(username, ["peer_verification_required"])

    def _require_verified_contact_for_chat(self, username: str, *, bundle: dict[str, Any] | None = None) -> None:
        contact = self._accepted_contact_record(username)
        if contact is None:
            return
        status = evaluate_contact_messaging_status(contact)
        self._sync_contact_security_events(contact)
        if status.manual_blocked or status.code == "messaging_unavailable":
            return
        if not status.blocked:
            return

        state = self.store.get_contact_state(username)
        fingerprint = None
        if state and state.get("current_fingerprint"):
            fingerprint = str(state["current_fingerprint"])
        elif bundle is not None and bundle.get("fingerprint"):
            fingerprint = str(bundle["fingerprint"])
        fingerprint_display = friendly_fingerprint(fingerprint) if fingerprint else None

        if REASON_FRIEND_IDENTITY_CHANGED in status.reasons:
            detail = (
                f"Contact {username} changed identity fingerprint to {fingerprint}. Verify before normal messaging resumes."
                if fingerprint
                else f"Contact {username} changed identity keys. Verify before normal messaging resumes."
            )
            self._record_verification_required_alert(
                username,
                event_type="key_change",
                reason="remote_key_change",
                current_fingerprint=fingerprint,
                detail=detail,
            )
        if REASON_YOU_HAVE_NOT_VERIFIED_FRIEND in status.reasons:
            detail = f"Verify {username} before sending normal chat messages."
            if fingerprint_display:
                detail = f"Verify {username} before sending normal chat messages. Safety number: {fingerprint_display}."
            self._record_verification_required_alert(
                username,
                event_type="verification_required",
                detail=detail,
            )
        if REASON_YOUR_IDENTITY_CHANGED in status.reasons:
            self.store.ensure_security_event(
                username,
                "local_key_change",
                f"You changed your active identity fingerprint. {username} must verify your current safety number before normal messaging resumes.",
            )
        if REASON_FRIEND_HAS_NOT_VERIFIED_YOU in status.reasons:
            self.store.ensure_security_event(
                username,
                "peer_verification_required",
                f"{username} has not verified your current safety number yet. They must verify you before normal messaging resumes.",
            )

        reasons = set(status.reasons)
        if reasons == {REASON_FRIEND_IDENTITY_CHANGED}:
            target = fingerprint_display or "the current safety number"
            raise ClientOperationError(
                f"Refusing to send: {username} changed keys. Review fingerprint {target} and run verify-contact first."
            )
        if reasons == {REASON_YOU_HAVE_NOT_VERIFIED_FRIEND}:
            if fingerprint_display:
                raise ClientOperationError(
                    f"Refusing to send: {username} is not verified yet. Compare safety number {fingerprint_display} and run verify-contact first."
                )
            raise ClientOperationError(
                f"Refusing to send: {username} is not verified yet. Compare the safety number out of band and run verify-contact first."
            )
        if reasons == {REASON_YOUR_IDENTITY_CHANGED}:
            raise ClientOperationError(
                f"Refusing to send: {username} has not verified your current identity yet. They must verify your safety number before normal messaging resumes."
            )
        if reasons == {REASON_FRIEND_HAS_NOT_VERIFIED_YOU}:
            raise ClientOperationError(
                f"Refusing to send: {username} has not verified your current identity yet. They must verify your safety number before normal messaging resumes."
            )
        if reasons == {REASON_YOU_HAVE_NOT_VERIFIED_FRIEND, REASON_FRIEND_HAS_NOT_VERIFIED_YOU}:
            if fingerprint_display:
                raise ClientOperationError(
                    f"Refusing to send: neither side has verified the other yet. Compare safety number {fingerprint_display}, run verify-contact, and ask {username} to verify you before normal messaging resumes."
                )
            raise ClientOperationError(
                f"Refusing to send: neither side has verified the other yet. Verify {username} and ask them to verify you before normal messaging resumes."
            )
        if reasons == {REASON_FRIEND_IDENTITY_CHANGED, REASON_YOUR_IDENTITY_CHANGED}:
            target = fingerprint_display or "the current safety number"
            raise ClientOperationError(
                f"Refusing to send: both sides changed identities. Review {username}'s fingerprint {target}, run verify-contact, and ask {username} to verify your current safety number before normal messaging resumes."
            )

        clauses: list[str] = []
        if REASON_FRIEND_IDENTITY_CHANGED in reasons:
            target = fingerprint_display or "the current safety number"
            clauses.append(f"{username} changed keys ({target})")
        if REASON_YOU_HAVE_NOT_VERIFIED_FRIEND in reasons:
            clauses.append(f"you have not verified {username}")
        if REASON_YOUR_IDENTITY_CHANGED in reasons:
            clauses.append(f"{username} has not verified your current identity")
        if REASON_FRIEND_HAS_NOT_VERIFIED_YOU in reasons:
            clauses.append(f"{username} has not verified you yet")
        reason_text = "; ".join(clauses) if clauses else status.label
        raise ClientOperationError(f"Refusing to send: {reason_text}.")

    def send_text(self, username: str, text: str, ttl_seconds: int | None = None) -> dict[str, Any]:
        self._require_unlocked()
        if not text or len(text) > 4000:
            raise ClientOperationError("Message text must be between 1 and 4000 characters.")
        purged = self.store.purge_expired_messages()
        _ = purged
        username = username.lower()
        if not self.store.has_messages_for_contact(username):
            try:
                self._ensure_initial_note_seeded(username)
            except Exception:
                pass
        current_bundle_result = self._fetch_current_bundle(username)
        self._require_verified_contact_for_chat(username, bundle=current_bundle_result.get("bundle"))
        verified_peer = current_bundle_result["verified_bundle"]
        counter = self.store.get_and_increment_counter(conversation_id_for_users(self.vault.username(), username))
        prepared = prepare_chat_envelope(
            sender_username=self.vault.username(),
            receiver_username=username,
            sender_key_fingerprint=self.vault.active_key_fingerprint(),
            receiver_key_fingerprint=verified_peer.fingerprint,
            counter=counter,
            text=text,
            ttl_seconds=ttl_seconds,
            sender_private_chat_key=self._get_private_chat_key_bytes(),
            receiver_public_chat_key=verified_peer.chat_public_key,
        )
        response = self._ensure_api().send_envelope(prepared.envelope)
        canonical_created_at = response.get("submitted_at") or prepared.envelope.header.created_at
        canonical_expires_at = response.get("canonical_expires_at") or prepared.envelope.header.expires_at
        self.store.store_outgoing_chat(
            self.vault.local_storage_key(),
            message_id=prepared.envelope.header.message_id,
            conversation_id=prepared.envelope.header.conversation_id,
            contact_username=username,
            sender=self.vault.username(),
            receiver=username,
            counter=prepared.envelope.header.counter,
            created_at=canonical_created_at,
            expires_at=canonical_expires_at,
            ttl_seconds=prepared.envelope.header.ttl_seconds,
            sender_key_fingerprint=prepared.envelope.header.sender_key_fingerprint,
            receiver_key_fingerprint=prepared.envelope.header.receiver_key_fingerprint,
            plaintext_payload=prepared.plaintext_payload,
        )
        return {
            "message_id": prepared.envelope.header.message_id,
            "submitted_at": response["submitted_at"],
            "created_at": canonical_created_at,
            "expires_at": canonical_expires_at,
            "receiver_online": response["receiver_online"],
            "status": "Sent",
        }

    def _send_delivery_receipt(self, row: dict[str, Any]) -> bool:
        peer_result = self._bundle_by_fingerprint(str(row["sender"]), str(row["sender_key_fingerprint"]))
        peer_public_chat_key = peer_result["verified_bundle"].chat_public_key
        ack_counter = self.store.get_and_increment_counter(str(row["conversation_id"]))
        ack = prepare_delivery_ack_envelope(
            sender_username=self.vault.username(),
            receiver_username=str(row["sender"]),
            sender_key_fingerprint=str(row["receiver_key_fingerprint"]),
            receiver_key_fingerprint=str(row["sender_key_fingerprint"]),
            counter=ack_counter,
            related_message_id=str(row["message_id"]),
            sender_private_chat_key=self._get_private_chat_key_bytes(str(row["receiver_key_fingerprint"])),
            receiver_public_chat_key=peer_public_chat_key,
        )
        self._ensure_api().send_envelope(ack.envelope)
        self.store.mark_incoming_message_delivered(str(row["message_id"]))
        return True

    @staticmethod
    def _message_is_unavailable(expires_at: str | None) -> bool:
        expires_dt = parse_datetime(expires_at)
        if expires_dt is None:
            return False
        return expires_dt <= utc_now()

    @staticmethod
    def _message_outside_history_retention(created_at: str | None) -> bool:
        created_dt = parse_datetime(created_at)
        if created_dt is None:
            return False
        return created_dt < history_retention_boundary()

    def _acknowledge_read_messages(
        self,
        contact_username: str | None = None,
        *,
        message_ids: set[str] | None = None,
    ) -> list[str]:
        rows = self.store.pending_delivery_receipts(contact_username.lower() if contact_username else None)
        if message_ids is not None:
            rows = [row for row in rows if str(row.get("message_id")) in message_ids]
        acknowledged: list[str] = []
        for row in rows:
            try:
                if self._send_delivery_receipt(row):
                    acknowledged.append(str(row["message_id"]))
            except Exception:
                continue
        return acknowledged

    def _process_delivery_ack(self, envelope: MessageEnvelope, payload: dict[str, Any]) -> dict[str, Any]:
        ack_for = payload.get("ack_for") or envelope.header.related_message_id
        consumed = False
        created_at = self._canonical_created_at(envelope) or envelope.header.created_at
        try:
            self._ensure_api().consume_message(envelope.header.message_id)
            consumed = True
        except APIError:
            consumed = False
        updated = self.store.mark_message_delivered(ack_for, delivered_at=created_at)
        return {
            "type": "delivery_ack",
            "ack_for": ack_for,
            "updated": updated,
            "consumed": consumed,
            "from": envelope.header.sender,
            "created_at": created_at,
        }

    def _ignore_duplicate_envelope(self, envelope: MessageEnvelope) -> dict[str, Any]:
        header = envelope.header
        consumed = False
        created_at = self._canonical_created_at(envelope) or header.created_at
        if header.kind == "delivery_ack":
            try:
                self._ensure_api().consume_message(header.message_id)
                consumed = True
            except APIError:
                consumed = False
        return {
            "type": "duplicate",
            "kind": header.kind,
            "message_id": header.message_id,
            "from": header.sender,
            "created_at": created_at,
            "consumed": consumed,
        }

    def process_envelope(
        self,
        envelope_data: dict[str, Any],
        *,
        visible_chat_contact: str | None = None,
        allow_immediate_read: bool = False,
    ) -> dict[str, Any]:
        self._require_unlocked()
        self.store.purge_expired_messages()
        envelope = MessageEnvelope(**envelope_data)
        header = envelope.header
        canonical_created_at = self._canonical_created_at(envelope_data) or header.created_at
        canonical_expires_at = self._canonical_expires_at(envelope_data)
        normalized_visible_chat = (visible_chat_contact or "").strip().lower() or None
        if header.receiver != self.vault.username():
            raise ClientOperationError(f"Envelope receiver mismatch: expected {self.vault.username()}, got {header.receiver}")
        if header.kind == "chat" and self._message_outside_history_retention(canonical_created_at):
            try:
                self._ensure_api().consume_message(header.message_id)
            except Exception:
                pass
            return {
                "type": "discarded",
                "from": header.sender,
                "message_id": header.message_id,
                "created_at": canonical_created_at,
                "reason": "outside_retention",
            }
        if header.receiver_key_fingerprint not in self.all_key_records():
            raise ClientOperationError(
                f"This client does not have private key material for receiver fingerprint {header.receiver_key_fingerprint}."
            )
        bundle_result = self._bundle_by_fingerprint(header.sender, header.sender_key_fingerprint)
        state = self.store.get_contact_state(header.sender)
        if (
            header.kind == "chat"
            and state
            and str(state.get("current_fingerprint") or "").strip() == header.sender_key_fingerprint
        ):
            trust_state = str(state.get("trust_state") or "").strip().lower()
            trust_reason = str(state.get("trust_reason") or "").strip().lower()
            if trust_state == "key_change_pending" and trust_reason != "local_key_rotation":
                raise ClientOperationError(
                    f"Security warning: active key for {header.sender} changed to {friendly_fingerprint(header.sender_key_fingerprint)}. Verify before accepting messages encrypted under the new key."
                )
            if not (trust_state == "verified" and bool(state.get("verified"))):
                self.store.ensure_security_event(
                    header.sender,
                    "verification_required",
                    f"Verify {header.sender} before accepting normal chat messages. Safety number: {friendly_fingerprint(header.sender_key_fingerprint)}.",
                )
                raise ClientOperationError(
                    f"Security warning: {header.sender} is not verified yet. Verify the current safety number before accepting normal messages encrypted under this key."
                )
        peer_public_chat_key = bundle_result["verified_bundle"].chat_public_key
        plaintext = decrypt_envelope(envelope, self._get_private_chat_key_bytes(header.receiver_key_fingerprint), peer_public_chat_key)
        first_seen = self.store.record_seen_envelope(
            header.message_id,
            header.sender,
            header.conversation_id,
            header.counter,
            header.kind,
        )
        if not first_seen:
            return self._ignore_duplicate_envelope(envelope)
        if header.kind == "delivery_ack":
            return self._process_delivery_ack(envelope, plaintext)
        if first_seen and header.kind == "chat" and not self.store.has_messages_for_contact(header.sender.lower()):
            try:
                self._ensure_initial_note_seeded(header.sender)
            except Exception:
                pass
        message_available = not self._message_is_unavailable(canonical_expires_at)
        read_immediately = bool(
            allow_immediate_read
            and first_seen
            and message_available
            and normalized_visible_chat == header.sender.lower()
        )
        if first_seen:
            self.store.store_incoming_chat(
                self.vault.local_storage_key(),
                message_id=header.message_id,
                conversation_id=header.conversation_id,
                contact_username=header.sender,
                sender=header.sender,
                receiver=header.receiver,
                counter=header.counter,
                created_at=canonical_created_at,
                expires_at=canonical_expires_at,
                ttl_seconds=header.ttl_seconds,
                sender_key_fingerprint=header.sender_key_fingerprint,
                receiver_key_fingerprint=header.receiver_key_fingerprint,
                plaintext_payload=plaintext,
                mark_read=read_immediately,
            )
        acknowledged_message_ids: list[str] = []
        if read_immediately:
            acknowledged_message_ids = self._acknowledge_read_messages(
                header.sender,
                message_ids={header.message_id},
            )
        ack_sent = header.message_id in acknowledged_message_ids
        return {
            "type": "chat",
            "from": header.sender,
            "message_id": header.message_id,
            "text": plaintext.get("text", ""),
            "first_seen": first_seen,
            "read_immediately": read_immediately,
            "ack_sent": ack_sent,
            "created_at": canonical_created_at,
            "expires_at": canonical_expires_at,
        }

    def sync_queue(
        self,
        limit: int = 100,
        *,
        visible_chat_contact: str | None = None,
    ) -> list[dict[str, Any]]:
        self._require_unlocked()
        self.store.purge_expired_messages()
        api = self._ensure_api()
        response = api.fetch_queue(limit=limit)
        processed: list[dict[str, Any]] = []
        for envelope in response.get("messages", []):
            try:
                result = self.process_envelope(envelope, allow_immediate_read=False)
                if result.get("type") in {"discarded", "duplicate"}:
                    continue
                processed.append(result)
            except ClientOperationError as exc:
                processed.append({"type": "error", "detail": str(exc), "envelope": envelope.get("header", {})})
        return processed

    def conversation_list(self) -> list[dict[str, Any]]:
        self.store.purge_expired_messages()
        return self.store.list_conversations()

    def history(
        self,
        username: str,
        limit: int = 20,
        before_local_id: int | None = None,
        mark_read: bool = True,
        *,
        include_unread: bool = True,
    ) -> tuple[list[dict[str, Any]], int | None]:
        self.store.purge_expired_messages()
        username = username.lower()
        rows, next_before = self.store.load_history(
            self.vault.local_storage_key(),
            username,
            limit=limit,
            before_local_id=before_local_id,
            include_unread=include_unread,
        )
        if not rows and before_local_id is None:
            try:
                self._ensure_initial_note_seeded(username)
            except Exception:
                pass
            rows, next_before = self.store.load_history(
                self.vault.local_storage_key(),
                username,
                limit=limit,
                before_local_id=before_local_id,
                include_unread=include_unread,
            )
        if mark_read:
            self.store.mark_conversation_read(username)
            self._acknowledge_read_messages(username)
        return rows, next_before

    def purge_local_history(self) -> int:
        return self.store.purge_expired_messages()

    def retention_boundary_at(self) -> str:
        return self.store.retention_boundary_at()

    def next_retention_cutoff_at(self, contact_username: str | None = None) -> str | None:
        return self.store.next_retention_cutoff_at(contact_username.lower() if contact_username else None)

    def next_expiry_at(self, contact_username: str | None = None) -> str | None:
        return self.store.next_expiry_at(contact_username.lower() if contact_username else None)

    def next_refresh_at(self, contact_username: str | None = None) -> str | None:
        candidates = [
            self.next_expiry_at(contact_username),
            self.next_retention_cutoff_at(contact_username),
        ]
        dated_candidates = [parse_datetime(value) for value in candidates if value]
        dated_candidates = [value for value in dated_candidates if value is not None]
        if not dated_candidates:
            return None
        return isoformat_z(min(dated_candidates))

    def unresolved_security_events(self) -> list[dict[str, Any]]:
        return self.store.unresolved_security_events()

    def websocket_url(self) -> str:
        config = self._require_profile()
        parsed = urlparse(config["server_url"])
        scheme = "wss" if parsed.scheme == "https" else "ws"
        path = parsed.path.rstrip("/")
        return f"{scheme}://{parsed.netloc}{path}/api/v1/ws"

    def websocket_ssl_context(self) -> ssl.SSLContext:
        config = self._require_profile()
        cafile = str(self.verify_override) if isinstance(self.verify_override, (str, Path)) else config["ca_cert_path"]
        return ssl.create_default_context(cafile=cafile)

    def session_token(self) -> str:
        self._require_unlocked()
        session = self.vault.session()
        if not session:
            raise ClientOperationError("No active session found. Login first.")
        return session["token"]
