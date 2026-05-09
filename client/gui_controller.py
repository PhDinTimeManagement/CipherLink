from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Callable
from urllib.parse import quote

import httpx
from cryptography.exceptions import InvalidTag
from websockets.sync.client import connect as ws_connect

from client.api import APIError
from client.profile import ProfileError, normalize_profile_name
from client.runtime import ClientOperationError, ClientRuntime


EventCallback = Callable[[dict[str, Any]], None]


class CipherLinkGUIController:
    def __init__(self, event_callback: EventCallback | None = None) -> None:
        self._event_callback = event_callback
        self._runtime: ClientRuntime | None = None
        self._profile_name: str | None = None
        self._base_dir: str | None = None
        self._runtime_lock = threading.RLock()
        self._listener_stop = threading.Event()
        self._listener_thread: threading.Thread | None = None
        self._visible_chat_contact: str | None = None

    @staticmethod
    def is_session_expired_error(value: Exception | str) -> bool:
        if isinstance(value, APIError):
            return value.status_code == 401 and "session is invalid or expired" in value.detail.lower()
        message = str(value).strip().lower()
        return any(
            token in message
            for token in (
                "http 401: session is invalid or expired",
                "session is invalid or expired",
                "invalid or expired session",
                "session expired",
            )
        )

    @staticmethod
    def format_user_error(exc: Exception) -> str:
        if isinstance(exc, APIError):
            return f"HTTP {exc.status_code}: {exc.detail}"
        if isinstance(exc, InvalidTag):
            return "Incorrect device passphrase or unreadable encrypted local vault data."
        if isinstance(exc, FileNotFoundError):
            filename = exc.filename or str(exc)
            return f"File not found: {filename}"
        if isinstance(exc, httpx.HTTPError):
            return f"Network error: {exc}"
        if isinstance(exc, (ClientOperationError, ProfileError, ValueError)):
            message = str(exc).strip()
            return message or exc.__class__.__name__
        message = str(exc).strip()
        return message or exc.__class__.__name__

    def _emit(self, event_type: str, **payload: Any) -> None:
        if self._event_callback is None:
            return
        try:
            self._event_callback({"type": event_type, **payload})
        except Exception:
            return

    def close(self) -> None:
        self.stop_listener()
        with self._runtime_lock:
            if self._runtime is not None:
                self._runtime.close()
            self._runtime = None
            self._visible_chat_contact = None

    def set_visible_chat_contact(self, username: str | None) -> None:
        normalized = str(username or "").strip().lower() or None
        with self._runtime_lock:
            self._visible_chat_contact = normalized

    def use_profile(self, profile_name: str, base_dir: str | Path | None = None) -> ClientRuntime:
        normalized_profile = normalize_profile_name(profile_name)
        normalized_base_dir = str(Path(base_dir).expanduser().resolve()) if base_dir else None
        with self._runtime_lock:
            if (
                self._runtime is None
                or self._profile_name != normalized_profile
                or self._base_dir != normalized_base_dir
            ):
                self.stop_listener()
                if self._runtime is not None:
                    self._runtime.close()
                self._runtime = ClientRuntime(profile_name=normalized_profile, base_dir=normalized_base_dir)
                self._profile_name = normalized_profile
                self._base_dir = normalized_base_dir
            return self._runtime

    def current_runtime(self) -> ClientRuntime:
        with self._runtime_lock:
            if self._runtime is None:
                raise ClientOperationError("Select or initialize a profile first.")
            return self._runtime

    def can_sync(self) -> bool:
        with self._runtime_lock:
            if self._runtime is None:
                return False
            try:
                self._runtime.session_token()
            except Exception:
                return False
            return True

    def register(
        self,
        *,
        profile_name: str,
        base_dir: str | Path | None,
        username: str,
        password: str,
        device_passphrase: str,
        bootstrap_path: str | Path | None = None,
        server_url: str | None = None,
        ca_cert_path: str | None = None,
    ) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.use_profile(profile_name, base_dir)
            return runtime.register(
                username=username,
                password=password,
                device_passphrase=device_passphrase,
                bootstrap_path=bootstrap_path,
                server_url=server_url,
                ca_cert_path=ca_cert_path,
            )

    def confirm_registration_otp(
        self,
        *,
        profile_name: str,
        base_dir: str | Path | None,
        username: str,
        password: str,
        otp_code: str,
        device_passphrase: str,
    ) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.use_profile(profile_name, base_dir)
            return runtime.confirm_registration_otp(username, password, otp_code, device_passphrase)

    def login(
        self,
        *,
        profile_name: str,
        base_dir: str | Path | None,
        username: str,
        password: str,
        otp_code: str,
        device_passphrase: str,
    ) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.use_profile(profile_name, base_dir)
            login_result = runtime.login(username, password, otp_code, device_passphrase)
            self.stop_listener()
            self.start_listener()
            sync_results = runtime.sync_queue()
            snapshot = self.refresh_snapshot()
            return {"login": login_result, "sync": sync_results, "snapshot": snapshot}

    def open_saved_session(
        self,
        *,
        profile_name: str,
        base_dir: str | Path | None,
        device_passphrase: str,
    ) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.use_profile(profile_name, base_dir)
            runtime.unlock(device_passphrase)
            me = runtime.me()
            self.stop_listener()
            self.start_listener()
            sync_results = runtime.sync_queue()
            snapshot = self.refresh_snapshot()
            return {"me": me, "sync": sync_results, "snapshot": snapshot}

    def logout(self) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            response = runtime.logout()
            self.stop_listener()
            return response

    def force_local_logout(self) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            response = runtime.force_local_logout()
            self.stop_listener()
            self._visible_chat_contact = None
            return response

    def identity_summary(self) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            config = runtime.server_config()
            session = runtime.session_info() or {}
            return {
                "profile_name": self._profile_name,
                "base_dir": self._base_dir,
                "username": runtime.username(),
                "server_url": config["server_url"],
                "ca_cert_path": config["ca_cert_path"],
                "active_fingerprint": runtime.active_key_fingerprint_display(),
                "session_expires_at": session.get("expires_at"),
            }

    def _snapshot_payload(self, runtime: ClientRuntime) -> dict[str, Any]:
        return {
            "contacts": runtime.list_contacts().get("contacts", []),
            "requests": runtime.list_requests(),
            "conversations": runtime.conversation_list(),
            "events": runtime.unresolved_security_events(),
            "identity": self.identity_summary(),
        }

    def _local_snapshot_payload(self, runtime: ClientRuntime) -> dict[str, Any]:
        return {
            "conversations": runtime.conversation_list(),
            "events": runtime.unresolved_security_events(),
            "identity": self.identity_summary(),
        }

    def refresh_snapshot(self) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return self._snapshot_payload(runtime)

    def refresh_local_snapshot(self) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return self._local_snapshot_payload(runtime)

    def sync_and_refresh_snapshot(self) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            results = runtime.sync_queue()
            return {"results": results, "snapshot": self._snapshot_payload(runtime)}

    def _history_context_payload(
        self,
        runtime: ClientRuntime,
        username: str,
        *,
        limit: int,
        mark_read: bool,
        include_unread: bool,
        include_conversations: bool,
    ) -> dict[str, Any]:
        rows, _ = runtime.history(
            username,
            limit=limit,
            before_local_id=None,
            mark_read=mark_read,
            include_unread=include_unread,
        )
        conversations = runtime.conversation_list() if include_conversations else None
        fingerprint: dict[str, Any] | None = None
        fingerprint_error: str | None = None
        try:
            info = runtime.fingerprint_info(username)
            fingerprint = {
                "username": info.username,
                "fingerprint": info.fingerprint,
                "display": info.display,
                "trust_state": info.trust_state,
                "verified": info.verified,
            }
        except Exception as exc:
            fingerprint_error = self.format_user_error(exc)
        return {
            "username": username.lower(),
            "rows": rows,
            "conversations": conversations,
            "fingerprint": fingerprint,
            "fingerprint_error": fingerprint_error,
        }

    def load_chat_context(self, username: str, limit: int = 20) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return self._history_context_payload(
                runtime,
                username,
                limit=limit,
                mark_read=True,
                include_unread=True,
                include_conversations=True,
            )

    def load_contact_history_context(self, username: str, limit: int = 50) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return self._history_context_payload(
                runtime,
                username,
                limit=limit,
                mark_read=False,
                include_unread=False,
                include_conversations=False,
            )

    def load_contacts(self) -> list[dict[str, Any]]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.list_contacts().get("contacts", [])

    def load_requests(self) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.list_requests()

    def sync_queue(self) -> list[dict[str, Any]]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.sync_queue()

    def send_friend_request(self, username: str, note: str | None = None) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.send_friend_request(username, note)

    def accept_request(self, request_id: int) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.accept_request(request_id)

    def decline_request(self, request_id: int) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.decline_request(request_id)

    def cancel_request(self, request_id: int) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.cancel_request(request_id)

    def block_user(self, username: str) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.block_user(username)

    def unblock_user(self, username: str) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.unblock_user(username)

    def remove_friend(self, username: str) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.remove_friend(username)

    def fingerprint_info(self, username: str) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            info = runtime.fingerprint_info(username)
            return {
                "username": info.username,
                "fingerprint": info.fingerprint,
                "display": info.display,
                "trust_state": info.trust_state,
                "verified": info.verified,
            }

    def verify_contact(self, username: str) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            info = runtime.verify_contact(username)
            return {
                "username": info.username,
                "fingerprint": info.fingerprint,
                "display": info.display,
                "trust_state": info.trust_state,
                "verified": info.verified,
            }

    def rotate_keys(self) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.rotate_keys()

    def send_text(self, username: str, text: str, ttl_seconds: int | None = None) -> dict[str, Any]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.send_text(username, text, ttl_seconds=ttl_seconds)

    def unresolved_security_events(self) -> list[dict[str, Any]]:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.unresolved_security_events()

    def next_expiry_at(self, contact_username: str | None = None) -> str | None:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.next_expiry_at(contact_username)

    def next_refresh_at(self, contact_username: str | None = None) -> str | None:
        with self._runtime_lock:
            runtime = self.current_runtime()
            return runtime.next_refresh_at(contact_username)

    def start_listener(self) -> None:
        with self._runtime_lock:
            runtime = self.current_runtime()
            if self._listener_thread is not None and self._listener_thread.is_alive():
                return
            self._listener_stop.clear()
            self._listener_thread = threading.Thread(
                target=self._listener_loop,
                args=(runtime,),
                name="cipherlink-gui-listener",
                daemon=True,
            )
            self._listener_thread.start()

    def stop_listener(self) -> None:
        self._listener_stop.set()
        thread = self._listener_thread
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2)
        self._listener_thread = None

    def _listener_loop(self, runtime: ClientRuntime) -> None:
        try:
            with self._runtime_lock:
                token = runtime.session_token()
                uri = f"{runtime.websocket_url()}?token={quote(token)}"
                ssl_context = runtime.websocket_ssl_context()
        except Exception as exc:
            self._emit("listener_status", level="error", message=self.format_user_error(exc))
            return

        while not self._listener_stop.is_set():
            try:
                with ws_connect(uri, ssl=ssl_context, ping_interval=20, ping_timeout=20, max_size=2**20) as websocket:
                    while not self._listener_stop.is_set():
                        try:
                            raw = websocket.recv(timeout=1)
                        except TimeoutError:
                            continue
                        event = json.loads(raw)
                        self._handle_listener_event(runtime, event)
            except Exception as exc:
                if not self._listener_stop.is_set():
                    if self.is_session_expired_error(exc):
                        self._emit("session_expired", message="HTTP 401: Session is invalid or expired.")
                        return
                    self._emit(
                        "listener_status",
                        level="warning",
                        message=f"Realtime connection lost. Reconnecting in 2 seconds: {self.format_user_error(exc)}",
                    )
                    time.sleep(2)

    def _handle_listener_event(self, runtime: ClientRuntime, event: dict[str, Any]) -> None:
        event_type = event.get("type")
        payload = event.get("payload", {})
        if event_type == "message":
            try:
                with self._runtime_lock:
                    result = runtime.process_envelope(
                        payload["envelope"],
                        visible_chat_contact=self._visible_chat_contact,
                        allow_immediate_read=True,
                    )
                result_type = result.get("type", "message_processed")
                if result_type == "duplicate":
                    return
                self._emit(result_type, **{k: v for k, v in result.items() if k != "type"})
                self._emit("local_snapshot_required")
            except Exception as exc:
                if self.is_session_expired_error(exc):
                    self._emit("session_expired", message="HTTP 401: Session is invalid or expired.")
                    return
                self._emit(
                    "listener_status",
                    level="error",
                    message=f"Failed to process incoming envelope: {self.format_user_error(exc)}",
                )
        elif event_type == "friend_request_received":
            self._emit(
                "friend_request_received",
                request_id=payload.get("request_id"),
                sender_username=payload.get("sender_username"),
                note=payload.get("note"),
            )
        elif event_type == "friend_request_updated":
            self._emit(
                "friend_request_updated",
                request_id=payload.get("request_id"),
                status=payload.get("status"),
                by=payload.get("by"),
            )
        elif event_type == "connected":
            pending_messages = int(payload.get("pending_messages") or 0)
            self._emit(
                "connected",
                username=payload.get("username"),
                pending_messages=pending_messages,
            )
            if pending_messages > 0:
                try:
                    with self._runtime_lock:
                        results = runtime.sync_queue()
                    self._emit("sync_results", results=results, source="auto")
                    self._emit("local_snapshot_required")
                except Exception as exc:
                    if self.is_session_expired_error(exc):
                        self._emit("session_expired", message="HTTP 401: Session is invalid or expired.")
                        return
                    self._emit(
                        "listener_status",
                        level="warning",
                        message=f"Automatic sync failed: {self.format_user_error(exc)}",
                    )
        elif event_type == "pong":
            return
        else:
            self._emit("listener_status", level="info", message=f"Server event {event_type}: {payload}")
