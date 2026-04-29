from __future__ import annotations

from pathlib import Path
from typing import Any
import ssl

import httpx

from shared.protocol import (
    ActionByUsernameRequest,
    ContactVerificationRequest,
    ConsumeMessageRequest,
    FriendRequestCreate,
    LoginRequest,
    MessageEnvelope,
    PublicKeyBundle,
    RegisterRequest,
    RegistrationOTPConfirmRequest,
)


class APIError(Exception):
    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class ServerAPI:
    def __init__(
        self,
        server_url: str,
        ca_cert_path: str | Path | bool,
        token: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        verify: ssl.SSLContext | bool
        if isinstance(ca_cert_path, (str, Path)):
            verify = ssl.create_default_context(cafile=str(ca_cert_path))
        else:
            verify = ca_cert_path
        self.client = httpx.Client(
            base_url=server_url.rstrip("/"),
            verify=verify,
            timeout=20.0,
            transport=transport,
            follow_redirects=False,
        )
        self.token = token

    def close(self) -> None:
        self.client.close()

    def set_token(self, token: str | None) -> None:
        self.token = token

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(self, method: str, path: str, *, json_payload: dict[str, Any] | None = None, params: dict[str, Any] | None = None) -> Any:
        response = self.client.request(method, path, headers=self._headers(), json=json_payload, params=params)
        if response.status_code >= 400:
            detail = response.text
            try:
                detail = response.json().get("detail", detail)
            except Exception:
                pass
            raise APIError(response.status_code, detail)
        if response.content:
            return response.json()
        return None

    def register(self, payload: RegisterRequest) -> dict[str, Any]:
        return self._request("POST", "/api/v1/auth/register", json_payload=payload.model_dump(mode="json"))

    def confirm_registration_otp(self, payload: RegistrationOTPConfirmRequest) -> dict[str, Any]:
        return self._request("POST", "/api/v1/auth/register/confirm-otp", json_payload=payload.model_dump(mode="json"))

    def login(self, payload: LoginRequest) -> dict[str, Any]:
        return self._request("POST", "/api/v1/auth/login", json_payload=payload.model_dump(mode="json"))

    def logout(self) -> dict[str, Any]:
        return self._request("POST", "/api/v1/auth/logout")

    def me(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/auth/me")

    def get_current_bundle(self, username: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/keys/current/{username}")

    def get_bundle_by_fingerprint(self, username: str, fingerprint: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/keys/by-fingerprint/{username}/{fingerprint}")

    def rotate_keys(self, bundle: PublicKeyBundle) -> dict[str, Any]:
        return self._request("POST", "/api/v1/keys/rotate", json_payload=bundle.model_dump(mode="json"))

    def send_friend_request(self, username: str, note: str | None = None) -> dict[str, Any]:
        payload = FriendRequestCreate(target_username=username, note=note)
        return self._request("POST", "/api/v1/contacts/requests", json_payload=payload.model_dump(mode="json"))

    def list_friend_requests(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/contacts/requests")

    def accept_friend_request(self, request_id: int) -> dict[str, Any]:
        return self._request("POST", f"/api/v1/contacts/requests/{request_id}/accept")

    def decline_friend_request(self, request_id: int) -> dict[str, Any]:
        return self._request("POST", f"/api/v1/contacts/requests/{request_id}/decline")

    def cancel_friend_request(self, request_id: int) -> dict[str, Any]:
        return self._request("POST", f"/api/v1/contacts/requests/{request_id}/cancel")

    def list_contacts(self) -> dict[str, Any]:
        return self._request("GET", "/api/v1/contacts")

    def verify_contact(self, username: str, fingerprint: str) -> dict[str, Any]:
        payload = ContactVerificationRequest(username=username, fingerprint=fingerprint)
        return self._request("POST", "/api/v1/contacts/verify", json_payload=payload.model_dump(mode="json"))

    def block_user(self, username: str) -> dict[str, Any]:
        payload = ActionByUsernameRequest(username=username)
        return self._request("POST", "/api/v1/contacts/block", json_payload=payload.model_dump(mode="json"))

    def unblock_user(self, username: str) -> dict[str, Any]:
        payload = ActionByUsernameRequest(username=username)
        return self._request("POST", "/api/v1/contacts/unblock", json_payload=payload.model_dump(mode="json"))

    def remove_friend(self, username: str) -> dict[str, Any]:
        payload = ActionByUsernameRequest(username=username)
        return self._request("POST", "/api/v1/contacts/remove", json_payload=payload.model_dump(mode="json"))

    def send_envelope(self, envelope: MessageEnvelope) -> dict[str, Any]:
        return self._request("POST", "/api/v1/messages/send", json_payload=envelope.model_dump(mode="json"))

    def fetch_queue(self, limit: int = 50, cursor: str | None = None) -> dict[str, Any]:
        params = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._request("GET", "/api/v1/messages/queue", params=params)

    def consume_message(self, message_id: str) -> dict[str, Any]:
        payload = ConsumeMessageRequest(message_id=message_id)
        return self._request("POST", "/api/v1/messages/consume", json_payload=payload.model_dump(mode="json"))
