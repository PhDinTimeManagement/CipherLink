from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


USERNAME_REGEX = r"^[A-Za-z0-9_.-]{3,32}$"
MAX_NOTE_LENGTH = 256
MAX_MESSAGE_TEXT_LENGTH = 4000
MAX_ENVELOPE_B64_LENGTH = 65536


class PublicKeyBundle(BaseModel):
    username: str = Field(pattern=USERNAME_REGEX)
    fingerprint: str = Field(min_length=64, max_length=64)
    identity_public_key: str = Field(min_length=40, max_length=200)
    chat_public_key: str = Field(min_length=40, max_length=200)
    signature: str = Field(min_length=40, max_length=200)
    created_at: Optional[str] = None
    is_active: bool = True


class ClientBootstrap(BaseModel):
    version: int = Field(default=1, ge=1, le=1)
    server_url: str = Field(min_length=8, max_length=512)
    ca_cert_filename: str = Field(min_length=1, max_length=256)
    ca_cert_sha256: str = Field(min_length=64, max_length=64)
    created_at: str
    description: Optional[str] = Field(default=None, max_length=256)

    @field_validator("server_url")
    @classmethod
    def validate_server_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value.startswith("https://"):
            raise ValueError("server_url must use https://")
        return value

    @field_validator("ca_cert_sha256")
    @classmethod
    def validate_ca_cert_sha256(cls, value: str) -> str:
        value = value.lower()
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("ca_cert_sha256 must be a 64-character lowercase hex string")
        return value


class RegisterRequest(BaseModel):
    username: str = Field(pattern=USERNAME_REGEX)
    password: str = Field(min_length=10, max_length=256)
    bundle: PublicKeyBundle


class RegisterResponse(BaseModel):
    username: str
    otp_provisioning_uri: str
    otp_secret_base32: str
    message: str


class RegistrationOTPConfirmRequest(BaseModel):
    username: str = Field(pattern=USERNAME_REGEX)
    password: str = Field(min_length=10, max_length=256)
    otp_code: str = Field(min_length=6, max_length=8)


class LoginRequest(BaseModel):
    username: str = Field(pattern=USERNAME_REGEX)
    password: str = Field(min_length=10, max_length=256)
    otp_code: str = Field(min_length=6, max_length=8)


class LoginResponse(BaseModel):
    token: str
    expires_at: str
    username: str
    active_key_fingerprint: str


class GenericMessage(BaseModel):
    message: str


class FriendRequestCreate(BaseModel):
    target_username: str = Field(pattern=USERNAME_REGEX)
    note: Optional[str] = Field(default=None, max_length=MAX_NOTE_LENGTH)


class FriendRequestRecord(BaseModel):
    request_id: int
    sender_username: str
    receiver_username: str
    status: str
    note: Optional[str]
    created_at: str
    updated_at: str


class RequestsResponse(BaseModel):
    incoming: list[FriendRequestRecord]
    outgoing: list[FriendRequestRecord]


class ContactRecord(BaseModel):
    username: str
    friendship_status: Literal["accepted", "removed"]
    blocked_by_me: bool
    blocked_me: bool
    since: str
    my_verification_state: Literal["missing", "verified", "identity_changed"] = "missing"
    friend_verification_state: Literal["missing", "verified", "identity_changed"] = "missing"
    initial_note: Optional[str] = None
    initial_note_created_at: Optional[str] = None
    initial_note_direction: Optional[Literal["in", "out"]] = None


class ContactsResponse(BaseModel):
    contacts: list[ContactRecord]


class ContactVerificationRequest(BaseModel):
    username: str = Field(pattern=USERNAME_REGEX)
    fingerprint: str = Field(min_length=64, max_length=64)


class ActionByUsernameRequest(BaseModel):
    username: str = Field(pattern=USERNAME_REGEX)


class MessageHeader(BaseModel):
    payload_version: int = Field(default=1, ge=1, le=1)
    message_id: str = Field(min_length=32, max_length=128)
    conversation_id: str = Field(min_length=32, max_length=64)
    sender: str = Field(pattern=USERNAME_REGEX)
    receiver: str = Field(pattern=USERNAME_REGEX)
    kind: Literal["chat", "delivery_ack"]
    counter: int = Field(ge=1)
    sender_key_fingerprint: str = Field(min_length=64, max_length=64)
    receiver_key_fingerprint: str = Field(min_length=64, max_length=64)
    created_at: str
    expires_at: Optional[str] = None
    ttl_seconds: Optional[int] = Field(default=None, ge=1, le=86400)
    related_message_id: Optional[str] = Field(default=None, min_length=32, max_length=128)

    @field_validator("expires_at")
    @classmethod
    def validate_expiry_relationship(cls, value: str | None, info):
        ttl_seconds = info.data.get("ttl_seconds")
        if ttl_seconds is None and value is not None:
            return value
        return value


class MessageEnvelope(BaseModel):
    header: MessageHeader
    nonce: str = Field(min_length=12, max_length=256)
    ciphertext: str = Field(min_length=12, max_length=MAX_ENVELOPE_B64_LENGTH)
    submitted_at: Optional[str] = None
    canonical_expires_at: Optional[str] = None


class SendMessageResponse(BaseModel):
    message: str
    submitted_at: str
    canonical_expires_at: Optional[str] = None
    receiver_online: bool


class QueueResponse(BaseModel):
    messages: list[MessageEnvelope]
    next_cursor: Optional[str] = None


class ConsumeMessageRequest(BaseModel):
    message_id: str = Field(min_length=32, max_length=128)


class ServerEvent(BaseModel):
    type: Literal[
        "friend_request_received",
        "friend_request_updated",
        "message",
        "security_notice",
        "pong",
        "connected",
    ]
    payload: dict
