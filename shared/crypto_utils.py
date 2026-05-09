from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from shared.protocol import MessageEnvelope, MessageHeader, PublicKeyBundle
from shared.utils import b64d, b64e, canonical_json, sha256_bytes, sha256_hex


RAW = serialization.Encoding.Raw
PRIVATE = serialization.PrivateFormat.Raw
PUBLIC = serialization.PublicFormat.Raw
NO_ENCRYPTION = serialization.NoEncryption()


@dataclass
class LocalKeyPair:
    identity_private_key: bytes
    identity_public_key: bytes
    chat_private_key: bytes
    chat_public_key: bytes
    signature: bytes
    fingerprint: str

    def as_public_bundle(self, username: str, created_at: str | None = None, is_active: bool = True) -> PublicKeyBundle:
        return PublicKeyBundle(
            username=username,
            fingerprint=self.fingerprint,
            identity_public_key=b64e(self.identity_public_key),
            chat_public_key=b64e(self.chat_public_key),
            signature=b64e(self.signature),
            created_at=created_at,
            is_active=is_active,
        )


@dataclass
class VerifiedBundle:
    username: str
    fingerprint: str
    identity_public_key: bytes
    chat_public_key: bytes
    signature: bytes
    is_active: bool = True


class CryptoError(Exception):
    pass


class DuplicateEnvelopeError(CryptoError):
    pass


class KeyChangeDetectedError(CryptoError):
    pass


class BundleVerificationError(CryptoError):
    pass


class EnvelopeValidationError(CryptoError):
    pass


MESSAGE_INFO_PREFIX = b"cipherlink-msg-v1"
ROOT_INFO = b"cipherlink-root-v1"
LOCAL_INFO = b"cipherlink-local-v1"



def generate_local_keypair() -> LocalKeyPair:
    identity_private = ed25519.Ed25519PrivateKey.generate()
    chat_private = x25519.X25519PrivateKey.generate()
    identity_private_bytes = identity_private.private_bytes(RAW, PRIVATE, NO_ENCRYPTION)
    identity_public_bytes = identity_private.public_key().public_bytes(RAW, PUBLIC)
    chat_private_bytes = chat_private.private_bytes(RAW, PRIVATE, NO_ENCRYPTION)
    chat_public_bytes = chat_private.public_key().public_bytes(RAW, PUBLIC)
    signature = identity_private.sign(chat_public_bytes)
    fingerprint = compute_bundle_fingerprint(identity_public_bytes, chat_public_bytes)
    return LocalKeyPair(
        identity_private_key=identity_private_bytes,
        identity_public_key=identity_public_bytes,
        chat_private_key=chat_private_bytes,
        chat_public_key=chat_public_bytes,
        signature=signature,
        fingerprint=fingerprint,
    )



def compute_bundle_fingerprint(identity_public_key: bytes, chat_public_key: bytes) -> str:
    return sha256_hex(identity_public_key + chat_public_key)



def verify_bundle(bundle: PublicKeyBundle | dict[str, Any]) -> VerifiedBundle:
    if not isinstance(bundle, PublicKeyBundle):
        bundle = PublicKeyBundle(**bundle)
    identity_public = b64d(bundle.identity_public_key)
    chat_public = b64d(bundle.chat_public_key)
    signature = b64d(bundle.signature)
    expected_fingerprint = compute_bundle_fingerprint(identity_public, chat_public)
    if expected_fingerprint != bundle.fingerprint:
        raise BundleVerificationError("Bundle fingerprint mismatch.")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(identity_public).verify(signature, chat_public)
    except Exception as exc:  # pragma: no cover - exact exception type is backend-specific
        raise BundleVerificationError("Bundle signature verification failed.") from exc
    return VerifiedBundle(
        username=bundle.username,
        fingerprint=bundle.fingerprint,
        identity_public_key=identity_public,
        chat_public_key=chat_public,
        signature=signature,
        is_active=bundle.is_active,
    )



def canonical_header_bytes(header: MessageHeader | dict[str, Any]) -> bytes:
    if isinstance(header, MessageHeader):
        data = header.model_dump(mode="json", exclude_none=False)
    else:
        data = MessageHeader(**header).model_dump(mode="json", exclude_none=False)
    return canonical_json(data)



def derive_root_key(
    our_chat_private_key: bytes,
    peer_chat_public_key: bytes,
    conversation_id: str,
    our_fingerprint: str,
    peer_fingerprint: str,
) -> bytes:
    private_key = x25519.X25519PrivateKey.from_private_bytes(our_chat_private_key)
    public_key = x25519.X25519PublicKey.from_public_bytes(peer_chat_public_key)
    shared_secret = private_key.exchange(public_key)
    ordered = "|".join(sorted([our_fingerprint, peer_fingerprint]))
    salt = sha256_bytes(f"{conversation_id}|{ordered}".encode("utf-8"))
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=ROOT_INFO)
    return hkdf.derive(shared_secret)



def derive_message_key(root_key: bytes, header: MessageHeader | dict[str, Any]) -> bytes:
    if not isinstance(header, MessageHeader):
        header = MessageHeader(**header)
    info = (
        f"{header.payload_version}|{header.message_id}|{header.sender}|{header.receiver}|"
        f"{header.kind}|{header.counter}|{header.sender_key_fingerprint}|{header.receiver_key_fingerprint}"
    ).encode("utf-8")
    salt = sha256_bytes(canonical_header_bytes(header))
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=MESSAGE_INFO_PREFIX + b"|" + info)
    return hkdf.derive(root_key)



def encrypt_payload(
    payload: dict[str, Any],
    header: MessageHeader,
    our_chat_private_key: bytes,
    peer_chat_public_key: bytes,
) -> tuple[str, str]:
    root_key = derive_root_key(
        our_chat_private_key=our_chat_private_key,
        peer_chat_public_key=peer_chat_public_key,
        conversation_id=header.conversation_id,
        our_fingerprint=header.sender_key_fingerprint,
        peer_fingerprint=header.receiver_key_fingerprint,
    )
    message_key = derive_message_key(root_key, header)
    aad = canonical_header_bytes(header)
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(message_key)
    ciphertext = cipher.encrypt(nonce, canonical_json(payload), aad)
    return b64e(nonce), b64e(ciphertext)



def decrypt_payload(
    envelope: MessageEnvelope | dict[str, Any],
    our_chat_private_key: bytes,
    peer_chat_public_key: bytes,
) -> dict[str, Any]:
    if not isinstance(envelope, MessageEnvelope):
        envelope = MessageEnvelope(**envelope)
    header = envelope.header
    root_key = derive_root_key(
        our_chat_private_key=our_chat_private_key,
        peer_chat_public_key=peer_chat_public_key,
        conversation_id=header.conversation_id,
        our_fingerprint=header.receiver_key_fingerprint,
        peer_fingerprint=header.sender_key_fingerprint,
    )
    message_key = derive_message_key(root_key, header)
    cipher = ChaCha20Poly1305(message_key)
    plaintext = cipher.decrypt(b64d(envelope.nonce), b64d(envelope.ciphertext), canonical_header_bytes(header))
    return json.loads(plaintext.decode("utf-8"))



def encrypt_local_blob(storage_key: bytes, payload: dict[str, Any], aad: bytes | None = None) -> tuple[str, str]:
    nonce = os.urandom(12)
    cipher = ChaCha20Poly1305(storage_key)
    ciphertext = cipher.encrypt(nonce, canonical_json(payload), aad)
    return b64e(nonce), b64e(ciphertext)



def decrypt_local_blob(storage_key: bytes, nonce_b64: str, ciphertext_b64: str, aad: bytes | None = None) -> dict[str, Any]:
    cipher = ChaCha20Poly1305(storage_key)
    plaintext = cipher.decrypt(b64d(nonce_b64), b64d(ciphertext_b64), aad)
    return json.loads(plaintext.decode("utf-8"))



def random_message_id() -> str:
    return secrets.token_hex(16)
