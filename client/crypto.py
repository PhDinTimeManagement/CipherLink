from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from shared.crypto_utils import (
    LocalKeyPair,
    decrypt_payload,
    encrypt_payload,
    generate_local_keypair,
    random_message_id,
    verify_bundle,
)
from shared.protocol import MessageEnvelope, MessageHeader, PublicKeyBundle
from shared.utils import conversation_id_for_users, isoformat_z, utc_now


@dataclass(slots=True)
class PreparedEnvelope:
    envelope: MessageEnvelope
    plaintext_payload: dict[str, Any]



def create_keypair() -> LocalKeyPair:
    return generate_local_keypair()



def prepare_chat_envelope(
    *,
    sender_username: str,
    receiver_username: str,
    sender_key_fingerprint: str,
    receiver_key_fingerprint: str,
    counter: int,
    text: str,
    ttl_seconds: int | None,
    sender_private_chat_key: bytes,
    receiver_public_chat_key: bytes,
) -> PreparedEnvelope:
    created_at_dt = utc_now()
    created_at = isoformat_z(created_at_dt)
    expires_at = isoformat_z(created_at_dt + timedelta(seconds=ttl_seconds)) if ttl_seconds else None
    header = MessageHeader(
        payload_version=1,
        message_id=random_message_id(),
        conversation_id=conversation_id_for_users(sender_username, receiver_username),
        sender=sender_username,
        receiver=receiver_username,
        kind="chat",
        counter=counter,
        sender_key_fingerprint=sender_key_fingerprint,
        receiver_key_fingerprint=receiver_key_fingerprint,
        created_at=created_at,
        expires_at=expires_at,
        ttl_seconds=ttl_seconds,
        related_message_id=None,
    )
    payload = {"text": text}
    nonce, ciphertext = encrypt_payload(payload, header, sender_private_chat_key, receiver_public_chat_key)
    return PreparedEnvelope(envelope=MessageEnvelope(header=header, nonce=nonce, ciphertext=ciphertext), plaintext_payload=payload)



def prepare_delivery_ack_envelope(
    *,
    sender_username: str,
    receiver_username: str,
    sender_key_fingerprint: str,
    receiver_key_fingerprint: str,
    counter: int,
    related_message_id: str,
    sender_private_chat_key: bytes,
    receiver_public_chat_key: bytes,
) -> PreparedEnvelope:
    created_at = isoformat_z(utc_now())
    header = MessageHeader(
        payload_version=1,
        message_id=random_message_id(),
        conversation_id=conversation_id_for_users(sender_username, receiver_username),
        sender=sender_username,
        receiver=receiver_username,
        kind="delivery_ack",
        counter=counter,
        sender_key_fingerprint=sender_key_fingerprint,
        receiver_key_fingerprint=receiver_key_fingerprint,
        created_at=created_at,
        expires_at=None,
        ttl_seconds=None,
        related_message_id=related_message_id,
    )
    payload = {"ack_for": related_message_id, "received_at": created_at}
    nonce, ciphertext = encrypt_payload(payload, header, sender_private_chat_key, receiver_public_chat_key)
    return PreparedEnvelope(envelope=MessageEnvelope(header=header, nonce=nonce, ciphertext=ciphertext), plaintext_payload=payload)



def decrypt_envelope(envelope: MessageEnvelope, our_private_chat_key: bytes, peer_public_chat_key: bytes) -> dict[str, Any]:
    return decrypt_payload(envelope, our_private_chat_key, peer_public_chat_key)



def verified_bundle(bundle: PublicKeyBundle | dict[str, Any]):
    return verify_bundle(bundle)
