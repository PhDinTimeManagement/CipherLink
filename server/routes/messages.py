from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from server.dependencies import Services, get_current_user, get_services
from server.repositories import DuplicateError, NotFoundError, UnauthorizedError
from shared.protocol import ConsumeMessageRequest, MessageEnvelope, QueueResponse, SendMessageResponse
from shared.trust_logic import evaluate_contact_messaging_status, security_messaging_block_detail
from shared.utils import conversation_id_for_users

router = APIRouter(prefix="/api/v1/messages", tags=["messages"])


def _chat_block_detail(sender_username: str, receiver_username: str, *, sender_blocked_receiver: bool, receiver_blocked_sender: bool) -> str | None:
    if not sender_blocked_receiver and not receiver_blocked_sender:
        return None
    clauses: list[str] = []
    if sender_blocked_receiver:
        clauses.append(f"{sender_username} blocked {receiver_username}")
    if receiver_blocked_sender:
        clauses.append(f"{receiver_username} blocked {sender_username}")
    if len(clauses) == 2:
        clauses = sorted(clauses)
    return f"Messaging is disabled because {' and '.join(clauses)}."


@router.post("/send", response_model=SendMessageResponse)
async def send_message(
    envelope: MessageEnvelope,
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> SendMessageResponse:
    header = envelope.header
    if header.sender != current_user.username:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="The header sender does not match the authenticated user.")
    sender_bundle = services.repo.get_bundle_by_fingerprint(current_user.username, header.sender_key_fingerprint)
    if sender_bundle is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The sender key fingerprint is unknown to the server.")
    if header.kind == "chat" and header.sender_key_fingerprint != current_user.active_key_fingerprint:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Chat messages must use the authenticated user's current active key fingerprint.")
    if header.receiver == current_user.username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Self-messaging is not allowed in this project.")
    expected_conversation_id = conversation_id_for_users(header.sender, header.receiver)
    if expected_conversation_id != header.conversation_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Conversation identifier does not match the sender/receiver pair.")
    receiver = services.repo.get_user_by_username(header.receiver)
    if receiver is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Receiver not found.")
    receiver_bundle = services.repo.get_bundle_by_fingerprint(header.receiver, header.receiver_key_fingerprint)
    if receiver_bundle is None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Receiver key fingerprint is unknown to the server.")
    if len(envelope.ciphertext.encode("utf-8")) + len(envelope.nonce.encode("utf-8")) > services.settings.max_ciphertext_bytes:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Envelope exceeds the maximum ciphertext size.")
    if header.kind == "chat":
        if header.related_message_id is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Chat messages must not include related_message_id.")
        block_relationship = services.repo.block_relationship(current_user.id, int(receiver["id"]))
        block_detail = _chat_block_detail(
            current_user.username,
            header.receiver,
            sender_blocked_receiver=block_relationship["user_a_blocked_user_b"],
            receiver_blocked_sender=block_relationship["user_b_blocked_user_a"],
        )
        if block_detail is not None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=block_detail)
        if not services.repo.are_friends(current_user.id, int(receiver["id"])):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only accepted friends may exchange chat messages.")
        verification_states = services.repo.verification_states_for_pair(current_user.id, int(receiver["id"]))
        verification_gate = evaluate_contact_messaging_status(
            {
                "friendship_status": "accepted",
                "blocked_by_me": False,
                "blocked_me": False,
                **verification_states,
            }
        )
        if verification_gate.blocked:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=security_messaging_block_detail(verification_gate),
            )
    else:
        if header.related_message_id is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Delivery acknowledgements must reference a related message.")
        original = services.repo.get_message_parties(header.related_message_id)
        if original is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Related message not found.")
        if int(original["receiver_id"]) != current_user.id or int(original["sender_id"]) != int(receiver["id"]):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Delivery acknowledgement does not match the original message participants.")
    try:
        row = services.repo.insert_message(current_user.id, int(receiver["id"]), envelope.model_dump(mode="json"))
    except DuplicateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    receiver_online = await services.ws_manager.is_online(int(receiver["id"]))
    if receiver_online:
        pushed = await services.ws_manager.send_to_user(
            int(receiver["id"]),
            "message",
            {
                "envelope": {
                    **envelope.model_dump(mode="json"),
                    "submitted_at": row["submitted_at"],
                    "canonical_expires_at": row["canonical_expires_at"],
                }
            },
        )
        if pushed:
            services.repo.mark_message_pushed(header.message_id)
    return SendMessageResponse(
        message="Ciphertext accepted by the server.",
        submitted_at=row["submitted_at"],
        canonical_expires_at=row["canonical_expires_at"],
        receiver_online=receiver_online,
    )


@router.get("/queue", response_model=QueueResponse)
async def fetch_queue(
    services: Services = Depends(get_services),
    current_user=Depends(get_current_user),
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None),
) -> QueueResponse:
    rows = services.repo.fetch_pending_messages(current_user.id, limit=limit, cursor=cursor)
    rows = list(reversed(rows))
    user_map = services.repo.usernames_for_ids(
        sorted({int(row["sender_id"]) for row in rows} | {int(row["receiver_id"]) for row in rows})
    )
    envelopes: list[MessageEnvelope] = []
    next_cursor = None
    for row in rows:
        envelopes.append(
            MessageEnvelope(
                header={
                    "payload_version": int(row["payload_version"]),
                    "message_id": row["message_id"],
                    "conversation_id": row["conversation_id"],
                    "sender": user_map[int(row["sender_id"])],
                    "receiver": user_map[int(row["receiver_id"])],
                    "kind": row["kind"],
                    "counter": int(row["counter"]),
                    "sender_key_fingerprint": row["sender_key_fingerprint"],
                    "receiver_key_fingerprint": row["receiver_key_fingerprint"],
                    "created_at": row["created_at"],
                    "expires_at": row["expires_at"],
                    "ttl_seconds": row["ttl_seconds"],
                    "related_message_id": row["related_message_id"],
                },
                nonce=row["nonce"],
                ciphertext=row["ciphertext"],
                submitted_at=row["submitted_at"],
                canonical_expires_at=row["canonical_expires_at"],
            )
        )
    if len(rows) == limit:
        next_cursor = rows[0]["submitted_at"] if rows else None
    return QueueResponse(messages=envelopes, next_cursor=next_cursor)


@router.post("/consume")
async def consume_message(
    payload: ConsumeMessageRequest,
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> dict[str, str]:
    try:
        services.repo.consume_message(current_user.id, payload.message_id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return {"message": "Envelope marked as consumed and removed from the offline queue."}
