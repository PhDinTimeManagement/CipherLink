from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from server.dependencies import Services, get_current_user, get_services, request_ip
from server.repositories import ConflictError, NotFoundError, UnauthorizedError
from shared.protocol import (
    ActionByUsernameRequest,
    ContactRecord,
    ContactVerificationRequest,
    ContactsResponse,
    FriendRequestCreate,
    FriendRequestRecord,
    GenericMessage,
    RequestsResponse,
)

router = APIRouter(prefix="/api/v1/contacts", tags=["contacts"])


@router.get("", response_model=ContactsResponse, response_model_exclude_none=True)
async def list_contacts(
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> ContactsResponse:
    contacts = services.repo.list_contacts(current_user.id)
    return ContactsResponse(contacts=[ContactRecord(**row) for row in contacts])


@router.post("/verify", response_model=GenericMessage)
async def verify_contact(
    payload: ContactVerificationRequest,
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> GenericMessage:
    target = services.repo.get_user_by_username(payload.username)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found.")
    try:
        services.repo.record_contact_verification(current_user.id, int(target["id"]), payload.fingerprint)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except UnauthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    return GenericMessage(message=f"Recorded verification for {target['username']}'s current safety number.")


@router.post("/requests", response_model=FriendRequestRecord)
async def send_friend_request(
    request: Request,
    payload: FriendRequestCreate,
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> FriendRequestRecord:
    ip = request_ip(request)
    limit_key = f"friend-request:{ip}:{current_user.username}"
    result = services.rate_limiter.allow(limit_key, limit=services.settings.max_friend_requests_per_hour, window_seconds=3600)
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many friend requests. Retry in {result.retry_after_seconds} seconds.",
        )
    target = services.repo.get_user_by_username(payload.target_username)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found.")
    try:
        record = services.repo.create_friend_request(current_user.id, int(target["id"]), payload.note)
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except UnauthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    await services.ws_manager.send_to_user(
        int(target["id"]),
        "friend_request_received",
        {
            "request_id": record["id"],
            "sender_username": current_user.username,
            "note": payload.note,
        },
    )
    return FriendRequestRecord(
        request_id=int(record["id"]),
        sender_username=record["sender_username"],
        receiver_username=record["receiver_username"],
        status=record["status"],
        note=record["note"],
        created_at=record["created_at"],
        updated_at=record["updated_at"],
    )


@router.get("/requests", response_model=RequestsResponse)
async def list_friend_requests(
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> RequestsResponse:
    records = services.repo.list_friend_requests(current_user.id)
    incoming = [
        FriendRequestRecord(
            request_id=int(row["id"]),
            sender_username=row["sender_username"],
            receiver_username=row["receiver_username"],
            status=row["status"],
            note=row["note"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
        for row in records["incoming"]
    ]
    outgoing = [
        FriendRequestRecord(
            request_id=int(row["id"]),
            sender_username=row["sender_username"],
            receiver_username=row["receiver_username"],
            status=row["status"],
            note=row["note"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )
        for row in records["outgoing"]
    ]
    return RequestsResponse(incoming=incoming, outgoing=outgoing)


@router.post("/requests/{request_id}/accept", response_model=FriendRequestRecord)
async def accept_friend_request(
    request_id: int,
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> FriendRequestRecord:
    try:
        record = services.repo.accept_friend_request(request_id, current_user.id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except UnauthorizedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    sender = services.repo.get_user_by_username(record["sender_username"])
    if sender:
        await services.ws_manager.send_to_user(
            int(sender["id"]),
            "friend_request_updated",
            {"request_id": request_id, "status": "accepted", "by": current_user.username},
        )
    return FriendRequestRecord(
        request_id=int(record["id"]),
        sender_username=record["sender_username"],
        receiver_username=record["receiver_username"],
        status=record["status"],
        note=record["note"],
        created_at=record["created_at"],
        updated_at=record["updated_at"],
    )


@router.post("/requests/{request_id}/decline", response_model=FriendRequestRecord)
async def decline_friend_request(
    request_id: int,
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> FriendRequestRecord:
    try:
        record = services.repo.decline_friend_request(request_id, current_user.id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    sender = services.repo.get_user_by_username(record["sender_username"])
    if sender:
        await services.ws_manager.send_to_user(
            int(sender["id"]),
            "friend_request_updated",
            {"request_id": request_id, "status": "declined", "by": current_user.username},
        )
    return FriendRequestRecord(
        request_id=int(record["id"]),
        sender_username=record["sender_username"],
        receiver_username=record["receiver_username"],
        status=record["status"],
        note=record["note"],
        created_at=record["created_at"],
        updated_at=record["updated_at"],
    )


@router.post("/requests/{request_id}/cancel", response_model=FriendRequestRecord)
async def cancel_friend_request(
    request_id: int,
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> FriendRequestRecord:
    try:
        record = services.repo.cancel_friend_request(request_id, current_user.id)
    except NotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    receiver = services.repo.get_user_by_username(record["receiver_username"])
    if receiver:
        await services.ws_manager.send_to_user(
            int(receiver["id"]),
            "friend_request_updated",
            {"request_id": request_id, "status": "cancelled", "by": current_user.username},
        )
    return FriendRequestRecord(
        request_id=int(record["id"]),
        sender_username=record["sender_username"],
        receiver_username=record["receiver_username"],
        status=record["status"],
        note=record["note"],
        created_at=record["created_at"],
        updated_at=record["updated_at"],
    )


@router.post("/block", response_model=GenericMessage)
async def block_user(
    payload: ActionByUsernameRequest,
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> GenericMessage:
    target = services.repo.get_user_by_username(payload.username)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found.")
    try:
        services.repo.block_user(current_user.id, int(target["id"]))
    except ConflictError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return GenericMessage(message=f"Blocked {target['username']}. Existing contacts stay in place; messaging is disabled until the block is removed.")


@router.post("/unblock", response_model=GenericMessage)
async def unblock_user(
    payload: ActionByUsernameRequest,
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> GenericMessage:
    target = services.repo.get_user_by_username(payload.username)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found.")
    services.repo.unblock_user(current_user.id, int(target["id"]))
    return GenericMessage(message=f"Unblocked {target['username']}. Messaging resumes only if they have not also blocked you.")


@router.post("/remove", response_model=GenericMessage)
async def remove_friend(
    payload: ActionByUsernameRequest,
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> GenericMessage:
    target = services.repo.get_contact_by_username(current_user.id, payload.username)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target user not found.")
    services.repo.remove_friend(current_user.id, int(target["id"]))
    return GenericMessage(message=f"Removed {target['username']} from your contacts.")
