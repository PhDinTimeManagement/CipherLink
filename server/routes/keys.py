from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status

from server.dependencies import Services, get_current_user, get_services
from server.repositories import DuplicateError
from shared.crypto_utils import BundleVerificationError, verify_bundle
from shared.protocol import GenericMessage, PublicKeyBundle

router = APIRouter(prefix="/api/v1/keys", tags=["keys"])


@router.get("/current/{username}", response_model=PublicKeyBundle)
async def get_current_bundle(
    username: str,
    services: Annotated[Services, Depends(get_services)],
    _current_user=Depends(get_current_user),
) -> PublicKeyBundle:
    bundle = services.repo.get_active_bundle(username)
    if bundle is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User or active key bundle not found.")
    return PublicKeyBundle(**bundle)


@router.get("/by-fingerprint/{username}/{fingerprint}", response_model=PublicKeyBundle)
async def get_bundle_by_fingerprint(
    username: str,
    fingerprint: str,
    services: Annotated[Services, Depends(get_services)],
    _current_user=Depends(get_current_user),
) -> PublicKeyBundle:
    bundle = services.repo.get_bundle_by_fingerprint(username, fingerprint)
    if bundle is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Key bundle not found.")
    return PublicKeyBundle(**bundle)


@router.post("/rotate", response_model=GenericMessage)
async def rotate_keys(
    payload: PublicKeyBundle,
    services: Annotated[Services, Depends(get_services)],
    current_user=Depends(get_current_user),
) -> GenericMessage:
    normalized_username = services.repo.normalize_username(payload.username)
    if normalized_username != current_user.username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Bundle username does not match the authenticated user.")
    if payload.fingerprint == current_user.active_key_fingerprint:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="The uploaded bundle is already active.")
    try:
        verify_bundle(payload)
        services.repo.add_key_bundle(current_user.id, payload.model_copy(update={"username": normalized_username}))
    except BundleVerificationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except DuplicateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return GenericMessage(message="Active key bundle rotated. Contacts should verify the new fingerprint.")
