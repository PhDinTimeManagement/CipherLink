from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from server.dependencies import Services, get_current_user, get_services, request_ip
from server.repositories import ConflictError, DuplicateError
from shared.crypto_utils import BundleVerificationError, verify_bundle
from shared.protocol import (
    GenericMessage,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    RegistrationOTPConfirmRequest,
)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register", response_model=RegisterResponse)
async def register(
    request: Request,
    payload: RegisterRequest,
    services: Annotated[Services, Depends(get_services)],
) -> RegisterResponse:
    ip = request_ip(request)
    result = services.rate_limiter.allow(f"register:{ip}", limit=5, window_seconds=300)
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many registration attempts. Retry in {result.retry_after_seconds} seconds.",
        )
    normalized_username = services.repo.normalize_username(payload.username)
    if services.repo.normalize_username(payload.bundle.username) != normalized_username:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Bundle username does not match request username.")
    try:
        verify_bundle(payload.bundle)
    except BundleVerificationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    try:
        password_hash = services.security.hash_password(payload.password)
        otp_secret = services.otp.generate_secret()
        otp_nonce, otp_ciphertext = services.security.encrypt_secret(otp_secret)
        services.repo.create_user(
            username=normalized_username,
            password_hash=password_hash,
            otp_secret_ciphertext=otp_ciphertext,
            otp_secret_nonce=otp_nonce,
            bundle=payload.bundle.model_copy(update={"username": normalized_username}),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except DuplicateError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    provisioning_uri = services.otp.provisioning_uri(otp_secret, normalized_username)
    return RegisterResponse(
        username=normalized_username,
        otp_provisioning_uri=provisioning_uri,
        otp_secret_base32=services.otp.secret_base32(otp_secret),
        message="Registration created. Scan the TOTP URI in an authenticator app and confirm one code to activate login.",
    )


@router.post("/register/confirm-otp", response_model=GenericMessage)
async def confirm_registration_otp(
    request: Request,
    payload: RegistrationOTPConfirmRequest,
    services: Annotated[Services, Depends(get_services)],
) -> GenericMessage:
    ip = request_ip(request)
    result = services.rate_limiter.allow(f"register-confirm:{ip}", limit=10, window_seconds=300)
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many OTP verification attempts. Retry in {result.retry_after_seconds} seconds.",
        )
    user = services.repo.get_user_by_username(payload.username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username, password, or OTP code.")
    if not services.security.verify_password(user["password_hash"], payload.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username, password, or OTP code.")
    secret = services.security.decrypt_secret(user["otp_secret_nonce"], user["otp_secret_ciphertext"])
    if not services.otp.verify(secret, payload.otp_code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username, password, or OTP code.")
    if int(user["otp_confirmed"]) == 0:
        services.repo.mark_otp_confirmed(int(user["id"]))
    return GenericMessage(message="OTP confirmed. Login now requires password + TOTP.")


@router.post("/login", response_model=LoginResponse)
async def login(
    request: Request,
    payload: LoginRequest,
    services: Annotated[Services, Depends(get_services)],
) -> LoginResponse:
    ip = request_ip(request)
    username = services.repo.normalize_username(payload.username)
    result = services.rate_limiter.allow(f"login:{ip}:{username}", limit=10, window_seconds=300)
    if not result.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many login attempts. Retry in {result.retry_after_seconds} seconds.",
        )
    user = services.repo.get_user_by_username(username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username, password, or OTP code.")
    if not services.security.verify_password(user["password_hash"], payload.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username, password, or OTP code.")
    if int(user["otp_confirmed"]) == 0:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="OTP has not been confirmed for this account yet.")
    secret = services.security.decrypt_secret(user["otp_secret_nonce"], user["otp_secret_ciphertext"])
    if not services.otp.verify(secret, payload.otp_code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid username, password, or OTP code.")
    session = services.security.create_session_token()
    services.repo.create_session(int(user["id"]), session.token_hash, session.expires_at)
    return LoginResponse(
        token=session.plaintext,
        expires_at=session.expires_at,
        username=user["username"],
        active_key_fingerprint=user["active_key_fingerprint"],
    )


@router.post("/logout", response_model=GenericMessage)
async def logout(
    current_user=Depends(get_current_user),
    services: Services = Depends(get_services),
) -> GenericMessage:
    if current_user.session_token_hash:
        services.repo.revoke_session(current_user.session_token_hash)
    await services.ws_manager.close_user_connections(current_user.id, reason="Logged out")
    return GenericMessage(message="Logged out and session invalidated.")


@router.get("/me", response_model=GenericMessage)
async def me(current_user=Depends(get_current_user)) -> GenericMessage:
    return GenericMessage(message=f"Authenticated as {current_user.username}.")
