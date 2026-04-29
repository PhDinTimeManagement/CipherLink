from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status

from server.config import Settings
from server.db import Database
from server.otp_utils import OTPManager
from server.rate_limit import SlidingWindowRateLimiter
from server.repositories import AuthenticatedUser, Repository
from server.security import SecurityManager
from server.ws_manager import WebSocketManager


@dataclass(slots=True)
class Services:
    settings: Settings
    db: Database
    repo: Repository
    security: SecurityManager
    otp: OTPManager
    rate_limiter: SlidingWindowRateLimiter
    ws_manager: WebSocketManager



def get_services(request: Request) -> Services:
    return request.app.state.services



def extract_bearer_token(authorization: str | None) -> str:
    if authorization is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing Authorization header.")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token.")
    return token.strip()


async def get_current_user(
    services: Annotated[Services, Depends(get_services)],
    authorization: Annotated[str | None, Header(alias="Authorization")] = None,
) -> AuthenticatedUser:
    token = extract_bearer_token(authorization)
    token_hash = services.security.hash_token(token)
    user = services.repo.get_user_for_token(token_hash)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session is invalid or expired.")
    return user



def request_ip(request: Request) -> str:
    if request.client is None:
        return "unknown"
    return request.client.host or "unknown"
