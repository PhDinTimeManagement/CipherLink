from __future__ import annotations

import base64
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.twofactor.totp import TOTP


class OTPManager:
    def __init__(self, issuer: str = "CipherLink") -> None:
        self.issuer = issuer

    def generate_secret(self) -> bytes:
        return os.urandom(20)

    def secret_base32(self, secret: bytes) -> str:
        return base64.b32encode(secret).decode("ascii")

    def provisioning_uri(self, secret: bytes, username: str) -> str:
        totp = TOTP(secret, 6, hashes.SHA1(), 30, enforce_key_length=False)
        return totp.get_provisioning_uri(username, self.issuer)

    def verify(self, secret: bytes, otp_code: str, at_time: int | None = None) -> bool:
        totp = TOTP(secret, 6, hashes.SHA1(), 30, enforce_key_length=False)
        timestamp = int(time.time()) if at_time is None else at_time
        token = otp_code.encode("ascii")
        for offset in (-30, 0, 30):
            try:
                totp.verify(token, timestamp + offset)
                return True
            except Exception:
                continue
        return False
