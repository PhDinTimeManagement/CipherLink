from __future__ import annotations

import base64
import os
import re
import secrets
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import Type
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from shared.utils import b64e, isoformat_z, sha256_hex, utc_now


PASSWORD_PATTERN_RULES = [
    (re.compile(r"[A-Z]"), "Password must contain at least one uppercase letter."),
    (re.compile(r"[a-z]"), "Password must contain at least one lowercase letter."),
    (re.compile(r"[0-9]"), "Password must contain at least one digit."),
    (re.compile(r"[^A-Za-z0-9]"), "Password must contain at least one symbol."),
]


@dataclass(slots=True)
class SessionToken:
    plaintext: str
    token_hash: str
    expires_at: str


class SecurityManager:
    def __init__(self, master_key_path: Path, session_lifetime_hours: int = 8) -> None:
        self.master_key_path = master_key_path
        self.session_lifetime_hours = session_lifetime_hours
        self.master_key = self._load_or_create_master_key(master_key_path)
        self.password_hasher = PasswordHasher(type=Type.ID)

    @staticmethod
    def _load_or_create_master_key(path: Path) -> bytes:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            return base64.urlsafe_b64decode(path.read_text(encoding="utf-8").encode("ascii"))
        key = ChaCha20Poly1305.generate_key()
        path.write_text(base64.urlsafe_b64encode(key).decode("ascii"), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return key

    def validate_password_policy(self, password: str) -> None:
        if len(password) < 10:
            raise ValueError("Password must be at least 10 characters long.")
        for regex, message in PASSWORD_PATTERN_RULES:
            if regex.search(password) is None:
                raise ValueError(message)

    def hash_password(self, password: str) -> str:
        self.validate_password_policy(password)
        return self.password_hasher.hash(password)

    def verify_password(self, password_hash: str, password: str) -> bool:
        try:
            return self.password_hasher.verify(password_hash, password)
        except VerifyMismatchError:
            return False

    def encrypt_secret(self, plaintext: bytes) -> tuple[str, str]:
        nonce = os.urandom(12)
        cipher = ChaCha20Poly1305(self.master_key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        return b64e(nonce), b64e(ciphertext)

    def decrypt_secret(self, nonce_b64: str, ciphertext_b64: str) -> bytes:
        cipher = ChaCha20Poly1305(self.master_key)
        nonce = base64.b64decode(nonce_b64.encode("ascii"))
        ciphertext = base64.b64decode(ciphertext_b64.encode("ascii"))
        return cipher.decrypt(nonce, ciphertext, None)

    def create_session_token(self) -> SessionToken:
        plaintext = secrets.token_urlsafe(32)
        token_hash = sha256_hex(plaintext.encode("utf-8"))
        expires_at = isoformat_z(utc_now() + timedelta(hours=self.session_lifetime_hours))
        return SessionToken(plaintext=plaintext, token_hash=token_hash, expires_at=expires_at)

    @staticmethod
    def hash_token(token: str) -> str:
        return sha256_hex(token.encode("utf-8"))
