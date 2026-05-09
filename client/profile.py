from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from shared.crypto_utils import LocalKeyPair
from shared.tls_utils import TLSConfigurationError, ensure_certificate_fingerprint, load_bootstrap_file, normalize_https_url
from shared.utils import b64d, b64e


@dataclass(slots=True)
class ProfilePaths:
    profile_dir: Path
    config_path: Path
    vault_path: Path
    local_db_path: Path
    trusted_ca_path: Path


class ProfileError(Exception):
    pass


class VaultLockedError(ProfileError):
    pass


class LocalVault:
    def __init__(self, paths: ProfilePaths):
        self.paths = paths
        self._data: dict[str, Any] | None = None
        self._key: bytes | None = None

    @property
    def is_unlocked(self) -> bool:
        return self._data is not None and self._key is not None

    def exists(self) -> bool:
        return self.paths.vault_path.exists()

    def create(self, username: str, device_passphrase: str) -> None:
        if self.exists():
            raise ProfileError(f"Vault already exists at {self.paths.vault_path}.")
        self.paths.profile_dir.mkdir(parents=True, exist_ok=True)
        self._data = {
            "username": username,
            "active_key_fingerprint": None,
            "keys": {},
            "local_storage_key": b64e(ChaCha20Poly1305.generate_key()),
            "session": None,
        }
        self._save(device_passphrase)

    def unlock(self, device_passphrase: str) -> None:
        if not self.exists():
            raise ProfileError("Vault does not exist. Register or initialize a profile first.")
        blob = json.loads(self.paths.vault_path.read_text(encoding="utf-8"))
        salt = b64d(blob["salt"])
        nonce = b64d(blob["nonce"])
        ciphertext = b64d(blob["ciphertext"])
        key = self._derive_key(device_passphrase, salt)
        cipher = ChaCha20Poly1305(key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        self._key = key
        self._data = json.loads(plaintext.decode("utf-8"))

    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return kdf.derive(passphrase.encode("utf-8"))

    def _save(self, device_passphrase: str | None = None) -> None:
        if self._data is None:
            raise VaultLockedError("Vault is not loaded.")
        self.paths.profile_dir.mkdir(parents=True, exist_ok=True)
        salt: bytes
        if self.paths.vault_path.exists():
            blob = json.loads(self.paths.vault_path.read_text(encoding="utf-8"))
            salt = b64d(blob["salt"])
            if self._key is None:
                if device_passphrase is None:
                    raise VaultLockedError("Device passphrase is required to save a locked vault.")
                self._key = self._derive_key(device_passphrase, salt)
        else:
            salt = os.urandom(16)
            if device_passphrase is None:
                raise VaultLockedError("Device passphrase is required to create a new vault.")
            self._key = self._derive_key(device_passphrase, salt)
        cipher = ChaCha20Poly1305(self._key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, json.dumps(self._data, sort_keys=True).encode("utf-8"), None)
        blob = {"version": 1, "salt": b64e(salt), "nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}
        self.paths.vault_path.write_text(json.dumps(blob, indent=2), encoding="utf-8")
        try:
            os.chmod(self.paths.vault_path, 0o600)
        except OSError:
            pass

    def save(self) -> None:
        if self._key is None or self._data is None:
            raise VaultLockedError("Vault is locked.")
        cipher = ChaCha20Poly1305(self._key)
        nonce = os.urandom(12)
        ciphertext = cipher.encrypt(nonce, json.dumps(self._data, sort_keys=True).encode("utf-8"), None)
        if not self.paths.vault_path.exists():
            raise VaultLockedError("Vault file is missing.")
        blob = json.loads(self.paths.vault_path.read_text(encoding="utf-8"))
        self.paths.vault_path.write_text(
            json.dumps({"version": 1, "salt": blob["salt"], "nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}, indent=2),
            encoding="utf-8",
        )
        try:
            os.chmod(self.paths.vault_path, 0o600)
        except OSError:
            pass

    def _require_data(self) -> dict[str, Any]:
        if self._data is None:
            raise VaultLockedError("Unlock the vault first.")
        return self._data

    def username(self) -> str:
        return self._require_data()["username"]

    def local_storage_key(self) -> bytes:
        return b64d(self._require_data()["local_storage_key"])

    def active_key_fingerprint(self) -> str | None:
        return self._require_data().get("active_key_fingerprint")

    def all_key_records(self) -> dict[str, Any]:
        return self._require_data()["keys"]

    def add_keypair(self, keypair: LocalKeyPair, created_at: str, make_active: bool = True) -> None:
        data = self._require_data()
        data["keys"][keypair.fingerprint] = {
            "identity_private_key": b64e(keypair.identity_private_key),
            "identity_public_key": b64e(keypair.identity_public_key),
            "chat_private_key": b64e(keypair.chat_private_key),
            "chat_public_key": b64e(keypair.chat_public_key),
            "signature": b64e(keypair.signature),
            "created_at": created_at,
        }
        if make_active:
            data["active_key_fingerprint"] = keypair.fingerprint
        self.save()

    def set_active_fingerprint(self, fingerprint: str) -> None:
        data = self._require_data()
        if fingerprint not in data["keys"]:
            raise ProfileError(f"Unknown key fingerprint: {fingerprint}")
        data["active_key_fingerprint"] = fingerprint
        self.save()

    def key_record(self, fingerprint: str | None = None) -> dict[str, Any]:
        data = self._require_data()
        if fingerprint is None:
            fingerprint = data.get("active_key_fingerprint")
        if fingerprint is None or fingerprint not in data["keys"]:
            raise ProfileError("No active keypair is available in the local vault.")
        return data["keys"][fingerprint]

    def session(self) -> dict[str, Any] | None:
        return self._require_data().get("session")

    def set_session(self, token: str, expires_at: str) -> None:
        data = self._require_data()
        data["session"] = {"token": token, "expires_at": expires_at}
        self.save()

    def clear_session(self) -> None:
        data = self._require_data()
        data["session"] = None
        self.save()


class ProfileConfig:
    def __init__(self, paths: ProfilePaths):
        self.paths = paths

    def exists(self) -> bool:
        return self.paths.config_path.exists()

    def load(self) -> dict[str, Any]:
        if not self.exists():
            raise ProfileError(f"Profile config not found: {self.paths.config_path}")
        data = json.loads(self.paths.config_path.read_text(encoding="utf-8"))
        if "server_url" not in data:
            raise ProfileError("Profile config is missing server_url.")
        try:
            server_url = normalize_https_url(str(data["server_url"]))
            ca_path_value = data.get("ca_cert_path") or data.get("trusted_ca_filename")
            if not ca_path_value:
                raise ProfileError("Profile config is missing ca_cert_path.")
            ca_path = Path(str(ca_path_value))
            if not ca_path.is_absolute():
                ca_path = (self.paths.profile_dir / ca_path).resolve()
            if not ca_path.exists():
                raise ProfileError(f"Trusted CA certificate not found: {ca_path}")
            actual_sha256 = ensure_certificate_fingerprint(ca_path, data.get("ca_cert_sha256"))
        except TLSConfigurationError as exc:
            raise ProfileError(str(exc)) from exc
        return {
            "server_url": server_url,
            "ca_cert_path": str(ca_path),
            "ca_cert_sha256": actual_sha256,
        }

    def save(
        self,
        *,
        server_url: str,
        ca_cert_path: str,
        ca_cert_sha256: str | None = None,
        copy_ca_to_profile: bool = True,
    ) -> dict[str, Any]:
        self.paths.profile_dir.mkdir(parents=True, exist_ok=True)
        try:
            normalized_server_url = normalize_https_url(server_url)
            source_cert_path = Path(ca_cert_path).expanduser().resolve()
            if not source_cert_path.exists():
                raise ProfileError(f"Trusted CA certificate not found: {source_cert_path}")
            destination_path = source_cert_path
            if copy_ca_to_profile:
                destination_path = self.paths.trusted_ca_path
                destination_path.write_bytes(source_cert_path.read_bytes())
                try:
                    os.chmod(destination_path, 0o644)
                except OSError:
                    pass
            actual_sha256 = ensure_certificate_fingerprint(destination_path, ca_cert_sha256)
        except TLSConfigurationError as exc:
            raise ProfileError(str(exc)) from exc
        payload = {
            "server_url": normalized_server_url,
            "ca_cert_path": destination_path.name if copy_ca_to_profile else str(destination_path),
            "ca_cert_sha256": actual_sha256,
        }
        self.paths.config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return payload

    def save_from_bootstrap(self, bootstrap_path: str | Path) -> dict[str, Any]:
        try:
            bootstrap = load_bootstrap_file(bootstrap_path)
        except TLSConfigurationError as exc:
            raise ProfileError(str(exc)) from exc
        return self.save(
            server_url=str(bootstrap["server_url"]),
            ca_cert_path=str(bootstrap["ca_cert_path"]),
            ca_cert_sha256=str(bootstrap["ca_cert_sha256"]),
            copy_ca_to_profile=True,
        )



def normalize_profile_name(profile_name: str) -> str:
    normalized = str(profile_name or "").strip().lower()
    if not normalized:
        raise ProfileError("Profile name is required.")
    return normalized


def profile_paths(profile_name: str, base_dir: str | Path | None = None) -> ProfilePaths:
    root = Path(base_dir or Path.cwd() / "client_profiles").resolve()
    profile_dir = root / normalize_profile_name(profile_name)
    return ProfilePaths(
        profile_dir=profile_dir,
        config_path=profile_dir / "profile.json",
        vault_path=profile_dir / "vault.enc.json",
        local_db_path=profile_dir / "local.db",
        trusted_ca_path=profile_dir / "trusted_server_ca.crt",
    )
