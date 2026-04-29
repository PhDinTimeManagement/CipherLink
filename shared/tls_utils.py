from __future__ import annotations

from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from shared.utils import sha256_hex


class TLSConfigurationError(ValueError):
    """Raised when TLS bootstrap or certificate material is invalid."""


def normalize_https_url(server_url: str) -> str:
    value = server_url.strip().rstrip("/")
    if not value.startswith("https://"):
        raise TLSConfigurationError("Server URL must use https://")
    return value



def load_pem_certificate_from_path(path: str | Path) -> x509.Certificate:
    certificate_path = Path(path).expanduser().resolve()
    pem_bytes = certificate_path.read_bytes()
    return x509.load_pem_x509_certificate(pem_bytes)



def certificate_sha256_hex(certificate: x509.Certificate) -> str:
    der = certificate.public_bytes(serialization.Encoding.DER)
    return sha256_hex(der)



def certificate_sha256_hex_from_path(path: str | Path) -> str:
    return certificate_sha256_hex(load_pem_certificate_from_path(path))



def ensure_certificate_fingerprint(path: str | Path, expected_sha256_hex: str | None) -> str:
    actual = certificate_sha256_hex_from_path(path)
    if expected_sha256_hex and actual.lower() != expected_sha256_hex.lower():
        raise TLSConfigurationError(
            f"Trusted CA certificate fingerprint mismatch. Expected {expected_sha256_hex.lower()}, got {actual.lower()}."
        )
    return actual



def bootstrap_dict(
    *,
    server_url: str,
    ca_cert_filename: str,
    ca_cert_sha256: str,
    created_at: str,
    description: str | None = None,
) -> dict[str, Any]:
    normalized_url = normalize_https_url(server_url)
    return {
        "version": 1,
        "server_url": normalized_url,
        "ca_cert_filename": ca_cert_filename,
        "ca_cert_sha256": ca_cert_sha256.lower(),
        "created_at": created_at,
        "description": description,
    }



def load_bootstrap_file(path: str | Path) -> dict[str, Any]:
    import json

    bootstrap_path = Path(path).expanduser().resolve()
    data = json.loads(bootstrap_path.read_text(encoding="utf-8"))
    if data.get("version") != 1:
        raise TLSConfigurationError(f"Unsupported bootstrap version: {data.get('version')!r}")
    if "server_url" not in data or "ca_cert_filename" not in data or "ca_cert_sha256" not in data:
        raise TLSConfigurationError("Bootstrap file is missing required fields.")
    data["server_url"] = normalize_https_url(str(data["server_url"]))
    data["ca_cert_sha256"] = str(data["ca_cert_sha256"]).lower()
    data["bootstrap_path"] = str(bootstrap_path)
    data["ca_cert_path"] = str((bootstrap_path.parent / str(data["ca_cert_filename"])).resolve())
    return data
