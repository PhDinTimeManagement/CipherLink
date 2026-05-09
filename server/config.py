from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_DIR = PROJECT_ROOT / "db"
DEFAULT_CERT_DIR = PROJECT_ROOT / "certs_dev"


@dataclass(slots=True)
class Settings:
    app_name: str = "CipherLink"
    host: str = "127.0.0.1"
    port: int = 8443
    db_path: Path = DEFAULT_DB_DIR / "cipherlink.sqlite3"
    schema_path: Path = Path(__file__).resolve().parent / "schema.sql"
    master_key_path: Path = DEFAULT_DB_DIR / "server_master.key"
    tls_cert_path: Path = DEFAULT_CERT_DIR / "localhost.crt"
    tls_key_path: Path = DEFAULT_CERT_DIR / "localhost.key"
    session_lifetime_hours: int = 8
    pending_retention_hours: int = 168
    consumed_retention_hours: int = 1
    max_ciphertext_bytes: int = 32768
    max_friend_requests_per_hour: int = 20
    enable_access_log: bool = False

    @classmethod
    def from_env(cls) -> "Settings":
        db_path = Path(os.getenv("CIPHERLINK_DB_PATH", str(DEFAULT_DB_DIR / "cipherlink.sqlite3")))
        schema_path = Path(os.getenv("CIPHERLINK_SCHEMA_PATH", str(Path(__file__).resolve().parent / "schema.sql")))
        master_key_path = Path(os.getenv("CIPHERLINK_MASTER_KEY_PATH", str(DEFAULT_DB_DIR / "server_master.key")))
        tls_cert_path = Path(os.getenv("CIPHERLINK_TLS_CERT", str(DEFAULT_CERT_DIR / "localhost.crt")))
        tls_key_path = Path(os.getenv("CIPHERLINK_TLS_KEY", str(DEFAULT_CERT_DIR / "localhost.key")))
        bind_host = os.getenv("CIPHERLINK_BIND_HOST", os.getenv("CIPHERLINK_HOST", "127.0.0.1"))
        return cls(
            host=bind_host,
            port=int(os.getenv("CIPHERLINK_PORT", "8443")),
            db_path=db_path,
            schema_path=schema_path,
            master_key_path=master_key_path,
            tls_cert_path=tls_cert_path,
            tls_key_path=tls_key_path,
            session_lifetime_hours=int(os.getenv("CIPHERLINK_SESSION_HOURS", "8")),
            pending_retention_hours=int(os.getenv("CIPHERLINK_PENDING_RETENTION_HOURS", "168")),
            consumed_retention_hours=int(os.getenv("CIPHERLINK_CONSUMED_RETENTION_HOURS", "1")),
            max_ciphertext_bytes=int(os.getenv("CIPHERLINK_MAX_CIPHERTEXT_BYTES", "32768")),
            max_friend_requests_per_hour=int(os.getenv("CIPHERLINK_MAX_FRIEND_REQUESTS_PER_HOUR", "20")),
            enable_access_log=os.getenv("CIPHERLINK_ACCESS_LOG", "0") == "1",
        )

    def ensure_directories(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.master_key_path.parent.mkdir(parents=True, exist_ok=True)
        self.tls_cert_path.parent.mkdir(parents=True, exist_ok=True)
