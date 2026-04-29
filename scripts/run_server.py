from __future__ import annotations

import argparse
import sys
from pathlib import Path

import uvicorn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from server.app import create_app  # noqa: E402
from server.config import Settings  # noqa: E402



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the CipherLink HTTPS server")
    parser.add_argument("--bind-host", help="Interface to bind, for example 0.0.0.0 or 127.0.0.1")
    parser.add_argument("--port", type=int, help="TCP port to listen on")
    parser.add_argument("--tls-cert", help="Path to the server TLS certificate (PEM)")
    parser.add_argument("--tls-key", help="Path to the server TLS private key (PEM)")
    parser.add_argument("--db-path", help="Path to the SQLite database file")
    parser.add_argument("--schema-path", help="Path to the schema SQL file")
    parser.add_argument("--master-key-path", help="Path to the server master key file")
    parser.add_argument("--access-log", action="store_true", help="Enable Uvicorn access logs")
    return parser



def apply_cli_overrides(settings: Settings, args: argparse.Namespace) -> Settings:
    if args.bind_host:
        settings.host = args.bind_host
    if args.port:
        settings.port = args.port
    if args.tls_cert:
        settings.tls_cert_path = Path(args.tls_cert)
    if args.tls_key:
        settings.tls_key_path = Path(args.tls_key)
    if args.db_path:
        settings.db_path = Path(args.db_path)
    if args.schema_path:
        settings.schema_path = Path(args.schema_path)
    if args.master_key_path:
        settings.master_key_path = Path(args.master_key_path)
    if args.access_log:
        settings.enable_access_log = True
    return settings



def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    settings = apply_cli_overrides(Settings.from_env(), args)
    settings.ensure_directories()
    if not settings.tls_cert_path.exists() or not settings.tls_key_path.exists():
        missing = []
        if not settings.tls_cert_path.exists():
            missing.append(str(settings.tls_cert_path))
        if not settings.tls_key_path.exists():
            missing.append(str(settings.tls_key_path))
        raise FileNotFoundError(
            "TLS material missing: "
            + ", ".join(missing)
            + ". Generate localhost material with scripts/generate_dev_cert.py or deployment material with scripts/generate_tls_materials.py."
        )
    app = create_app(settings)
    print(
        f"Starting CipherLink server on https://{settings.host}:{settings.port} using cert={settings.tls_cert_path}. "
        "Clients must connect with a hostname or IP that matches the server certificate SANs."
    )
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        ssl_certfile=str(settings.tls_cert_path),
        ssl_keyfile=str(settings.tls_key_path),
        access_log=settings.enable_access_log,
        log_level="info",
    )


if __name__ == "__main__":
    main()
