from __future__ import annotations

import argparse
import json
import shutil
import sys
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.protocol import ClientBootstrap  # noqa: E402
from shared.tls_utils import bootstrap_dict, certificate_sha256_hex_from_path, normalize_https_url  # noqa: E402
from shared.utils import isoformat_z, utc_now  # noqa: E402

DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "client_bootstrap"



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Create a client bootstrap bundle for remote CipherLink users")
    parser.add_argument("--server-url", required=True, help="Public HTTPS URL clients will use, for example https://192.168.1.50:8443")
    parser.add_argument("--ca-cert", required=True, help="Path to the CA certificate that signed the server certificate")
    parser.add_argument("--out-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory to write the bootstrap bundle")
    parser.add_argument("--ca-output-name", default="server_ca.crt", help="Filename for the copied CA certificate inside the bundle")
    parser.add_argument("--bootstrap-name", default="server_bootstrap.json", help="Bootstrap JSON filename")
    parser.add_argument("--description", default="CipherLink remote client bootstrap bundle", help="Optional free-text description")
    parser.add_argument("--zip-output", default=None, help="Optional ZIP path to package the bootstrap bundle")
    return parser



def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    server_url = normalize_https_url(args.server_url)
    ca_cert_path = Path(args.ca_cert).expanduser().resolve()
    if not ca_cert_path.exists():
        raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")

    output_dir = Path(args.out_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    copied_ca_path = output_dir / args.ca_output_name
    shutil.copyfile(ca_cert_path, copied_ca_path)
    ca_sha256 = certificate_sha256_hex_from_path(copied_ca_path)

    bootstrap_payload = ClientBootstrap(
        **bootstrap_dict(
            server_url=server_url,
            ca_cert_filename=copied_ca_path.name,
            ca_cert_sha256=ca_sha256,
            created_at=isoformat_z(utc_now()),
            description=args.description,
        )
    )
    bootstrap_path = output_dir / args.bootstrap_name
    bootstrap_path.write_text(json.dumps(bootstrap_payload.model_dump(mode="json"), indent=2), encoding="utf-8")
    readme_path = output_dir / "README.txt"
    readme_path.write_text(
        "CipherLink client bootstrap bundle\n\n"
        "1. Verify the CA SHA256 fingerprint with the server operator over a trusted out-of-band channel.\n"
        f"2. Use: python -m client.cli --profile <name> register --bootstrap-file {bootstrap_path.name} ...\n"
        "3. Keep the CA certificate read-only. Do not replace it without re-verifying the fingerprint.\n",
        encoding="utf-8",
    )

    print(f"Wrote bootstrap JSON: {bootstrap_path}")
    print(f"Copied CA certificate: {copied_ca_path}")
    print(f"CA SHA256 fingerprint: {ca_sha256}")
    print(
        "Client registration example: "
        f"python -m client.cli --profile alice register --username alice --bootstrap-file {bootstrap_path} "
        "--password <password> --device-passphrase <passphrase>"
    )

    if args.zip_output:
        zip_path = Path(args.zip_output).expanduser().resolve()
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for file_path in sorted(output_dir.rglob("*")):
                if file_path.is_file():
                    archive.write(file_path, arcname=file_path.relative_to(output_dir))
        print(f"Wrote bootstrap ZIP: {zip_path}")


if __name__ == "__main__":
    main()
