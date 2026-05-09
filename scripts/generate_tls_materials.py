from __future__ import annotations

import argparse
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "certs_network"



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a private CA and a server TLS certificate for CipherLink")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for generated PEM files")
    parser.add_argument("--common-name", default=None, help="Server certificate common name")
    parser.add_argument("--dns", action="append", default=[], help="DNS SAN entry. Repeat for multiple names")
    parser.add_argument("--ip", action="append", default=[], help="IP SAN entry. Repeat for multiple addresses")
    parser.add_argument("--days", type=int, default=365, help="Certificate validity in days")
    parser.add_argument("--ca-common-name", default="CipherLink Demo Root CA", help="Root CA common name")
    parser.add_argument("--server-cert-name", default="server.crt", help="Server certificate filename")
    parser.add_argument("--server-key-name", default="server.key", help="Server private key filename")
    parser.add_argument("--ca-cert-name", default="cipherlink-ca.crt", help="CA certificate filename")
    parser.add_argument("--ca-key-name", default="cipherlink-ca.key", help="CA private key filename")
    return parser



def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ZZ"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CipherLink"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )



def _write_private_key(path: Path, private_key: rsa.RSAPrivateKey) -> None:
    path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )



def _write_certificate(path: Path, certificate: x509.Certificate) -> None:
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))



def _san_entries(dns_names: Iterable[str], ip_values: Iterable[str]) -> list[x509.GeneralName]:
    entries: list[x509.GeneralName] = []
    for name in dns_names:
        stripped = name.strip()
        if stripped:
            entries.append(x509.DNSName(stripped))
    for ip_value in ip_values:
        stripped = ip_value.strip()
        if stripped:
            entries.append(x509.IPAddress(ipaddress.ip_address(stripped)))
    return entries



def create_ca(common_name: str, valid_days: int) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = _name(common_name)
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .sign(private_key, hashes.SHA256())
    )
    return private_key, certificate



def create_server_cert(
    *,
    ca_private_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
    common_name: str,
    dns_names: list[str],
    ip_values: list[str],
    valid_days: int,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc)
    san_entries = _san_entries(dns_names, ip_values)
    if not san_entries:
        san_entries = _san_entries(["localhost"], ["127.0.0.1"])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(ca_certificate.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectAlternativeName(san_entries), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256())
    )
    return private_key, certificate



def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    dns_names = list(dict.fromkeys(args.dns or []))
    ip_values = list(dict.fromkeys(args.ip or []))
    if not dns_names and not ip_values:
        dns_names = ["localhost"]
        ip_values = ["127.0.0.1"]
    common_name = args.common_name or (dns_names[0] if dns_names else ip_values[0])

    ca_private_key, ca_certificate = create_ca(args.ca_common_name, args.days)
    server_private_key, server_certificate = create_server_cert(
        ca_private_key=ca_private_key,
        ca_certificate=ca_certificate,
        common_name=common_name,
        dns_names=dns_names,
        ip_values=ip_values,
        valid_days=args.days,
    )

    ca_cert_path = output_dir / args.ca_cert_name
    ca_key_path = output_dir / args.ca_key_name
    server_cert_path = output_dir / args.server_cert_name
    server_key_path = output_dir / args.server_key_name

    _write_private_key(ca_key_path, ca_private_key)
    _write_certificate(ca_cert_path, ca_certificate)
    _write_private_key(server_key_path, server_private_key)
    _write_certificate(server_cert_path, server_certificate)

    san_extension = server_certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    san_values = [entry.value for entry in san_extension.value]
    ca_fingerprint = ca_certificate.fingerprint(hashes.SHA256()).hex()

    print(f"Wrote CA certificate:   {ca_cert_path}")
    print(f"Wrote CA private key:  {ca_key_path}")
    print(f"Wrote server cert:     {server_cert_path}")
    print(f"Wrote server key:      {server_key_path}")
    print(f"Server certificate SANs: {san_values}")
    print(f"CA SHA256 fingerprint: {ca_fingerprint}")
    print(
        "Next step: start the server with scripts/run_server.py --bind-host 0.0.0.0 "
        f"--tls-cert {server_cert_path} --tls-key {server_key_path}"
    )
    print(
        "Then create a client bootstrap bundle with scripts/create_client_bootstrap.py so remote users can trust the CA."
    )


if __name__ == "__main__":
    main()
