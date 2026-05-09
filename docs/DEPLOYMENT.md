# Deployment Guide

This guide explains how to run CipherLink locally or across multiple machines.

## 1. Prerequisites

Use Python 3.11 or later.

Install dependencies from the repository root.

### Unix/Linux/MacOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation scripts, run once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## 2. Generated Files Warning

The following files are generated for local operation and should not be committed:

```text
certs_dev/
certs_network/
client_bootstrap/
client_profiles/
db/cipherlink.sqlite3
db/server_master.key
```

The repository should contain source code and schema, not generated keys, certificates, databases, or client profiles.

## 3. TLS Setup

The server requires TLS material before it can start.

### Option A: localhost development TLS

Use this for local testing on one machine:

```bash
python scripts/generate_dev_cert.py
```

Generated files:

```text
certs_dev/localhost.crt
certs_dev/localhost.key
```

The default server configuration uses these paths.

### Option B: network deployment TLS

Use this when remote clients connect to the server from other machines.

For IP-based access:

```bash
python scripts/generate_tls_materials.py \
  --ip 192.168.1.50 \
  --common-name 192.168.1.50
```

For DNS-based access:

```bash
python scripts/generate_tls_materials.py \
  --dns cipherlink.example.test \
  --common-name cipherlink.example.test
```

For both DNS and IP SANs:

```bash
python scripts/generate_tls_materials.py \
  --dns cipherlink.example.test \
  --ip 192.168.1.50 \
  --common-name cipherlink.example.test
```

Generated files:

```text
certs_network/cipherlink-ca.crt
certs_network/cipherlink-ca.key
certs_network/server.crt
certs_network/server.key
```

Protect the private keys:

```bash
chmod 600 certs_network/*.key
```

On Windows, restrict access through file properties or ACLs.

### SAN Requirement

Clients must connect using a host or IP address present in the server certificate SAN list.

Examples:

| Client URL | Required certificate SAN |
|---|---|
| `https://192.168.1.50:8443` | IP SAN `192.168.1.50` |
| `https://cipherlink.example.test:8443` | DNS SAN `cipherlink.example.test` |

## 4. Database Initialization

The canonical runtime schema is:

```text
server/schema.sql
```

Initialize the database and server master key:

```bash
python scripts/init_db.py
```

This creates:

```text
db/cipherlink.sqlite3
db/server_master.key
```

`db/server_master.key` encrypts server-side TOTP secrets. Do not delete it for a live deployment unless you intentionally reset all accounts.

### Reset Local Development State

For a clean local reset:

```bash
rm -f db/cipherlink.sqlite3 db/server_master.key
python scripts/init_db.py
```

On Windows PowerShell:

```powershell
Remove-Item db\cipherlink.sqlite3, db\server_master.key -ErrorAction SilentlyContinue
python scripts\init_db.py
```

## 5. Start the Server

### Localhost Development

```bash
python scripts/run_server.py
```

Default URL:

```text
https://127.0.0.1:8443
```

### Network Server

```bash
python scripts/run_server.py \
  --bind-host 0.0.0.0 \
  --port 8443 \
  --tls-cert certs_network/server.crt \
  --tls-key certs_network/server.key
```

Windows PowerShell:

```powershell
python scripts\run_server.py `
  --bind-host 0.0.0.0 `
  --port 8443 `
  --tls-cert certs_network\server.crt `
  --tls-key certs_network\server.key
```

Open the chosen TCP port in the host firewall if remote clients cannot connect.

## 6. Configuration Options

The server accepts CLI options through `scripts/run_server.py` and environment variables through `server/config.py`.

| Setting | CLI option | Environment variable | Default |
|---|---|---|---|
| Bind host | `--bind-host` | `CIPHERLINK_BIND_HOST` or `CIPHERLINK_HOST` | `127.0.0.1` |
| Port | `--port` | `CIPHERLINK_PORT` | `8443` |
| SQLite DB path | `--db-path` | `CIPHERLINK_DB_PATH` | `db/cipherlink.sqlite3` |
| Schema path | `--schema-path` | `CIPHERLINK_SCHEMA_PATH` | `server/schema.sql` |
| Server master key path | `--master-key-path` | `CIPHERLINK_MASTER_KEY_PATH` | `db/server_master.key` |
| TLS cert | `--tls-cert` | `CIPHERLINK_TLS_CERT` | `certs_dev/localhost.crt` |
| TLS key | `--tls-key` | `CIPHERLINK_TLS_KEY` | `certs_dev/localhost.key` |
| Session lifetime | — | `CIPHERLINK_SESSION_HOURS` | `8` |
| Pending message retention | — | `CIPHERLINK_PENDING_RETENTION_HOURS` | `168` |
| Consumed message retention | — | `CIPHERLINK_CONSUMED_RETENTION_HOURS` | `1` |
| Max ciphertext bytes | — | `CIPHERLINK_MAX_CIPHERTEXT_BYTES` | `32768` |
| Friend request limit | — | `CIPHERLINK_MAX_FRIEND_REQUESTS_PER_HOUR` | `20` |
| Uvicorn access log | `--access-log` | `CIPHERLINK_ACCESS_LOG=1` | disabled |

Avoid access logs in deployments where WebSocket URLs may be logged, because the WebSocket token is currently passed in the query string.

## 7. Create a Network Bootstrap Bundle

For remote clients, create a bootstrap bundle after generating network TLS material.

```bash
python scripts/create_client_bootstrap.py \
  --server-url https://192.168.1.50:8443 \
  --ca-cert certs_network/cipherlink-ca.crt \
  --out-dir client_bootstrap \
  --zip-output client_bootstrap.zip
```

The bundle contains:

```text
server_bootstrap.json
server_ca.crt
README.txt
```

Distribute the bootstrap ZIP over a trusted channel. Separately provide the CA SHA-256 fingerprint out of band so users can compare it before first trust.

Do not commit generated bootstrap bundles.

## 8. Client Registration and Login

### Direct Local Registration

Use this for localhost development:

```bash
python -m client.cli --profile alice register \
  --username alice \
  --server-url https://127.0.0.1:8443 \
  --ca-cert certs_dev/localhost.crt
```

The command prompts for:

- account password;
- local device vault passphrase.

It prints a TOTP provisioning URI and base32 secret. Add the TOTP secret to an authenticator app.

Confirm OTP:

```bash
python -m client.cli --profile alice confirm-otp \
  --username alice \
  --otp <current-totp-code>
```

Log in:

```bash
python -m client.cli --profile alice login \
  --username alice \
  --otp <current-totp-code>
```

### Bootstrap Registration for Remote Clients

After extracting the bootstrap bundle:

```bash
python -m client.cli --profile alice register \
  --username alice \
  --bootstrap-file /path/to/client_bootstrap/server_bootstrap.json
```

On Windows PowerShell:

```powershell
python -m client.cli --profile alice register `
  --username alice `
  --bootstrap-file C:\path\to\client_bootstrap\server_bootstrap.json
```

Then confirm OTP and log in as shown above.

## 9. CLI, Shell, and GUI Startup

Run one-off CLI commands:

```bash
python -m client.cli --profile alice contacts
python -m client.cli --profile alice requests
python -m client.cli --profile alice conversations
```

Open the interactive shell:

```bash
python -m client.cli --profile alice shell
```

Open the desktop GUI:

```bash
python -m client.gui_app
```

Or through the CLI wrapper:

```bash
python -m client.cli gui
```

## 10. Functional Test with Two Users

Register, confirm OTP, and log in two profiles, for example `alice` and `bob`.

Alice sends a friend request:

```bash
python -m client.cli --profile alice send-friend-request --to bob
```

Bob lists and accepts:

```bash
python -m client.cli --profile bob requests
python -m client.cli --profile bob accept-request --id <request-id>
```

Both sides must compare and verify fingerprints out of band:

```bash
python -m client.cli --profile alice fingerprint --user bob
python -m client.cli --profile bob fingerprint --user alice

python -m client.cli --profile alice verify-contact --user bob
python -m client.cli --profile bob verify-contact --user alice
```

Alice sends a message:

```bash
python -m client.cli --profile alice send --to bob --text "hello bob"
```

Bob syncs and opens the conversation:

```bash
python -m client.cli --profile bob sync
python -m client.cli --profile bob history --user alice
```

Alice syncs to receive read acknowledgement state:

```bash
python -m client.cli --profile alice sync
python -m client.cli --profile alice history --user bob
```

## 11. Disappearing Message Test

Send a message with a TTL:

```bash
python -m client.cli --profile alice send \
  --to bob \
  --text "this message expires" \
  --ttl 10
```

Bob syncs and views history:

```bash
python -m client.cli --profile bob sync
python -m client.cli --profile bob history --user alice
```

After the TTL passes, expired messages are removed from the normal local history view. This is best-effort deletion, not secure deletion.

## 12. Troubleshooting

### TLS material missing

Generate certificates first:

```bash
python scripts/generate_dev_cert.py
```

or for network deployment:

```bash
python scripts/generate_tls_materials.py --ip <server-ip> --common-name <server-ip>
```

### Certificate verification failure

Check that:

- the client uses `https://`;
- the client URL host/IP matches a certificate SAN;
- the correct CA certificate is passed or included in the bootstrap bundle;
- the CA fingerprint in the bootstrap JSON matches the CA certificate.

### Client cannot connect remotely

Check that:

- the server is started with `--bind-host 0.0.0.0`;
- the firewall allows the selected TCP port;
- the client uses the same host/IP that appears in the certificate SAN;
- the server URL includes the correct port.

### Login fails after registration

Make sure OTP confirmation was completed:

```bash
python -m client.cli --profile alice confirm-otp \
  --username alice \
  --otp <current-totp-code>
```

Also check system time on the client and server; TOTP depends on time.

### Password rejected

The password must have:

- at least 10 characters;
- uppercase letter;
- lowercase letter;
- digit;
- symbol.

### Chat send is rejected after becoming friends

Both users must verify each other’s current fingerprint. Accepted friendship alone is not enough.

Run:

```bash
python -m client.cli --profile alice verify-contact --user bob
python -m client.cli --profile bob verify-contact --user alice
```

Only verify after comparing safety numbers out of band.

### Message no longer appears

The message may have expired due to TTL or local history retention. Disappearing-message deletion is best effort.

### Schema mismatch or missing table

Use `server/schema.sql` as the runtime schema. Reinitialize a local development database if needed:

```bash
rm -f db/cipherlink.sqlite3
python scripts/init_db.py
```

Do not initialize from stale duplicate schema files unless they have been synchronized with `server/schema.sql`.

### Session expired

Log in again:

```bash
python -m client.cli --profile alice login \
  --username alice \
  --otp <current-totp-code>
```