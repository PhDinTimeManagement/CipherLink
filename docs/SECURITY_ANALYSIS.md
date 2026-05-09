# Security Analysis

This document describes the security design of CipherLink based on the current implementation in `server/`, `client/`, and `shared/`.

## Scope

CipherLink is a single-server, 1:1 secure messaging prototype. It provides:

- account registration and login with password plus TOTP;
- signed client public key bundles;
- client-side end-to-end encrypted chat payloads;
- friend/contact workflow;
- mutual fingerprint verification before chat messages are accepted;
- offline encrypted-message queueing;
- local encrypted client profiles;
- TLS-protected client/server transport.

This is an academic security project and not production-ready secure messaging software.

## Threat Model

### In Scope

| Threat | Mitigation in this project |
|---|---|
| Passive network attacker | HTTPS/WSS transport with certificate validation. |
| Active network attacker | TLS plus explicit CA bootstrap/fingerprint verification for network deployments. |
| Honest-but-curious server | Message plaintext and client private keys are not sent to the server. |
| Database disclosure without server master key | Message bodies remain end-to-end encrypted; TOTP secrets are encrypted. Metadata is still exposed. |
| Replay or duplicate messages | Server and client track message identifiers and counters. |
| Contact key change | Local trust state changes to `key_change_pending`; server-side verification records also block chat until re-verification. |
| Unauthorized messaging by non-friends | Server enforces accepted friendship before chat send. |
| Messaging after block | Server enforces block state before chat send. |
| Weak account passwords | Server enforces minimum length and character-class policy, then hashes with Argon2id. |

### Out of Scope / Not Fully Mitigated

| Threat | Current limitation |
|---|---|
| Malicious server key substitution before users verify fingerprints | The server distributes public key bundles. Out-of-band fingerprint verification is required to detect substitution. |
| Full malicious server behavior | The design assumes an honest-but-curious server for message confidentiality, not a fully malicious key-distribution server. |
| Forward secrecy / post-compromise security | There is no double ratchet. Static X25519 chat keys are used until rotated. |
| Malicious or modified clients | A modified client can save plaintext, ignore deletion timers, or lie about UI state. |
| Screenshots / copy-paste | Disappearing messages cannot prevent capture outside the app. |
| Server metadata privacy | Usernames, contact graph, timestamps, ciphertext sizes, key fingerprints, and delivery timing remain visible to the server. |
| Multi-device identity | The current design is single-profile/single-device oriented. |
| Production scalability | SQLite, in-memory rate limiting, and in-memory WebSocket presence are suitable for a course/demo deployment, not a large production system. |

## Authentication and Identity

### Usernames

Usernames are validated with the regex in `shared/protocol.py`:

```text
^[A-Za-z0-9_.-]{3,32}$
```

The repository layer normalizes usernames to lowercase.

### Passwords

Password handling is implemented in `server/security.py`.

The server requires:

- at least 10 characters;
- at least one uppercase letter;
- at least one lowercase letter;
- at least one digit;
- at least one symbol.

Passwords are hashed with Argon2id via `argon2-cffi`.

### TOTP

TOTP is implemented in `server/otp_utils.py` using:

- 20-byte random TOTP secret;
- 6-digit TOTP code;
- SHA-1 TOTP;
- 30-second period;
- a small verification window around the current time.

The registration endpoint returns the provisioning URI and base32 secret so the user can enroll the secret in an authenticator app. That registration output must be treated as sensitive setup material.

### TOTP Secret At Rest

The server encrypts TOTP secrets with ChaCha20-Poly1305 under a generated server master key stored at:

```text
db/server_master.key
```

This key is required for normal operation and must never be committed to GitHub. If both `db/server_master.key` and a populated server database are leaked, encrypted TOTP seeds can be decrypted.

### Sessions

Successful login creates a random opaque session token. The server stores only a SHA-256 hash of the token in the `sessions` table. The plaintext token is returned to the client and stored inside the encrypted local vault.

Session lifetime defaults to 8 hours in `server/config.py`.

## Client Key Material

Each client profile contains locally generated key material:

- Ed25519 identity private/public keypair;
- X25519 chat/agreement private/public keypair;
- Ed25519 signature over the X25519 public key;
- SHA-256 fingerprint over `identity_public_key || chat_public_key`.

Private keys are stored only in the encrypted local vault at:

```text
client_profiles/<profile>/vault.enc.json
```

The server receives only public key bundles.

## Public Key Bundles

Public key bundles are defined in `shared/protocol.py` as `PublicKeyBundle`.

A bundle contains:

- username;
- fingerprint;
- Ed25519 identity public key;
- X25519 chat public key;
- Ed25519 signature;
- creation time;
- active/revoked state.

Bundle verification is implemented in `shared/crypto_utils.py`:

1. Decode the public keys and signature.
2. Recompute the fingerprint.
3. Verify that the Ed25519 identity public key signed the X25519 chat public key.

This verifies bundle internal consistency, but users still need out-of-band fingerprint verification to detect malicious key substitution.

## Message Encryption Design

Message encryption is implemented in `shared/crypto_utils.py`.

### Root Key Derivation

For a sender and receiver:

```text
shared_secret = X25519(our_chat_private_key, peer_chat_public_key)
root_key = HKDF-SHA256(
    input_key_material = shared_secret,
    salt = SHA256(conversation_id | sorted_key_fingerprints),
    info = "cipherlink-root-v1",
    length = 32
)
```

### Per-Message Key Derivation

Each message derives a fresh message key from the root key:

```text
message_key = HKDF-SHA256(
    input_key_material = root_key,
    salt = SHA256(canonical_header_json),
    info = "cipherlink-msg-v1|...",
    length = 32
)
```

The header includes the message ID, sender, receiver, message kind, counter, and key fingerprints. This means different messages derive different AEAD keys even though the same long-term X25519 chat keys are reused.

### AEAD Encryption

CipherLink uses ChaCha20-Poly1305 with:

- 256-bit message key;
- 96-bit random nonce;
- canonical JSON plaintext payload;
- canonical JSON message header as associated data.

The header is not encrypted, but it is authenticated. Tampering with sender, receiver, conversation ID, key fingerprints, counter, message ID, TTL, or message kind breaks AEAD verification.

## Message Kinds

The protocol supports two message kinds:

| Kind | Purpose |
|---|---|
| `chat` | Normal encrypted chat payload. |
| `delivery_ack` | Encrypted acknowledgement/read-confirmation envelope referencing a prior message. |

The UI currently treats server acceptance as a delivered/queued state and a decrypted acknowledgement as read confirmation.

## Contact Trust and Verification

Contact trust is enforced both locally and server-side.

### Local Trust

The client tracks contact state in `client/local_store.py`:

- `unverified`;
- `verified`;
- `key_change_pending`.

If a contact’s active fingerprint changes after verification, the local state becomes `key_change_pending`, a security event is created, and outgoing messages are blocked until the user re-verifies.

### Server-Side Verification Gate

The current runtime schema in `server/schema.sql` includes:

```text
contact_verifications
```

The server route `POST /api/v1/contacts/verify` records that one user has verified another user’s current active fingerprint.

For `chat` messages, `server/routes/messages.py` checks:

- sender matches authenticated user;
- sender key fingerprint is the sender’s active key;
- receiver exists;
- receiver key fingerprint is known;
- conversation ID matches the sender/receiver pair;
- sender and receiver are accepted friends;
- neither user has blocked the other;
- both users have acceptable verification states.

This means both sides must verify the other side’s current safety number before chat sends are accepted.

## Transport Security

The server runs over HTTPS and WSS through Uvicorn in `scripts/run_server.py`.

There are two TLS modes:

### Local Development

`scripts/generate_dev_cert.py` creates:

```text
certs_dev/localhost.crt
certs_dev/localhost.key
```

These files are generated development material and must not be committed.

### Network Deployment

`scripts/generate_tls_materials.py` creates:

```text
certs_network/cipherlink-ca.crt
certs_network/cipherlink-ca.key
certs_network/server.crt
certs_network/server.key
```

The server certificate must include the DNS name or IP address clients use in its SAN list.

`scripts/create_client_bootstrap.py` creates a bootstrap bundle containing:

- server URL;
- CA certificate filename;
- CA certificate SHA-256 fingerprint;
- creation timestamp;
- optional description.

Clients verify that the copied CA certificate matches the bootstrap fingerprint.

## WebSocket Authentication Risk

The WebSocket endpoint authenticates with:

```text
/api/v1/ws?token=<session-token>
```

This works, but query-string tokens can be captured by reverse-proxy logs, debug logs, browser/network tooling, or monitoring systems if access logging is enabled. `CIPHERLINK_ACCESS_LOG` defaults to disabled, which is appropriate.

A stronger production design would use a short-lived WebSocket ticket, an authenticated upgrade flow, or another mechanism that avoids long-lived session tokens in URLs.

## Server Database Security

The server uses SQLite through `server/db.py` and `server/repositories.py`.

The runtime schema is:

```text
server/schema.sql
```

Important server-side tables:

| Table | Security relevance |
|---|---|
| `users` | Usernames, Argon2id password hashes, encrypted TOTP seeds, active key fingerprint. |
| `key_bundles` | Public identity/chat keys, fingerprints, active/revoked state. |
| `sessions` | Hashes of session tokens and expiry/revocation timestamps. |
| `friend_requests` | Contact workflow metadata and notes. |
| `friendships` | Accepted/removed relationship state. |
| `blocks` | Block relationships. |
| `contact_verifications` | Per-user verification of another user’s active fingerprint. |
| `messages` | Encrypted envelopes, routing metadata, counters, timestamps, TTL, delivery/consume/delete state. |

The server database is not encrypted as a whole. Message plaintext is still protected by end-to-end encryption, but metadata remains visible.

## Client Local Storage Security

Each client profile is generated under:

```text
client_profiles/<profile>/
```

Important generated files:

| File | Purpose |
|---|---|
| `profile.json` | Server URL and trusted CA configuration. |
| `trusted_server_ca.crt` | CA certificate copied into the profile. |
| `vault.enc.json` | Encrypted vault containing private keys, session token, and local storage key. |
| `local.db` | Local SQLite message/contact/security-event store. |

The vault is encrypted with:

- Scrypt KDF;
- 16-byte random salt;
- ChaCha20-Poly1305.

Local message bodies in `local.db` are encrypted using the vault’s `local_storage_key`. However, local metadata such as usernames, timestamps, counters, unread state, and fingerprints remain queryable in SQLite.

## Disappearing-Message Analysis

Disappearing messages use TTL metadata in message headers.

Implemented behavior:

- TTL and expiry metadata are authenticated as AEAD associated data.
- The server filters expired messages out of queue responses.
- A background server task marks expired/stale messages deleted.
- The client removes expired messages from local history.
- The GUI/shell attempt to refresh views when messages expire.

Limitations:

- Deletion is best effort.
- Recipients can screenshot, copy, or modify clients.
- SQLite storage may not guarantee forensic secure deletion.
- Clock skew can affect expiry behavior.
- The protocol does not prevent a malicious client from archiving plaintext before deletion.

## Abuse Controls

Implemented controls include:

- registration rate limit;
- OTP confirmation rate limit;
- login rate limit;
- friend request rate limit;
- password policy;
- username validation;
- message size limit;
- friend-only chat enforcement;
- block enforcement;
- duplicate message ID/counter rejection;
- malformed bundle/envelope rejection.

Rate limiting is in-memory and process-local. It resets on server restart and is not shared across multiple server processes.

## What Must Never Be Committed

Never commit:

```text
certs_dev/*
certs_network/*
db/cipherlink.sqlite3
db/server_master.key
client_profiles/
client_bootstrap/*
.env
*.key
*.pem
*.p12
*.pfx
*.sqlite3
*.db
```

This includes private keys, CA keys, databases, server master keys, client vaults, local client databases, generated bootstrap bundles, logs, and local environment files.

## Known Limitations and Recommended Improvements

| Limitation | Recommended improvement |
|---|---|
| No double ratchet or post-compromise security. | Add an audited ratcheting protocol or use a mature secure messaging protocol implementation. |
| Static X25519 chat key is reused until rotation. | Add per-session or per-message ratcheting and stronger key lifecycle management. |
| Server distributes public keys. | Add stronger transparency/auditing or user-verifiable key directory mechanisms. |
| WebSocket token is passed in the query string. | Replace with short-lived WebSocket tickets or a safer authenticated upgrade design. |
| SQLite is unencrypted. | Use full-database encryption, OS-level disk encryption, or a managed database with hardened access controls. |
| TLS private keys are generated unencrypted. | Set restrictive permissions immediately and store deployment keys outside the repository. |
| In-memory rate limiter. | Use Redis or another shared rate-limit backend for multi-process deployments. |
| In-memory WebSocket presence. | Use a shared pub/sub layer for multi-worker deployments. |
| No automated test suite in the uploaded archive. | Add tests for auth, key rotation, trust verification, message encryption, queue handling, and deployment scripts. |
| Dependency ranges are broad. | Add a lockfile or constraints file for reproducible builds. |