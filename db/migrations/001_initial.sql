PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    otp_secret_ciphertext TEXT NOT NULL,
    otp_secret_nonce TEXT NOT NULL,
    otp_confirmed INTEGER NOT NULL DEFAULT 0,
    active_key_fingerprint TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users(lower(username));

CREATE TABLE IF NOT EXISTS key_bundles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    identity_public_key TEXT NOT NULL,
    chat_public_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    revoked_at TEXT,
    UNIQUE(user_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_key_bundles_user_active ON key_bundles(user_id, is_active);

CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    last_seen_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);

CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK(status IN ('pending', 'accepted', 'declined', 'cancelled')),
    note TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(sender_id <> receiver_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_friend_requests_pending ON friend_requests(sender_id, receiver_id) WHERE status = 'pending';

CREATE TABLE IF NOT EXISTS friendships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_low_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_high_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL CHECK(status IN ('accepted', 'removed')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK(user_low_id < user_high_id),
    UNIQUE(user_low_id, user_high_id)
);

CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    CHECK(blocker_id <> blocked_id),
    UNIQUE(blocker_id, blocked_id)
);


CREATE TABLE IF NOT EXISTS contact_verifications (
    verifier_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    verified_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    verified_fingerprint TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    CHECK(verifier_user_id <> verified_user_id),
    PRIMARY KEY (verifier_user_id, verified_user_id)
);

CREATE INDEX IF NOT EXISTS idx_contact_verifications_verified_user ON contact_verifications(verified_user_id);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL UNIQUE,
    conversation_id TEXT NOT NULL,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('chat', 'delivery_ack')),
    payload_version INTEGER NOT NULL DEFAULT 1,
    counter INTEGER NOT NULL,
    ttl_seconds INTEGER,
    sender_key_fingerprint TEXT NOT NULL,
    receiver_key_fingerprint TEXT NOT NULL,
    related_message_id TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    canonical_expires_at TEXT,
    nonce TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    consumed_at TEXT,
    delivered_at TEXT,
    deleted_at TEXT,
    last_pushed_at TEXT,
    size_bytes INTEGER NOT NULL,
    CHECK(sender_id <> receiver_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_messages_sender_counter ON messages(sender_id, conversation_id, counter);
CREATE INDEX IF NOT EXISTS idx_messages_receiver_queue ON messages(receiver_id, consumed_at, deleted_at, submitted_at);
CREATE INDEX IF NOT EXISTS idx_messages_cleanup ON messages(deleted_at, canonical_expires_at, submitted_at);
