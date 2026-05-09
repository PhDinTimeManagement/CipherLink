from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


HKT = timezone(timedelta(hours=8), name="HKT")


def day_start(value: datetime, *, local_tz: tzinfo = HKT) -> datetime:
    localized = value.astimezone(local_tz)
    start = localized.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.astimezone(timezone.utc)


def history_retention_boundary(now: datetime | None = None, *, local_tz: tzinfo = HKT) -> datetime:
    reference = now if now is not None else utc_now()
    return day_start(reference, local_tz=local_tz) - timedelta(days=1)


def next_history_retention_cutoff(now: datetime | None = None, *, local_tz: tzinfo = HKT) -> datetime:
    reference = now if now is not None else utc_now()
    return day_start(reference, local_tz=local_tz) + timedelta(days=1)


def within_history_retention(value: str | None, *, now: datetime | None = None, local_tz: tzinfo = HKT) -> bool:
    created_at = parse_datetime(value)
    if created_at is None:
        return False
    return created_at >= history_retention_boundary(now=now, local_tz=local_tz)


def isoformat_z(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def urlsafe_b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def urlsafe_b64d(data: str) -> bytes:
    padding = "=" * ((4 - (len(data) % 4)) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def conversation_id_for_users(user_a: str, user_b: str) -> str:
    ordered = sorted([user_a.lower(), user_b.lower()])
    digest = hashlib.sha256("::".join(ordered).encode("utf-8")).hexdigest()
    return digest[:32]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def chunk_string(value: str, group: int = 4, sep: str = "-") -> str:
    return sep.join(value[i : i + group] for i in range(0, len(value), group))


def friendly_fingerprint(fingerprint_hex: str) -> str:
    return chunk_string(fingerprint_hex.upper(), 4, "-")
