from __future__ import annotations

from datetime import timedelta, timezone, tzinfo
from typing import Any

from shared.trust_logic import evaluate_contact_messaging_status
from shared.utils import HKT, history_retention_boundary, isoformat_z, parse_datetime, utc_now


TRUST_STATE_LABELS = {
    "verified": "Verified",
    "unverified": "Not verified",
    "key_change_pending": "Needs re-verification",
}

FRIENDSHIP_LABELS = {
    "accepted": "Friend",
    "pending": "Pending",
    "removed": "Removed",
}

EVENT_TYPE_LABELS = {
    "key_change": "Key changed",
    "local_key_change": "Own key changed",
    "verification_required": "Verification required",
    "peer_verification_required": "Friend must verify you",
}

UTC_DISPLAY_TIMEZONE = timezone.utc
HKT_DISPLAY_TIMEZONE = timezone(timedelta(hours=8), name="HKT")
GUI_DISPLAY_TIMEZONE = HKT_DISPLAY_TIMEZONE
CLI_DISPLAY_TIMEZONE = HKT_DISPLAY_TIMEZONE
HISTORY_RETENTION_TIMEZONE = HKT
UNAVAILABLE_MESSAGE_PLACEHOLDER = "Message no longer available"
DEFAULT_RECENT_HISTORY_LIMIT = 20
MESSAGE_STATUS_LABELS = {
    "sent": "Delivered",
    "delivered": "Read",
    "unavailable": "Unavailable",
}


def _timezone_label(display_tz: tzinfo) -> str:
    label = display_tz.tzname(None)
    return label if label else "UTC"


def format_timestamp(
    value: str | None,
    *,
    fallback: str = "Unknown time",
    include_seconds: bool = True,
    display_tz: tzinfo = UTC_DISPLAY_TIMEZONE,
) -> str:
    dt = parse_datetime(value)
    if dt is None:
        if value in (None, ""):
            return fallback
        return str(value)
    localized = dt.astimezone(display_tz)
    fmt = "%Y-%m-%d %H:%M:%S" if include_seconds else "%Y-%m-%d %H:%M"
    return f"{localized.strftime(fmt)} {_timezone_label(display_tz)}"


def now_timestamp(*, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> str:
    return format_timestamp(isoformat_z(utc_now()), display_tz=display_tz)


def yes_no(value: Any) -> str:
    return "Yes" if bool(value) else "No"


def short_id(value: str | None, length: int = 12) -> str:
    if not value:
        return "—"
    if len(value) <= length:
        return value
    return f"{value[:length]}…"


def trust_state_label(value: str | None) -> str:
    if not value:
        return "Unknown"
    return TRUST_STATE_LABELS.get(value, value.replace("_", " ").title())


def friendship_status_label(value: str | None) -> str:
    if not value:
        return "Unknown"
    return FRIENDSHIP_LABELS.get(value, value.replace("_", " ").title())


def event_type_label(value: str | None) -> str:
    if not value:
        return "Event"
    return EVENT_TYPE_LABELS.get(value, value.replace("_", " ").title())


def unread_label(count: int | None, *, zero_label: str = "No unread") -> str:
    total = int(count or 0)
    if total == 0:
        return str(zero_label)
    if total == 1:
        return "1 unread"
    return f"{total} unread"


def note_label(note: str | None) -> str:
    value = (note or "").strip()
    return value if value else "No note"


def ttl_label(ttl_seconds: int | None) -> str:
    if ttl_seconds is None:
        return "No disappearing timer"
    if ttl_seconds == 1:
        return "Disappears after 1 second"
    return f"Disappears after {ttl_seconds} seconds"


def unavailable_at_label(expires_at: str | None, *, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> str:
    if not expires_at:
        return "No unavailable time"
    return f"Unavailable at {format_timestamp(expires_at, display_tz=display_tz)}"


def expires_label(expires_at: str | None, *, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> str:
    return unavailable_at_label(expires_at, display_tz=display_tz)


def sent_status_label(status: str | None) -> str:
    if not status:
        return "Status unknown"
    cleaned = str(status).strip().replace("_", " ")
    mapped = MESSAGE_STATUS_LABELS.get(cleaned.lower())
    return mapped if mapped else cleaned.title()


def delivered_at_label(delivered_at: str | None, *, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> str:
    if not delivered_at:
        return "Read"
    return f"Read {format_timestamp(delivered_at, fallback='Unknown time', display_tz=display_tz)}"


def online_label(is_online: Any) -> str:
    return "Online now" if bool(is_online) else "Queued for delivery"


def contact_messaging_label(contact: dict[str, Any]) -> str:
    return evaluate_contact_messaging_status(contact).label


def contact_relationship_label(contact: dict[str, Any]) -> str:
    relationship = friendship_status_label(contact.get("friendship_status"))
    messaging = contact_messaging_label(contact)
    return f"{relationship} · {messaging}"


def format_contact_lines(contact: dict[str, Any], *, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> list[str]:
    lines = [
        f"• {contact.get('username', '?')} — {contact_relationship_label(contact)}",
        f"  Friends since: {format_timestamp(contact.get('since'), fallback='Unknown', display_tz=display_tz)}"
        if contact.get("since")
        else "  Friends since: Not available",
    ]
    flags: list[str] = []
    if contact.get("blocked_by_me"):
        flags.append("You blocked this contact")
    if contact.get("blocked_me"):
        flags.append("This contact blocked you")
    if flags:
        lines.append(f"  Notes: {'; '.join(flags)}")
    return lines


def format_request_lines(row: dict[str, Any], *, outgoing: bool, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> list[str]:
    request_id = row.get("request_id", "?")
    actor = row.get("receiver_username") if outgoing else row.get("sender_username")
    direction = "To" if outgoing else "From"
    created = format_timestamp(row.get("created_at"), display_tz=display_tz)
    return [
        f"• Request #{request_id} — {direction} {actor} — {created}",
        f"  Note: {note_label(row.get('note'))}",
    ]


def conversation_row_display(
    row: dict[str, Any],
    *,
    display_tz: tzinfo = UTC_DISPLAY_TIMEZONE,
    zero_unread_label: str = "No unread",
) -> tuple[str, str, str]:
    return (
        str(row.get("contact_username", "")),
        unread_label(int(row.get("unread_count") or 0), zero_label=zero_unread_label),
        format_timestamp(row.get("last_activity_at"), fallback="No messages yet", display_tz=display_tz),
    )


def contact_row_display(row: dict[str, Any], *, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> tuple[str, str, str, str]:
    return (
        str(row.get("username", "")),
        friendship_status_label(row.get("friendship_status")),
        contact_messaging_label(row),
        format_timestamp(row.get("since"), fallback="Unknown", display_tz=display_tz),
    )


def request_row_display(
    row: dict[str, Any],
    *,
    outgoing: bool,
    display_tz: tzinfo = UTC_DISPLAY_TIMEZONE,
) -> tuple[Any, str, str, str]:
    person = row.get("receiver_username") if outgoing else row.get("sender_username")
    return (
        row.get("request_id"),
        str(person or ""),
        note_label(row.get("note")),
        format_timestamp(row.get("created_at"), fallback="Unknown", display_tz=display_tz),
    )


def event_row_display(row: dict[str, Any], *, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> tuple[str, str, str, str]:
    return (
        format_timestamp(row.get("created_at"), fallback="Unknown", display_tz=display_tz),
        str(row.get("contact_username") or ""),
        event_type_label(row.get("event_type")),
        str(row.get("detail") or ""),
    )


def history_metadata_parts(
    row: dict[str, Any],
    contact_username: str,
    *,
    display_tz: tzinfo = UTC_DISPLAY_TIMEZONE,
) -> list[str]:
    created = format_timestamp(row.get("created_at"), fallback="Unknown time", display_tz=display_tz)
    direction = row.get("direction")
    speaker = "You" if direction == "out" else contact_username
    parts = [speaker, f"Delivered {created}"]

    if direction == "out":
        parts = [f"Delivered {created}", speaker]
    else:
        parts = [speaker, f"Delivered {created}"]

    if direction == "out":
        delivered_at = row.get("delivered_at")
        if delivered_at:
            parts.append(delivered_at_label(delivered_at, display_tz=display_tz))
    if row.get("expires_at"):
        parts.append(unavailable_at_label(row.get("expires_at"), display_tz=display_tz))
    return parts


def history_header(
    row: dict[str, Any],
    contact_username: str,
    *,
    display_tz: tzinfo = UTC_DISPLAY_TIMEZONE,
) -> str:
    return " • ".join(history_metadata_parts(row, contact_username, display_tz=display_tz))


def chat_header(
    row: dict[str, Any],
    contact_username: str,
    *,
    display_tz: tzinfo = UTC_DISPLAY_TIMEZONE,
) -> str:
    parts = history_metadata_parts(row, contact_username, display_tz=display_tz)
    return " • ".join(parts[:2])


def chat_secondary_header(
    row: dict[str, Any],
    contact_username: str,
    *,
    display_tz: tzinfo = UTC_DISPLAY_TIMEZONE,
) -> str:
    parts = history_metadata_parts(row, contact_username, display_tz=display_tz)
    return " • ".join(parts[2:])


def message_is_unavailable(row: dict[str, Any], *, now=None) -> bool:
    expires_at = parse_datetime(row.get("expires_at"))
    if expires_at is None:
        return False
    current = now if now is not None else utc_now()
    return expires_at <= current


def message_body_for_display(row: dict[str, Any]) -> str:
    if message_is_unavailable(row):
        return UNAVAILABLE_MESSAGE_PLACEHOLDER
    payload = row.get("payload", {})
    if isinstance(payload, dict):
        text = payload.get("text", "")
        if text is None:
            return ""
        return str(text)
    return ""


def fingerprint_summary_lines(info: dict[str, Any]) -> list[str]:
    return [
        f"Contact: {info.get('username', '?')}",
        f"Safety number: {info.get('display', 'Unavailable')}",
        f"Trust: {trust_state_label(info.get('trust_state'))}",
        f"Verified on this device: {yes_no(info.get('verified'))}",
    ]


def identity_summary_text(summary: dict[str, Any], *, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> str:
    profile = summary.get("profile_name") or "?"
    server_url = summary.get("server_url") or "?"
    fingerprint = summary.get("active_fingerprint") or "Unknown safety number"
    expires_at = format_timestamp(summary.get("session_expires_at"), fallback="Unknown", display_tz=display_tz)
    return (
        f"Profile {profile} • Server URL {server_url} • Session until {expires_at}\n"
        f"Safety number {fingerprint}"
    )



def chat_meta_text(contact: dict[str, Any] | None, fingerprint: dict[str, Any] | None, fingerprint_error: str | None = None) -> str:
    parts: list[str] = []
    if contact is not None:
        parts.append(contact_relationship_label(contact))
    if fingerprint is not None:
        parts.append(f"Safety number {fingerprint.get('display')}")
        parts.append(trust_state_label(fingerprint.get("trust_state")))
        if fingerprint.get("verified"):
            parts.append("Verified on this device")
    elif fingerprint_error:
        parts.append(fingerprint_error)
    return " • ".join(part for part in parts if part) or "Select a conversation to view details."


def send_result_text(
    result: dict[str, Any],
    username: str,
    *,
    ttl_seconds: int | None = None,
    display_tz: tzinfo = UTC_DISPLAY_TIMEZONE,
) -> str:
    created = format_timestamp(
        result.get("created_at") or result.get("submitted_at"),
        fallback="Unknown time",
        display_tz=display_tz,
    )
    ttl_text = ttl_label(ttl_seconds)
    return (
        f"Sent to {username} at {created} • {sent_status_label(result.get('status'))} • "
        f"{online_label(result.get('receiver_online'))} • ID {short_id(result.get('message_id'))} • {ttl_text}"
    )


def incoming_chat_text(item: dict[str, Any], *, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> str:
    created = format_timestamp(item.get("created_at"), fallback="Unknown time", display_tz=display_tz)
    text = item.get("text") or ""
    status = "new" if item.get("first_seen") else "already seen"
    ack = "read receipt sent" if item.get("ack_sent") else "read receipt not sent"
    extra = unavailable_at_label(item.get("expires_at"), display_tz=display_tz) if item.get("expires_at") else None
    tail = f" • {extra}" if extra else ""
    return f"New message from {item.get('from')} at {created} ({status}; {ack}){tail}: {text}"


def incoming_message_notice_text(item: dict[str, Any], *, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> str:
    created = format_timestamp(item.get("created_at"), fallback="Unknown time", display_tz=display_tz)
    extra = unavailable_at_label(item.get("expires_at"), display_tz=display_tz) if item.get("expires_at") else None
    tail = f" • {extra}" if extra else ""
    return f"New message from {item.get('from')} at {created}{tail}"


def incoming_message_hint_text(item: dict[str, Any]) -> str:
    username = str(item.get("from") or "USERNAME").strip().lower() or "USERNAME"
    return f"Type <open {username}> to read the message"


def delivery_ack_text(item: dict[str, Any], *, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> str:
    created = format_timestamp(item.get("created_at"), fallback="Unknown time", display_tz=display_tz)
    return (
        f"Read confirmed at {created} by {item.get('from')} for message {short_id(item.get('ack_for'))}."
    )


def sync_item_text(item: dict[str, Any], *, source: str, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> str:
    source_label = source.title()
    item_type = item.get("type")
    if item_type == "chat":
        return f"{source_label} sync • {incoming_message_notice_text(item, display_tz=display_tz)}"
    if item_type == "delivery_ack":
        return f"{source_label} sync • {delivery_ack_text(item, display_tz=display_tz)}"
    if item_type == "error":
        return f"{source_label} sync • Error: {item.get('detail', 'Unknown error')}"
    return f"{source_label} sync • {item}"


def activity_entry(message: str, *, display_tz: tzinfo = UTC_DISPLAY_TIMEZONE) -> str:
    return f"[{now_timestamp(display_tz=display_tz)}] {message}"


def history_retention_notice(
    *,
    display_tz: tzinfo = UTC_DISPLAY_TIMEZONE,
    retention_tz: tzinfo = HISTORY_RETENTION_TIMEZONE,
    now=None,
) -> str:
    boundary = history_retention_boundary(now=now, local_tz=retention_tz)
    return f"History messages are only available from {format_timestamp(isoformat_z(boundary), display_tz=display_tz)}"


def recent_history_limit_label(limit: int = DEFAULT_RECENT_HISTORY_LIMIT) -> str:
    return f"Shows only the most recent {int(limit)} chat records."


def recent_history_limit_notice(limit: int = DEFAULT_RECENT_HISTORY_LIMIT) -> str:
    return f"Showing only the most recent {int(limit)} chat records by default."
