from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

VERIFICATION_STATE_MISSING = "missing"
VERIFICATION_STATE_VERIFIED = "verified"
VERIFICATION_STATE_IDENTITY_CHANGED = "identity_changed"

REASON_YOU_HAVE_NOT_VERIFIED_FRIEND = "you_have_not_verified_this_friend"
REASON_FRIEND_HAS_NOT_VERIFIED_YOU = "this_friend_has_not_verified_you"
REASON_FRIEND_IDENTITY_CHANGED = "this_friend_identity_changed"
REASON_YOUR_IDENTITY_CHANGED = "your_identity_changed"

_REASON_PHRASES = {
    REASON_YOU_HAVE_NOT_VERIFIED_FRIEND: "you have not verified this friend",
    REASON_FRIEND_HAS_NOT_VERIFIED_YOU: "this friend has not verified you",
    REASON_FRIEND_IDENTITY_CHANGED: "this friend's identity changed",
    REASON_YOUR_IDENTITY_CHANGED: "your identity changed",
}


@dataclass(frozen=True, slots=True)
class ContactMessagingStatus:
    code: str
    label: str
    blocked: bool
    manual_blocked: bool
    reasons: tuple[str, ...]


def normalize_verification_state(value: str | None, *, default: str = VERIFICATION_STATE_VERIFIED) -> str:
    if value is None:
        return default
    cleaned = str(value).strip().lower()
    if cleaned in {
        VERIFICATION_STATE_MISSING,
        VERIFICATION_STATE_VERIFIED,
        VERIFICATION_STATE_IDENTITY_CHANGED,
    }:
        return cleaned
    return default


def _join_phrases(phrases: list[str]) -> str:
    if not phrases:
        return ""
    if len(phrases) == 1:
        return phrases[0]
    if len(phrases) == 2:
        return f"{phrases[0]} and {phrases[1]}"
    return ", ".join(phrases[:-1]) + f", and {phrases[-1]}"


def contact_security_reasons(contact: Mapping[str, Any]) -> tuple[str, ...]:
    my_state = normalize_verification_state(contact.get("my_verification_state"))
    friend_state = normalize_verification_state(contact.get("friend_verification_state"))

    reasons: list[str] = []
    if my_state == VERIFICATION_STATE_IDENTITY_CHANGED:
        reasons.append(REASON_FRIEND_IDENTITY_CHANGED)
    elif my_state != VERIFICATION_STATE_VERIFIED:
        reasons.append(REASON_YOU_HAVE_NOT_VERIFIED_FRIEND)

    if friend_state == VERIFICATION_STATE_IDENTITY_CHANGED:
        reasons.append(REASON_YOUR_IDENTITY_CHANGED)
    elif friend_state != VERIFICATION_STATE_VERIFIED:
        reasons.append(REASON_FRIEND_HAS_NOT_VERIFIED_YOU)
    return tuple(reasons)


def evaluate_contact_messaging_status(contact: Mapping[str, Any] | None) -> ContactMessagingStatus:
    if contact is None:
        return ContactMessagingStatus(
            code="unknown",
            label="Unknown",
            blocked=True,
            manual_blocked=False,
            reasons=(),
        )

    blocked_by_me = bool(contact.get("blocked_by_me"))
    blocked_me = bool(contact.get("blocked_me"))
    if blocked_by_me and blocked_me:
        return ContactMessagingStatus(
            code="blocked_both_ways",
            label="Blocked by you and this friend",
            blocked=True,
            manual_blocked=True,
            reasons=("blocked_by_you", "blocked_by_this_friend"),
        )
    if blocked_by_me:
        return ContactMessagingStatus(
            code="blocked_by_you",
            label="Blocked by you",
            blocked=True,
            manual_blocked=True,
            reasons=("blocked_by_you",),
        )
    if blocked_me:
        return ContactMessagingStatus(
            code="blocked_by_this_friend",
            label="Blocked by this friend",
            blocked=True,
            manual_blocked=True,
            reasons=("blocked_by_this_friend",),
        )

    if str(contact.get("friendship_status") or "").strip().lower() != "accepted":
        return ContactMessagingStatus(
            code="messaging_unavailable",
            label="Messaging unavailable",
            blocked=True,
            manual_blocked=False,
            reasons=(),
        )

    reasons = contact_security_reasons(contact)
    if not reasons:
        return ContactMessagingStatus(
            code="not_blocked",
            label="Not blocked",
            blocked=False,
            manual_blocked=False,
            reasons=(),
        )

    known_labels = {
        (REASON_YOU_HAVE_NOT_VERIFIED_FRIEND,): (
            "blocked_you_have_not_verified_this_friend",
            "Blocked because you have not verified this friend",
        ),
        (REASON_FRIEND_HAS_NOT_VERIFIED_YOU,): (
            "blocked_this_friend_has_not_verified_you",
            "Blocked because this friend has not verified you",
        ),
        (
            REASON_YOU_HAVE_NOT_VERIFIED_FRIEND,
            REASON_FRIEND_HAS_NOT_VERIFIED_YOU,
        ): (
            "blocked_neither_side_has_verified",
            "Blocked because neither side has verified the other",
        ),
        (REASON_FRIEND_IDENTITY_CHANGED,): (
            "blocked_due_to_this_friend_identity_change",
            "Blocked due to this friend’s identity change",
        ),
        (REASON_YOUR_IDENTITY_CHANGED,): (
            "blocked_due_to_your_identity_change",
            "Blocked due to your identity change",
        ),
        (
            REASON_FRIEND_IDENTITY_CHANGED,
            REASON_YOUR_IDENTITY_CHANGED,
        ): (
            "blocked_due_to_identity_changes_on_both_sides",
            "Blocked due to identity changes on both sides",
        ),
    }
    mapping = known_labels.get(tuple(reasons))
    if mapping is not None:
        code, label = mapping
        return ContactMessagingStatus(
            code=code,
            label=label,
            blocked=True,
            manual_blocked=False,
            reasons=reasons,
        )

    phrases = [_REASON_PHRASES.get(reason, reason.replace("_", " ")) for reason in reasons]
    return ContactMessagingStatus(
        code="blocked_due_to_multiple_security_conditions",
        label=f"Blocked because {_join_phrases(phrases)}",
        blocked=True,
        manual_blocked=False,
        reasons=reasons,
    )


def security_messaging_block_detail(status: ContactMessagingStatus) -> str:
    if not status.blocked or status.manual_blocked:
        return "Messaging is not blocked for this contact."
    if status.code == "blocked_you_have_not_verified_this_friend":
        return "Messaging is blocked because you have not verified this friend's current safety number yet."
    if status.code == "blocked_this_friend_has_not_verified_you":
        return "Messaging is blocked because this friend has not verified your current safety number yet."
    if status.code == "blocked_neither_side_has_verified":
        return "Messaging is blocked because neither side has verified the other's current safety number yet."
    if status.code == "blocked_due_to_this_friend_identity_change":
        return "Messaging is blocked because this friend changed identities. Verify the new safety number first."
    if status.code == "blocked_due_to_your_identity_change":
        return "Messaging is blocked because you changed identities. This friend must verify your current safety number first."
    if status.code == "blocked_due_to_identity_changes_on_both_sides":
        return "Messaging is blocked because both sides changed identities. Each side must verify the other's current safety number again."
    lowered = status.label[:1].lower() + status.label[1:]
    if lowered.endswith("."):
        return f"Messaging is blocked because {lowered}"
    return f"Messaging is blocked because {lowered}."
