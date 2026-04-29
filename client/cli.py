from __future__ import annotations

import argparse
import getpass
import sys

from client.api import APIError
from client.presentation import (
    CLI_DISPLAY_TIMEZONE,
    DEFAULT_RECENT_HISTORY_LIMIT,
    conversation_row_display,
    delivery_ack_text,
    event_row_display,
    fingerprint_summary_lines,
    format_contact_lines,
    format_request_lines,
    format_timestamp,
    history_header,
    history_retention_notice,
    incoming_chat_text,
    incoming_message_hint_text,
    incoming_message_notice_text,
    message_body_for_display,
    recent_history_limit_notice,
    send_result_text,
    short_id,
    trust_state_label,
)
from client.profile import ProfileError, normalize_profile_name
from client.runtime import ClientOperationError, ClientRuntime
from client.shell import CipherLinkShell


def prompt_if_missing(value: str | None, prompt: str, secret: bool = False) -> str:
    if value is not None:
        return value
    return getpass.getpass(prompt) if secret else input(prompt)



def positive_int_arg(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed



def ttl_seconds_arg(value: str) -> int:
    parsed = positive_int_arg(value)
    if parsed > 86400:
        raise argparse.ArgumentTypeError("must be between 1 and 86400 seconds")
    return parsed



def _print_section(title: str) -> None:
    print(title)
    print("-" * len(title))



def _print_request_lists(payload: dict[str, object]) -> None:
    incoming = payload.get("incoming", []) if isinstance(payload, dict) else []
    outgoing = payload.get("outgoing", []) if isinstance(payload, dict) else []

    _print_section("Incoming requests")
    if not incoming:
        print("No incoming requests.")
    else:
        for row in incoming:
            for line in format_request_lines(row, outgoing=False, display_tz=CLI_DISPLAY_TIMEZONE):
                print(line)
    print()
    _print_section("Outgoing requests")
    if not outgoing:
        print("No outgoing requests.")
    else:
        for row in outgoing:
            for line in format_request_lines(row, outgoing=True, display_tz=CLI_DISPLAY_TIMEZONE):
                print(line)



def _print_contacts(payload: dict[str, object]) -> None:
    contacts = payload.get("contacts", []) if isinstance(payload, dict) else []
    if not contacts:
        print("You do not have any contacts yet.")
        return
    _print_section("Contacts")
    for index, row in enumerate(contacts):
        if index:
            print()
        for line in format_contact_lines(row, display_tz=CLI_DISPLAY_TIMEZONE):
            print(line)



def _print_sync_results(results: list[dict[str, object]]) -> None:
    if not results:
        print("No queued messages to process.")
        return
    _print_section("Sync results")
    for item in results:
        item_type = item.get("type")
        if item_type == "duplicate":
            continue
        if item_type == "chat":
            print(f"• {incoming_message_notice_text(item, display_tz=CLI_DISPLAY_TIMEZONE)}")
            print(f"  Hint: {incoming_message_hint_text(item)}")
        elif item_type == "delivery_ack":
            print(f"• {delivery_ack_text(item, display_tz=CLI_DISPLAY_TIMEZONE)}")
        elif item_type == "error":
            print(f"• Error: {item.get('detail', 'Unknown error')}")
        else:
            print(f"• {item}")



def _print_history(
    rows: list[dict[str, object]],
    username: str,
    next_before: int | None,
    *,
    show_default_limit_note: bool = True,
) -> None:
    _print_section(f"Conversation with {username}")
    print(history_retention_notice(display_tz=CLI_DISPLAY_TIMEZONE))
    if show_default_limit_note:
        print(recent_history_limit_notice(DEFAULT_RECENT_HISTORY_LIMIT))
    print()
    if not rows:
        print("No local messages yet.")
    for row in rows:
        print(history_header(row, username, display_tz=CLI_DISPLAY_TIMEZONE))
        body = message_body_for_display(row)
        if body:
            for line in str(body).splitlines() or [""]:
                print(f"  {line}")
        print()
    if next_before is not None:
        print(f"More history available. Use --before {next_before} to load older messages.")



def _print_conversations(rows: list[dict[str, object]]) -> None:
    if not rows:
        print("No conversations yet.")
        return
    _print_section("Conversations")
    for row in rows:
        contact, unread, last_activity = conversation_row_display(row, display_tz=CLI_DISPLAY_TIMEZONE)
        print(f"• {contact} — {last_activity} — {unread}")



def _print_events(rows: list[dict[str, object]]) -> None:
    if not rows:
        print("No unresolved security events.")
        return
    _print_section("Security events")
    for row in rows:
        created, contact, event_type, detail = event_row_display(row, display_tz=CLI_DISPLAY_TIMEZONE)
        print(f"• {created} — {contact or 'Unknown contact'} — {event_type}")
        print(f"  {detail}")



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CipherLink client CLI")
    parser.add_argument("--profile", required=False, help="Profile name under ./client_profiles or the provided base directory")
    parser.add_argument("--base-dir", default=None, help="Optional base directory for client profiles")
    sub = parser.add_subparsers(dest="command", required=True)

    reg = sub.add_parser("register", help="Register a new account and generate local device keys")
    reg.add_argument("--username", required=True)
    reg.add_argument("--password", help="Account password. Prompted if omitted.")
    reg.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")
    reg.add_argument("--server-url", help="Example: https://192.168.1.50:8443")
    reg.add_argument("--ca-cert", help="Path to the trusted CA certificate for the server")
    reg.add_argument("--bootstrap-file", help="Path to a server bootstrap JSON file created by create_client_bootstrap.py")

    otp = sub.add_parser("confirm-otp", help="Confirm the TOTP during registration")
    otp.add_argument("--username", required=True)
    otp.add_argument("--password", help="Account password. Prompted if omitted.")
    otp.add_argument("--otp", required=True, help="Current six-digit TOTP code")
    otp.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")

    login = sub.add_parser("login", help="Log in with password + OTP")
    login.add_argument("--username", required=True)
    login.add_argument("--password", help="Account password. Prompted if omitted.")
    login.add_argument("--otp", required=True, help="Current six-digit TOTP code")
    login.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")

    logout = sub.add_parser("logout", help="Log out and revoke the current session")
    logout.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")

    shell = sub.add_parser("shell", help="Open the interactive shell")
    shell.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")

    sub.add_parser("gui", help="Open the CipherLink desktop GUI client")

    sub.add_parser("requests", help="List incoming and outgoing friend requests").add_argument(
        "--device-passphrase", help="Local vault passphrase. Prompted if omitted."
    )
    sub.add_parser("contacts", help="List accepted contacts").add_argument(
        "--device-passphrase", help="Local vault passphrase. Prompted if omitted."
    )

    add = sub.add_parser("send-friend-request", help="Send a friend request")
    add.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")
    add.add_argument("--to", required=True)
    add.add_argument("--note", default=None)

    accept = sub.add_parser("accept-request", help="Accept an incoming friend request")
    accept.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")
    accept.add_argument("--id", type=positive_int_arg, required=True)

    decline = sub.add_parser("decline-request", help="Decline an incoming friend request")
    decline.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")
    decline.add_argument("--id", type=positive_int_arg, required=True)

    cancel = sub.add_parser("cancel-request", help="Cancel an outgoing friend request")
    cancel.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")
    cancel.add_argument("--id", type=positive_int_arg, required=True)

    send = sub.add_parser("send", help="Send a text message")
    send.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")
    send.add_argument("--to", required=True)
    send.add_argument("--text", required=True)
    send.add_argument("--ttl", type=ttl_seconds_arg, default=None, help="Optional disappearing-message timer in seconds")

    sync = sub.add_parser("sync", help="Fetch queued message notifications without marking them as read")
    sync.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")

    history = sub.add_parser("history", help="Show local message history for a contact and mark it as read")
    history.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")
    history.add_argument("--user", required=True)
    history.add_argument("--limit", type=positive_int_arg, default=20)
    history.add_argument("--before", type=positive_int_arg, default=None, help="Pagination cursor from a previous history output")

    conversations = sub.add_parser("conversations", help="List local conversations and unread counters")
    conversations.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")

    fp = sub.add_parser("fingerprint", help="Show the current contact fingerprint / safety number")
    fp.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")
    fp.add_argument("--user", required=True)

    verify = sub.add_parser("verify-contact", help="Mark a contact's current fingerprint as verified")
    verify.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")
    verify.add_argument("--user", required=True)

    rotate = sub.add_parser("rotate-keys", help="Rotate the active local identity / agreement keypair")
    rotate.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")

    block = sub.add_parser("block", help="Block a user")
    block.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")
    block.add_argument("--user", required=True)

    unblock = sub.add_parser("unblock", help="Unblock a user")
    unblock.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")
    unblock.add_argument("--user", required=True)

    remove = sub.add_parser("remove-friend", help="Remove a contact")
    remove.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")
    remove.add_argument("--user", required=True)

    events = sub.add_parser("events", help="List unresolved local security events")
    events.add_argument("--device-passphrase", help="Local vault passphrase. Prompted if omitted.")

    return parser



def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    command = args.command
    if command == "gui":
        from client.gui_app import main as gui_main

        gui_args: list[str] = []
        if args.profile:
            gui_args.extend(["--profile", args.profile])
        if args.base_dir:
            gui_args.extend(["--base-dir", args.base_dir])
        return gui_main(gui_args)
    if not args.profile:
        parser.error("--profile is required for all non-GUI commands")
    runtime = ClientRuntime(profile_name=normalize_profile_name(args.profile), base_dir=args.base_dir)
    try:
        if command == "register":
            password = prompt_if_missing(args.password, "Account password: ", secret=True)
            device_passphrase = prompt_if_missing(args.device_passphrase, "Device vault passphrase: ", secret=True)
            if args.bootstrap_file:
                if args.server_url or args.ca_cert:
                    parser.error("register accepts either --bootstrap-file or the pair --server-url and --ca-cert, not both")
                result = runtime.register(
                    username=args.username,
                    password=password,
                    device_passphrase=device_passphrase,
                    bootstrap_path=args.bootstrap_file,
                )
            else:
                if not args.server_url or not args.ca_cert:
                    parser.error("register requires either --bootstrap-file or both --server-url and --ca-cert")
                result = runtime.register(
                    username=args.username,
                    password=password,
                    device_passphrase=device_passphrase,
                    server_url=args.server_url,
                    ca_cert_path=args.ca_cert,
                )
            _print_section("Registration created")
            print(f"Username: {result.get('username')}")
            print(result.get("message", "Registration succeeded."))
            print()
            print("Authenticator setup")
            print(f"  Base32 secret: {result.get('otp_secret_base32')}")
            print(f"  Provisioning URI: {result.get('otp_provisioning_uri')}")
            print()
            print("Next step: scan the provisioning URI or enter the secret into your authenticator app, then run confirm-otp.")
            return 0

        device_passphrase = prompt_if_missing(getattr(args, "device_passphrase", None), "Device vault passphrase: ", secret=True)
        runtime.unlock(device_passphrase)

        if command == "confirm-otp":
            password = prompt_if_missing(args.password, "Account password: ", secret=True)
            result = runtime.confirm_registration_otp(args.username, password, args.otp, device_passphrase)
            print(result.get("message", "OTP confirmed."))
            return 0
        if command == "login":
            password = prompt_if_missing(args.password, "Account password: ", secret=True)
            result = runtime.login(args.username, password, args.otp, device_passphrase)
            _print_section("Login successful")
            print(f"Username: {result.get('username')}")
            print(
                f"Session expires: {format_timestamp(result.get('expires_at'), fallback='Unknown', display_tz=CLI_DISPLAY_TIMEZONE)}"
            )
            print("The session token was saved in the encrypted local vault.")
            return 0
        if command == "logout":
            print(runtime.logout().get("message", "Logged out."))
            return 0
        if command == "shell":
            shell = CipherLinkShell(runtime)
            shell.cmdloop()
            runtime = shell.runtime
            return 0
        if command == "requests":
            _print_request_lists(runtime.list_requests())
            return 0
        if command == "contacts":
            _print_contacts(runtime.list_contacts())
            return 0
        if command == "send-friend-request":
            result = runtime.send_friend_request(args.to, args.note)
            print(f"Friend request sent to {result.get('receiver_username')}. Request #{result.get('request_id')}.")
            return 0
        if command == "accept-request":
            runtime.accept_request(args.id)
            print(f"Accepted request #{args.id}.")
            return 0
        if command == "decline-request":
            runtime.decline_request(args.id)
            print(f"Declined request #{args.id}.")
            return 0
        if command == "cancel-request":
            runtime.cancel_request(args.id)
            print(f"Cancelled request #{args.id}.")
            return 0
        if command == "send":
            result = runtime.send_text(args.to, args.text, ttl_seconds=args.ttl)
            print(send_result_text(result, args.to, ttl_seconds=args.ttl, display_tz=CLI_DISPLAY_TIMEZONE))
            return 0
        if command == "sync":
            _print_sync_results(runtime.sync_queue())
            return 0
        if command == "history":
            rows, next_before = runtime.history(args.user, limit=args.limit, before_local_id=args.before, mark_read=True)
            _print_history(
                rows,
                args.user,
                next_before,
                show_default_limit_note=(args.limit == DEFAULT_RECENT_HISTORY_LIMIT and args.before is None),
            )
            return 0
        if command == "conversations":
            try:
                runtime.list_contacts()
            except Exception:
                pass
            _print_conversations(runtime.conversation_list())
            return 0
        if command == "fingerprint":
            info = runtime.fingerprint_info(args.user)
            _print_section(f"Safety number for {info.username}")
            for line in fingerprint_summary_lines(info.__dict__):
                print(line)
            print(f"Raw fingerprint: {info.fingerprint}")
            return 0
        if command == "verify-contact":
            info = runtime.verify_contact(args.user)
            print(f"Verified {info.username}'s current identity.")
            print(f"Safety number: {info.display}")
            print(f"Trust: {trust_state_label(info.trust_state)}")
            return 0
        if command == "rotate-keys":
            print(runtime.rotate_keys().get("message", "Keys rotated."))
            return 0
        if command == "block":
            print(runtime.block_user(args.user).get("message", f"Blocked {args.user}."))
            return 0
        if command == "unblock":
            print(runtime.unblock_user(args.user).get("message", f"Unblocked {args.user}."))
            return 0
        if command == "remove-friend":
            print(runtime.remove_friend(args.user).get("message", f"Removed {args.user} from contacts."))
            return 0
        if command == "events":
            _print_events(runtime.unresolved_security_events())
            return 0
        parser.error(f"Unknown command: {command}")
        return 2
    except (APIError, ClientOperationError, ProfileError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        runtime.close()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
