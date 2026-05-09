from __future__ import annotations

import _thread
import cmd
from dataclasses import dataclass, asdict
import getpass
import json
import os
import signal
import sys
import threading
import time
from datetime import timedelta
from textwrap import dedent
from typing import Any, Iterable
from urllib.parse import quote

import httpx
from cryptography.exceptions import InvalidTag
from websockets.sync.client import connect as ws_connect

from client.api import APIError
from client.profile import ProfileError
from client.runtime import ClientOperationError, ClientRuntime
from client.presentation import (
    CLI_DISPLAY_TIMEZONE,
    DEFAULT_RECENT_HISTORY_LIMIT,
    conversation_row_display,
    delivery_ack_text,
    event_row_display,
    fingerprint_summary_lines,
    format_contact_lines,
    format_request_lines,
    history_header,
    history_retention_notice,
    incoming_message_hint_text,
    incoming_message_notice_text,
    message_is_unavailable,
    message_body_for_display,
    note_label,
    recent_history_limit_notice,
    send_result_text,
    short_id,
)
from shared.utils import next_history_retention_cutoff, parse_datetime, utc_now


def _format_help(
    command: str,
    *,
    what: str,
    syntax: str,
    required: Iterable[str] | None = None,
    optional: Iterable[str] | None = None,
    example: str,
    notes: Iterable[str] | None = None,
) -> str:
    required_lines = list(required or ["None."])
    optional_lines = list(optional or ["None."])
    note_lines = list(notes or ["None."])
    return dedent(
        f"""
        Command: {command}

        What it does:
          {what}

        Syntax:
          {syntax}

        Required arguments:
          """
    ).rstrip() + "\n" + "\n".join(f"  - {line}" for line in required_lines) + "\n\n" + dedent(
        """
        Optional arguments:
        """
    ).rstrip() + "\n" + "\n".join(f"  - {line}" for line in optional_lines) + "\n\n" + dedent(
        f"""
        Example:
          {example}

        Important notes:
        """
    ).rstrip() + "\n" + "\n".join(f"  - {line}" for line in note_lines)


@dataclass(slots=True)
class SecureRefreshRequest:
    username: str
    limit: int
    before_local_id: int | None
    reason: str
    full_history: bool = False


@dataclass(slots=True)
class SessionExpiredLogoutRequest:
    message: str
    reason: str


FULL_HISTORY_PAGE_SIZE = 200


COMMAND_HELP: dict[str, str] = {
    "help": _format_help(
        "help",
        what="Show the command list, or show the full help text for one specific shell command.",
        syntax="help [command]",
        optional=["command: The command name to inspect, for example send, open, or verify_contact."],
        example="help sendttl",
        notes=[
            "Running help with no argument prints the command index grouped by documented commands.",
            "The shell also accepts ? as a shortcut for help because it inherits from Python's cmd module.",
            "Help lookup is tolerant of case for built-in EOF and also accepts hyphen/underscore variants for command names.",
        ],
    ),
    "sync": _format_help(
        "sync",
        what="Fetch pending envelopes from the server, decrypt unread messages into the local store, and show reminders without marking them as read.",
        syntax="sync",
        example="sync",
        notes=[
            "Use this after logging in if you were offline or if you want to force a manual queue check.",
            "Unread messages stay unread until you open the conversation with the open command.",
            "Sync does not send read receipts; messages become read only after you actually open and read the conversation.",
        ],
    ),
    "contacts": _format_help(
        "contacts",
        what="List your current contact relationships from the server, including friendship and block status flags.",
        syntax="contacts",
        example="contacts",
        notes=[
            "The output shows friendship_status plus whether you blocked the other user or they blocked you.",
            "This command reads server state; it does not show local conversation history.",
        ],
    ),
    "requests": _format_help(
        "requests",
        what="List pending incoming and outgoing friend requests.",
        syntax="requests",
        example="requests",
        notes=[
            "Use the numeric request_id shown here with accept, decline, or cancel.",
            "Accepted or declined requests no longer appear as pending.",
        ],
    ),
    "add": _format_help(
        "add",
        what="Send a friend request to another registered user.",
        syntax="add <username> [note]",
        required=["username: The target username to send the request to."],
        optional=["note: Optional free-text note appended to the request. It may contain spaces."],
        example="add bob Hi Bob, this is Alice from the project demo.",
        notes=[
            "The target username is normalized to lowercase before the request is sent.",
            "The server rejects duplicate, invalid, or blocked friend requests.",
        ],
    ),
    "accept": _format_help(
        "accept",
        what="Accept a pending incoming friend request.",
        syntax="accept <request_id>",
        required=["request_id: Integer ID of a pending incoming request."],
        example="accept 12",
        notes=[
            "Use requests first to discover the correct request_id.",
            "Only the receiver of a pending request can accept it.",
        ],
    ),
    "decline": _format_help(
        "decline",
        what="Decline a pending incoming friend request.",
        syntax="decline <request_id>",
        required=["request_id: Integer ID of a pending incoming request."],
        example="decline 12",
        notes=[
            "Use requests first to discover the correct request_id.",
            "Only the receiver of a pending request can decline it.",
        ],
    ),
    "cancel": _format_help(
        "cancel",
        what="Cancel a friend request that you previously sent and that is still pending.",
        syntax="cancel <request_id>",
        required=["request_id: Integer ID of a pending outgoing request."],
        example="cancel 21",
        notes=[
            "Use requests first to discover the correct request_id.",
            "Only the sender of a pending request can cancel it.",
        ],
    ),
    "block": _format_help(
        "block",
        what="Block another user.",
        syntax="block <username>",
        required=["username: The user to block."],
        example="block bob",
        notes=[
            "Blocking does not remove an existing friendship or contact entry.",
            "Blocked users stay visible in contacts, but chat messaging is disabled while either side remains blocked.",
        ],
    ),
    "unblock": _format_help(
        "unblock",
        what="Remove a block that you previously placed on another user.",
        syntax="unblock <username>",
        required=["username: The user to unblock."],
        example="unblock bob",
        notes=[
            "Unblocking does not change friendship status or remove the contact entry.",
            "Chat resumes only when neither side is blocking the other.",
        ],
    ),
    "remove": _format_help(
        "remove",
        what="Remove an accepted friend from your contact list.",
        syntax="remove <username>",
        required=["username: The contact to remove."],
        example="remove bob",
        notes=[
            "Removing a friend affects the friendship relationship only; local message history still follows the automatic one-day retention window.",
            "After removal, users must become friends again before sending new chat messages.",
        ],
    ),
    "send": _format_help(
        "send",
        what="Encrypt and send a normal chat message to one contact.",
        syntax="send <username> <message text>",
        required=[
            "username: The friend who should receive the message.",
            "message text: The plaintext to encrypt and send. It may contain spaces.",
        ],
        example="send bob Hello Bob, this message is end-to-end encrypted.",
        notes=[
            "Message text must be between 1 and 4000 characters.",
            "New friendships require Verify before the first normal chat message can be sent.",
            "The command refuses to send if the contact changed keys and you have not re-verified the new fingerprint.",
            "After you rotate your own active keys, the other side must verify your new safety number before normal chat resumes.",
            "Only accepted friends can exchange chat messages, and blocked users cannot receive new messages.",
        ],
    ),
    "sendttl": _format_help(
        "sendttl",
        what="Encrypt and send a disappearing chat message with a time-to-live in seconds.",
        syntax="sendttl <username> <ttl_seconds> <message text>",
        required=[
            "username: The friend who should receive the message.",
            "ttl_seconds: Positive integer lifetime for the message in seconds.",
            "message text: The plaintext to encrypt and send. It may contain spaces.",
        ],
        example="sendttl bob 30 This message should disappear after thirty seconds.",
        notes=[
            "The expiry metadata is authenticated inside the encrypted envelope header.",
            "New friendships require Verify before the first normal chat message can be sent.",
            "After you rotate your own active keys, the other side must verify your new safety number before normal chat resumes.",
            "After expiry, local history keeps the timestamps but replaces the original content with an unavailable placeholder.",
            "If a disappearing message expires while its plaintext is visible in the currently open conversation, the shell performs a secure session refresh to reduce terminal plaintext exposure.",
            "A disappearing timer does not prevent screenshots, copy/paste, or malicious clients from preserving content.",
        ],
    ),
    "conversations": _format_help(
        "conversations",
        what="Show the local conversation list with last activity timestamps and unread counters.",
        syntax="conversations",
        example="conversations",
        notes=[
            "The list is built from locally stored message history after decryption.",
            "Unread counts decrease when you open a conversation with the open command.",
        ],
    ),
    "open": _format_help(
        "open",
        what="Display decrypted chat history with one contact, optionally with pagination or the full local history.",
        syntax="open <username> [limit] [before_local_id]\n  open <username> full",
        required=["username: The contact whose conversation you want to view."],
        optional=[
            "limit: Maximum number of messages to display. Defaults to 20.",
            "before_local_id: Local pagination cursor. Show messages older than this local message ID.",
            "full: Load the complete local conversation history for this contact in one view.",
        ],
        example="open bob full",
        notes=[
            "The command reads local history only; it does not fetch new messages from the server. Run sync first if needed.",
            "Opening a conversation marks its incoming messages as read and sends read receipts when possible.",
            "History output only includes messages inside the current one-day retention window and prints that boundary at the top.",
            "If a disappearing message later expires while this open conversation is still visible, the shell clears the terminal and refreshes the session before reopening the conversation.",
            "If more history exists, the shell prints a 'Next page cursor' value that you can feed back into before_local_id.",
        ],
    ),
    "fingerprint": _format_help(
        "fingerprint",
        what="Display the current active fingerprint for a contact together with current trust state information.",
        syntax="fingerprint <username>",
        required=["username: The contact whose active key fingerprint you want to inspect."],
        example="fingerprint bob",
        notes=[
            "Use this before verify_contact to compare the shown fingerprint out of band.",
            "If the contact rotated keys, this command can surface the new active fingerprint and current trust state.",
        ],
    ),
    "verify_contact": _format_help(
        "verify_contact",
        what="Mark the contact's current active fingerprint as verified on this client.",
        syntax="verify_contact <username>",
        required=["username: The contact whose currently active fingerprint you have checked out of band."],
        example="verify_contact bob",
        notes=[
            "This command records that you verified the contact's currently active fingerprint for the current friendship.",
            "Use it only after independently comparing fingerprints outside the chat channel.",
            "Verifying a changed fingerprint resolves related security events and allows sending to that contact again.",
        ],
    ),
    "rotate": _format_help(
        "rotate",
        what="Generate a new local keypair, upload the new public bundle, and make the new fingerprint active for future messages.",
        syntax="rotate",
        example="rotate",
        notes=[
            "Other users will see a key-change warning the next time they fetch your bundle or receive a message tied to the new fingerprint.",
            "Existing locally stored private key material is kept so this client can still decrypt history addressed to older fingerprints.",
        ],
    ),
    "events": _format_help(
        "events",
        what="List unresolved local security events, such as detected contact key changes.",
        syntax="events",
        example="events",
        notes=[
            "Use this to review security-relevant warnings recorded by the client.",
            "Verifying a contact after a key change marks related events as resolved.",
        ],
    ),
    "logout": _format_help(
        "logout",
        what="Log out from the server, revoke the current session token, stop the websocket listener, and exit the shell.",
        syntax="logout",
        example="logout",
        notes=[
            "This command talks to the server and invalidates the current session token.",
            "After logout, you must log in again before opening the shell in a new session.",
        ],
    ),
    "exit": _format_help(
        "exit",
        what="Close the interactive shell without calling the server logout endpoint.",
        syntax="exit",
        example="exit",
        notes=[
            "This stops the websocket listener and returns you to the system prompt.",
            "Your stored session token remains in the local vault, so you can reopen the shell without logging in again until the token expires or you explicitly log out.",
        ],
    ),
    "quit": _format_help(
        "quit",
        what="Close the interactive shell without calling the server logout endpoint.",
        syntax="quit",
        example="quit",
        notes=[
            "quit is an alias of exit in this shell implementation.",
            "Your stored session token remains in the local vault, so you can reopen the shell without logging in again until the token expires or you explicitly log out.",
        ],
    ),
    "EOF": _format_help(
        "EOF",
        what="Close the interactive shell by sending an end-of-file signal, without calling the server logout endpoint.",
        syntax="EOF",
        example="EOF",
        notes=[
            "You normally trigger this with Ctrl-D on Unix-like terminals or Ctrl-Z followed by Enter on Windows terminals.",
            "Typing the literal word EOF at the prompt also exits because the shell exposes do_EOF as a command handler.",
            "Like exit and quit, this keeps the current local session token unless you explicitly run logout.",
        ],
    ),
}


def _attach_command_help() -> None:
    for command_name, help_text in COMMAND_HELP.items():
        method_name = "do_EOF" if command_name == "EOF" else f"do_{command_name}"
        method = getattr(CipherLinkShell, method_name, None)
        if method is not None:
            method.__doc__ = help_text


class CipherLinkShell(cmd.Cmd):
    intro = "CipherLink shell. Type help or ? to list commands."
    prompt = "cipherlink> "

    def __init__(self, runtime: ClientRuntime):
        super().__init__()
        self.runtime = runtime
        self._stop_event = threading.Event()
        self._output_lock = threading.RLock()
        self._open_view_username: str | None = None
        self._open_view_limit: int = 20
        self._open_view_before: int | None = None
        self._open_view_full_history = False
        self._open_view_render_signature: tuple[Any, ...] | None = None
        self._open_view_sensitive_expiry_at: str | None = None
        self._open_view_retention_cutoff_at: str | None = None
        self._pending_secure_refresh: SecureRefreshRequest | None = None
        self._pending_session_logout: SessionExpiredLogoutRequest | None = None
        self._secure_refresh_wake_requested = False
        self._session_logout_wake_requested = False
        self._command_active = False
        self._suppress_next_connected_notice = False
        self._listener_thread: threading.Thread | None = None
        self._expiry_thread: threading.Thread | None = None
        self._start_background_threads()

    def cmdloop(self, intro: str | None = None) -> None:
        if self._using_windows_console_prompt():
            return self._cmdloop_windows(intro=intro)
        while True:
            try:
                return super().cmdloop(intro=intro)
            except KeyboardInterrupt:
                if self._pending_session_logout is not None:
                    intro = None
                    if not self._handle_pending_session_logout():
                        return
                    continue
                if self._pending_secure_refresh is not None:
                    intro = None
                    if not self._handle_pending_secure_refresh():
                        return
                    continue
                print("\nInterrupted. Shell is still active. Use exit, quit, logout, or EOF to leave.")
                intro = None

    def _using_windows_console_prompt(self) -> bool:
        if os.name != "nt" or not self.use_rawinput:
            return False
        try:
            stdin = sys.stdin
            stdout = sys.stdout
            if stdin is None or stdout is None:
                return False
            if hasattr(stdin, "isatty") and not stdin.isatty():
                return False
            if hasattr(stdout, "isatty") and not stdout.isatty():
                return False
            self._get_windows_console_module()
            return True
        except Exception:
            return False

    @staticmethod
    def _get_windows_console_module():
        import msvcrt

        return msvcrt

    def _cmdloop_windows(self, intro: str | None = None) -> None:
        self.preloop()
        if self.use_rawinput and self.completekey:
            try:
                import readline  # type: ignore
            except ImportError:
                readline = None
            if readline is not None:
                try:
                    self.old_completer = readline.get_completer()
                    readline.set_completer(self.complete)
                    if readline.backend == "editline":
                        if self.completekey == "tab":
                            command_string = "bind ^I rl_complete"
                        else:
                            command_string = f"bind {self.completekey} rl_complete"
                    else:
                        command_string = f"{self.completekey}: complete"
                    readline.parse_and_bind(command_string)
                except Exception:
                    readline = None
        else:
            readline = None

        try:
            if intro is not None:
                self.intro = intro
            if self.intro:
                self.stdout.write(str(self.intro) + "\n")
            stop = False
            while not stop:
                try:
                    if self.cmdqueue:
                        line = self.cmdqueue.pop(0)
                    else:
                        if self._pending_session_logout is not None:
                            if not self._handle_pending_session_logout():
                                return
                            continue
                        if self._pending_secure_refresh is not None:
                            if not self._handle_pending_secure_refresh():
                                return
                            continue
                        line = self._readline_windows_prompt(self.prompt)
                except KeyboardInterrupt:
                    if self._pending_session_logout is not None:
                        if not self._handle_pending_session_logout():
                            return
                        continue
                    if self._pending_secure_refresh is not None:
                        if not self._handle_pending_secure_refresh():
                            return
                        continue
                    print("\nInterrupted. Shell is still active. Use exit, quit, logout, or EOF to leave.")
                    continue
                except EOFError:
                    line = "EOF"

                line = self.precmd(line)
                stop = bool(self.onecmd(line))
                stop = bool(self.postcmd(stop, line))
        finally:
            self.postloop()
            if readline is not None:
                try:
                    readline.set_completer(self.old_completer)
                except Exception:
                    pass

    def _readline_windows_prompt(self, prompt: str) -> str:
        msvcrt = self._get_windows_console_module()
        with self._output_lock:
            print(prompt, end="", flush=True)
        buffer: list[str] = []
        while True:
            if self._pending_session_logout is not None or self._pending_secure_refresh is not None:
                with self._output_lock:
                    print()
                raise KeyboardInterrupt
            if not msvcrt.kbhit():
                time.sleep(0.05)
                continue
            ch = msvcrt.getwch()
            if ch in {"\r", "\n"}:
                with self._output_lock:
                    print()
                return "".join(buffer)
            if ch == "\x03":
                with self._output_lock:
                    print("^C")
                raise KeyboardInterrupt
            if ch == "\x1a":
                with self._output_lock:
                    print("^Z")
                return "EOF"
            if ch in {"\x00", "\xe0"}:
                try:
                    msvcrt.getwch()
                except Exception:
                    pass
                continue
            if ch in {"\b", "\x7f"}:
                if buffer:
                    buffer.pop()
                    with self._output_lock:
                        print("\b \b", end="", flush=True)
                continue
            buffer.append(ch)
            with self._output_lock:
                print(ch, end="", flush=True)

    def emptyline(self) -> bool:
        """Do nothing on an empty prompt instead of repeating the last command."""
        return False

    def onecmd(self, line: str) -> bool:
        command_name, _, _ = self.parseline(line)
        normalized_command = (command_name or "").strip().lower()
        if normalized_command and normalized_command != "open":
            self._clear_open_view()
        try:
            self._command_active = True
            return bool(super().onecmd(line))
        except KeyboardInterrupt:
            if self._pending_session_logout is not None or self._pending_secure_refresh is not None:
                raise
            self._print_command_error(line, "Command interrupted. Shell is still active.")
            return False
        except (APIError, ClientOperationError, ProfileError, ValueError) as exc:
            if self._is_session_expired_error(exc):
                self._request_session_expired_logout()
                raise KeyboardInterrupt
            self._print_command_error(line, self._format_command_error(exc))
            return False
        except httpx.HTTPError as exc:
            self._print_command_error(line, f"Network error: {exc}")
            return False
        except Exception as exc:
            self._print_command_error(line, f"Unexpected error: {exc}")
            return False
        finally:
            self._command_active = False
            if self._pending_session_logout is not None and not self._session_logout_wake_requested:
                if self._using_windows_console_prompt():
                    self._session_logout_wake_requested = True
                else:
                    self._session_logout_wake_requested = True
                    try:
                        _thread.interrupt_main()
                    except Exception:
                        self._session_logout_wake_requested = False
            elif self._pending_secure_refresh is not None and not self._secure_refresh_wake_requested:
                if self._using_windows_console_prompt():
                    self._secure_refresh_wake_requested = True
                else:
                    self._secure_refresh_wake_requested = True
                    try:
                        _thread.interrupt_main()
                    except Exception:
                        self._secure_refresh_wake_requested = False

    def _resolve_help_target(self, raw_name: str) -> str | None:
        cleaned = raw_name.strip()
        if not cleaned:
            return None
        if cleaned in COMMAND_HELP:
            return cleaned
        alternate = cleaned.replace("-", "_")
        if alternate in COMMAND_HELP:
            return alternate
        lowered = alternate.lower()
        for command_name in COMMAND_HELP:
            if command_name.lower() == lowered:
                return command_name
        return None

    @staticmethod
    def _usage_error(*usage_lines: str) -> ValueError:
        if not usage_lines:
            return ValueError("Invalid command arguments.")
        first_line, *remaining_lines = usage_lines
        if first_line.startswith("Usage:"):
            lines = [first_line, *remaining_lines]
        else:
            lines = [f"Usage: {first_line}", *remaining_lines]
        return ValueError("\n".join(lines))

    def _require_no_arguments(self, arg: str, *, usage: str) -> None:
        if arg.strip():
            raise self._usage_error(usage)

    def _parse_single_token_argument(self, arg: str, *, usage: str) -> str:
        parts = arg.split()
        if len(parts) != 1:
            raise self._usage_error(usage)
        return parts[0]

    def _parse_positive_int_argument(
        self,
        arg: str,
        *,
        usage: str,
        minimum: int = 1,
        maximum: int | None = None,
    ) -> int:
        token = self._parse_single_token_argument(arg, usage=usage)
        try:
            value = int(token)
        except ValueError as exc:
            raise self._usage_error(usage) from exc
        if value < minimum or (maximum is not None and value > maximum):
            raise self._usage_error(usage)
        return value

    def _parse_help_argument(self, arg: str) -> str | None:
        cleaned = arg.strip()
        if not cleaned:
            return None
        parts = cleaned.split()
        if len(parts) != 1:
            raise self._usage_error("help [command]")
        return parts[0]

    def _parse_username_and_optional_text(self, arg: str, *, usage: str) -> tuple[str, str | None]:
        parts = arg.split(maxsplit=1)
        if not parts:
            raise self._usage_error(usage)
        username = parts[0]
        note = parts[1] if len(parts) > 1 else None
        return username, note

    def _parse_send_arguments(self, arg: str, *, usage: str) -> tuple[str, str]:
        parts = arg.split(maxsplit=1)
        if len(parts) != 2:
            raise self._usage_error(usage)
        return parts[0], parts[1]

    def _parse_sendttl_arguments(self, arg: str) -> tuple[str, int, str]:
        usage = "sendttl <username> <ttl_seconds> <message text>"
        parts = arg.split(maxsplit=2)
        if len(parts) != 3:
            raise self._usage_error(usage)
        try:
            ttl_seconds = int(parts[1])
        except ValueError as exc:
            raise self._usage_error(usage) from exc
        if ttl_seconds < 1 or ttl_seconds > 86400:
            raise self._usage_error(usage)
        return parts[0], ttl_seconds, parts[2]

    def _parse_open_arguments(self, arg: str) -> tuple[str, int, int | None, bool]:
        usage = "open <username> [limit] [before_local_id]"
        full_usage = "       open <username> full"
        parts = arg.split()
        if not parts or len(parts) > 3:
            raise self._usage_error(usage, full_usage)
        username = parts[0]
        if len(parts) == 2 and parts[1].lower() == "full":
            return username, 20, None, True
        if len(parts) > 1 and parts[1].lower() == "full":
            raise self._usage_error("open <username> full")
        try:
            limit = int(parts[1]) if len(parts) > 1 else 20
            before = int(parts[2]) if len(parts) > 2 else None
        except ValueError as exc:
            raise self._usage_error(usage, full_usage) from exc
        if limit < 1 or (before is not None and before < 1):
            raise self._usage_error(usage, full_usage)
        return username, limit, before, False

    def do_help(self, arg: str) -> None:
        requested_target = self._parse_help_argument(arg)
        if requested_target is None:
            super().do_help("")
            return
        target = self._resolve_help_target(requested_target)
        if target is not None:
            print(COMMAND_HELP[target])
            return
        super().do_help(requested_target)

    def postcmd(self, stop: bool, line: str) -> bool:
        return stop

    def _start_background_threads(self) -> None:
        self._stop_event = threading.Event()
        self._listener_thread = threading.Thread(target=self._listener_loop, daemon=True)
        self._expiry_thread = threading.Thread(target=self._expiry_loop, daemon=True)
        self._listener_thread.start()
        self._expiry_thread.start()

    def _discard_pending_terminal_input(self) -> None:
        try:
            stdin = sys.stdin
            fileno = stdin.fileno()
        except Exception:
            fileno = None
        if fileno is not None:
            try:
                if os.isatty(fileno):
                    try:
                        import termios

                        termios.tcflush(fileno, termios.TCIFLUSH)
                        return
                    except Exception:
                        pass
            except Exception:
                pass
        try:
            import msvcrt

            while msvcrt.kbhit():
                msvcrt.getwch()
        except Exception:
            pass

    def _wake_prompt_for_secure_refresh(self) -> bool:
        if self._using_windows_console_prompt():
            return True
        if threading.current_thread() is threading.main_thread():
            return False
        try:
            main_ident = threading.main_thread().ident
            if main_ident is not None and hasattr(signal, "pthread_kill"):
                signal.pthread_kill(main_ident, signal.SIGINT)
                return True
        except Exception:
            pass
        try:
            os.kill(os.getpid(), signal.SIGINT)
            return True
        except Exception:
            pass
        try:
            _thread.interrupt_main()
            return True
        except Exception:
            return False

    def _clear_open_view(self) -> None:
        self._open_view_username = None
        self._open_view_before = None
        self._open_view_limit = 20
        self._open_view_full_history = False
        self._open_view_render_signature = None
        self._open_view_sensitive_expiry_at = None
        self._open_view_retention_cutoff_at = None
        self._secure_refresh_wake_requested = False
        self._session_logout_wake_requested = False

    def _load_history_for_open(
        self,
        username: str,
        *,
        limit: int,
        before_local_id: int | None,
        mark_read: bool,
        full_history: bool,
    ) -> tuple[list[dict[str, Any]], int | None]:
        if not full_history:
            return self.runtime.history(username, limit=limit, before_local_id=before_local_id, mark_read=mark_read)

        all_rows: list[dict[str, Any]] = []
        next_before = before_local_id
        page_mark_read = mark_read
        final_next_before: int | None = None
        while True:
            page_rows, page_next_before = self.runtime.history(
                username,
                limit=FULL_HISTORY_PAGE_SIZE,
                before_local_id=next_before,
                mark_read=page_mark_read,
            )
            all_rows = page_rows + all_rows
            final_next_before = page_next_before
            if page_next_before is None or not page_rows:
                break
            next_before = page_next_before
            page_mark_read = False
        return all_rows, final_next_before

    @staticmethod
    def _history_view_signature(
        username: str,
        rows: list[dict[str, Any]],
        next_before: int | None,
    ) -> tuple[Any, ...]:
        normalized_rows: list[tuple[Any, ...]] = []
        for row in rows:
            normalized_rows.append(
                (
                    row.get("local_id"),
                    row.get("direction"),
                    row.get("created_at"),
                    row.get("sent_status"),
                    row.get("delivered_at"),
                    row.get("expires_at"),
                    message_body_for_display(row),
                )
            )
        return (username.lower(), next_before, tuple(normalized_rows))

    def _update_open_view_sensitive_expiry(self, rows: list[dict[str, Any]]) -> None:
        next_expiry_dt = None
        for row in rows:
            expires_at = row.get("expires_at")
            if not expires_at or message_is_unavailable(row):
                continue
            body = message_body_for_display(row)
            if not body:
                continue
            expires_dt = parse_datetime(expires_at)
            if expires_dt is None:
                continue
            if next_expiry_dt is None or expires_dt < next_expiry_dt:
                next_expiry_dt = expires_dt
        self._open_view_sensitive_expiry_at = None if next_expiry_dt is None else next_expiry_dt.isoformat().replace("+00:00", "Z")

    def _update_open_view_retention_cutoff(self, rows: list[dict[str, Any]]) -> None:
        if self._open_view_username is not None:
            self._open_view_retention_cutoff_at = next_history_retention_cutoff().isoformat().replace("+00:00", "Z")
        else:
            self._open_view_retention_cutoff_at = None

    def _current_open_view_deadline(self, username: str) -> tuple[str, str] | None:
        if self._open_view_username != username:
            return None
        due_candidates: list[tuple[str, str]] = []
        if self._open_view_sensitive_expiry_at:
            due_candidates.append(("_open_view_sensitive_expiry_at", self._open_view_sensitive_expiry_at))
        if self._open_view_retention_cutoff_at:
            due_candidates.append(("_open_view_retention_cutoff_at", self._open_view_retention_cutoff_at))
        if not due_candidates:
            return None
        return min(due_candidates, key=lambda item: parse_datetime(item[1]) or utc_now())

    def _wait_until_open_view_deadline_due(self, username: str, attr_name: str, due_at: str) -> bool:
        expires_dt = parse_datetime(due_at)
        if expires_dt is None:
            return False
        refresh_deadline = expires_dt + timedelta(milliseconds=75)
        while not self._stop_event.is_set():
            if self._current_open_view_deadline(username) != (attr_name, due_at):
                return False
            remaining = (refresh_deadline - utc_now()).total_seconds()
            if remaining <= 0:
                return self._current_open_view_deadline(username) == (attr_name, due_at)
            if self._stop_event.wait(min(remaining, 0.25)):
                return False
        return False

    def _wait_until_global_deadline_due(self, due_at: str) -> bool:
        due_dt = parse_datetime(due_at)
        if due_dt is None:
            return False
        refresh_deadline = due_dt + timedelta(milliseconds=75)
        while not self._stop_event.is_set():
            if self._open_view_username is not None or self._pending_secure_refresh is not None:
                return False
            remaining = (refresh_deadline - utc_now()).total_seconds()
            if remaining <= 0:
                return True
            if self._stop_event.wait(min(remaining, 0.25)):
                return False
        return False

    def _clear_terminal_view(self) -> None:
        with self._output_lock:
            print("\033[3J\033[2J\033[H", end="", flush=True)

    def _prompt_refresh_value(self, prompt: str, *, secret: bool) -> str | None:
        while True:
            value = getpass.getpass(prompt) if secret else input(prompt)
            normalized = value.strip()
            if normalized.lower() in {"cancel", "<cancel>"}:
                return None
            if normalized:
                return value
            print("[Secure Refresh] Input required. Type <cancel> to exit the shell.")

    def _prompt_refresh_confirmation(self, prompt: str) -> bool:
        response = input(prompt).strip().lower()
        return response not in {"cancel", "<cancel>"}

    @staticmethod
    def _is_session_expired_error(value: Exception | str) -> bool:
        if isinstance(value, APIError):
            return value.status_code == 401 and "session is invalid or expired" in value.detail.lower()
        message = str(value).strip().lower()
        return any(
            token in message
            for token in (
                "http 401: session is invalid or expired",
                "session is invalid or expired",
                "invalid or expired session",
                "session expired",
                "4401",
            )
        )

    def _request_session_expired_logout(self) -> None:
        if self._pending_session_logout is not None:
            return
        self._pending_session_logout = SessionExpiredLogoutRequest(
            message="HTTP 401: Session is invalid or expired.",
            reason="The current session expired while the shell was active.",
        )
        self._open_view_sensitive_expiry_at = None
        self._open_view_retention_cutoff_at = None
        self._session_logout_wake_requested = False
        if not self._command_active:
            self._session_logout_wake_requested = self._wake_prompt_for_secure_refresh()

    def _wait_for_any_key_acknowledgement(self, prompt: str) -> None:
        print(prompt, end="", flush=True)
        self._discard_pending_terminal_input()
        try:
            import msvcrt  # type: ignore

            msvcrt.getwch()
            print()
            return
        except Exception:
            pass
        try:
            fileno = sys.stdin.fileno()
        except Exception:
            fileno = None
        if fileno is not None:
            try:
                if os.isatty(fileno):
                    import termios
                    import tty

                    original = termios.tcgetattr(fileno)
                    try:
                        tty.setraw(fileno)
                        os.read(fileno, 1)
                    finally:
                        termios.tcsetattr(fileno, termios.TCSADRAIN, original)
                    print()
                    return
            except Exception:
                pass
        input()

    def _request_secure_refresh(self, *, reason: str) -> None:
        username = self._open_view_username
        if not username or self._pending_secure_refresh is not None:
            return
        self._pending_secure_refresh = SecureRefreshRequest(
            username=username,
            limit=self._open_view_limit,
            before_local_id=self._open_view_before,
            full_history=self._open_view_full_history,
            reason=reason,
        )
        self._open_view_sensitive_expiry_at = None
        self._open_view_retention_cutoff_at = None
        self._secure_refresh_wake_requested = False
        self._session_logout_wake_requested = False
        if not self._command_active:
            self._secure_refresh_wake_requested = self._wake_prompt_for_secure_refresh()

    def _request_secure_refresh_for_expiry(self) -> None:
        self._request_secure_refresh(reason="A disappearing message expired after being viewed.")

    def _request_secure_refresh_for_retention(self) -> None:
        self._request_secure_refresh(reason="The one-day history retention window advanced while this conversation was open.")

    def _build_runtime_for_refresh(self, profile_name: str, base_dir: str | None, previous_runtime: ClientRuntime) -> ClientRuntime:
        return ClientRuntime(
            profile_name=profile_name,
            base_dir=base_dir,
            transport=getattr(previous_runtime, "transport", None),
            verify_override=getattr(previous_runtime, "verify_override", None),
        )

    def _restore_runtime_after_secure_refresh(
        self,
        *,
        profile_name: str,
        base_dir: str | None,
        username: str,
        previous_runtime: ClientRuntime,
    ) -> ClientRuntime | None:
        while True:
            device_passphrase = self._prompt_refresh_value(
                "Device vault passphrase (<cancel> to exit): ",
                secret=True,
            )
            if device_passphrase is None:
                return None
            runtime = self._build_runtime_for_refresh(profile_name, base_dir, previous_runtime)
            try:
                runtime.unlock(device_passphrase)
            except Exception as exc:
                runtime.close()
                print(f"[Secure Refresh] {self._format_command_error(exc)}")
                continue
            try:
                runtime.me()
                return runtime
            except APIError as exc:
                if exc.status_code != 401:
                    runtime.close()
                    print(f"[Secure Refresh] {self._format_command_error(exc)}")
                    if not self._prompt_refresh_confirmation(
                        "Press Enter to retry the secure refresh, or type <cancel> to exit: "
                    ):
                        return None
                    continue
                print("[Secure Refresh] The saved session expired. Account password and OTP are required.")
            except Exception as exc:
                runtime.close()
                print(f"[Secure Refresh] {self._format_command_error(exc)}")
                if not self._prompt_refresh_confirmation(
                    "Press Enter to retry the secure refresh, or type <cancel> to exit: "
                ):
                    return None
                continue

            while True:
                password = self._prompt_refresh_value("Account password (<cancel> to exit): ", secret=True)
                if password is None:
                    runtime.close()
                    return None
                otp_code = self._prompt_refresh_value("OTP code (<cancel> to exit): ", secret=False)
                if otp_code is None:
                    runtime.close()
                    return None
                try:
                    runtime.login(username, password, otp_code, device_passphrase)
                    return runtime
                except APIError as exc:
                    if exc.status_code == 401:
                        print("[Secure Refresh] Invalid username, password, or OTP code.")
                    elif exc.status_code == 429:
                        print(f"[Secure Refresh] HTTP 429: {exc.detail}")
                    else:
                        print(f"[Secure Refresh] {self._format_command_error(exc)}")
                except Exception as exc:
                    print(f"[Secure Refresh] {self._format_command_error(exc)}")

    def _handle_pending_session_logout(self) -> bool:
        request = self._pending_session_logout
        if request is None:
            return True
        self._pending_session_logout = None
        self._session_logout_wake_requested = False

        self._stop_listener()
        self._discard_pending_terminal_input()
        try:
            self.runtime.force_local_logout()
        except Exception:
            pass
        self._clear_open_view()
        self._clear_terminal_view()
        print(f"[Session Expired] {request.message}")
        print("[Session Expired] You have been logged out.")
        print("[Session Expired] Press any key to return to the normal command-line interface.")
        self._wait_for_any_key_acknowledgement("")
        return False

    def _handle_pending_secure_refresh(self) -> bool:
        request = self._pending_secure_refresh
        if request is None:
            return True
        self._pending_secure_refresh = None
        self._secure_refresh_wake_requested = False

        current_runtime = self.runtime
        if not hasattr(current_runtime, "paths"):
            self._clear_terminal_view()
            print("[Secure Refresh] A disappearing message expired after being viewed.")
            print("[Secure Refresh] This shell cannot rebuild the session context safely. Exiting.")
            self._stop_listener()
            return False

        profile_name = current_runtime.paths.profile_dir.name
        base_dir = str(current_runtime.paths.profile_dir.parent)
        try:
            username = current_runtime.username()
        except Exception:
            username = profile_name

        self._stop_listener()
        self._discard_pending_terminal_input()
        try:
            current_runtime.close()
        except Exception:
            pass

        self._clear_terminal_view()
        print(f"[Secure Refresh] {request.reason}")
        print("[Secure Refresh] The shell is refreshing to reduce terminal visibility of earlier plaintext.")
        print("[Secure Refresh] Terminal scrollback clearing is best-effort and depends on your terminal emulator.")
        print("[Secure Refresh] Type <cancel> at any prompt to exit the shell.")

        refreshed_runtime = self._restore_runtime_after_secure_refresh(
            profile_name=profile_name,
            base_dir=base_dir,
            username=username,
            previous_runtime=current_runtime,
        )
        if refreshed_runtime is None:
            self.runtime = current_runtime
            print("[Secure Refresh] Secure refresh canceled. Exiting shell.")
            return False

        self.runtime = refreshed_runtime
        self._suppress_next_connected_notice = True
        try:
            self.runtime.purge_local_history()
        except Exception:
            pass
        self._clear_terminal_view()
        print(f"[Secure Refresh] Session restored for {username}. Reopened conversation with {request.username}.")
        try:
            rows, next_before = self._load_history_for_open(
                request.username,
                limit=request.limit,
                before_local_id=request.before_local_id,
                mark_read=True,
                full_history=request.full_history,
            )
            self._open_view_username = request.username.lower()
            self._open_view_limit = request.limit
            self._open_view_before = request.before_local_id
            self._open_view_full_history = request.full_history
            self._render_history_view(request.username, rows, next_before)
        except Exception as exc:
            self._clear_open_view()
            print(
                f"[Secure Refresh] Session restored, but reopening {request.username} failed: {self._format_command_error(exc)}"
            )
        self._start_background_threads()
        return True

    def _render_history_view(
        self,
        username: str,
        rows: list[dict[str, Any]],
        next_before: int | None,
        *,
        clear_screen: bool = False,
        reason: str | None = None,
    ) -> None:
        with self._output_lock:
            if clear_screen:
                print("\033[3J\033[2J\033[H", end="", flush=True)
            self._print_section(f"Conversation with {username}")
            print(history_retention_notice(display_tz=CLI_DISPLAY_TIMEZONE))
            if (
                not self._open_view_full_history
                and self._open_view_before is None
                and self._open_view_limit == DEFAULT_RECENT_HISTORY_LIMIT
            ):
                print(recent_history_limit_notice(DEFAULT_RECENT_HISTORY_LIMIT))
            print()
            if reason:
                print(f"[{reason}]")
            if not rows:
                print("No local messages yet.")
            for row in rows:
                print(f"{row['local_id']:>4}. {history_header(row, username, display_tz=CLI_DISPLAY_TIMEZONE)}")
                body = message_body_for_display(row)
                if body:
                    for line in str(body).splitlines() or [""]:
                        print(f"      {line}")
                print()
            if next_before is not None:
                print(f"Use open {username} [limit] [before_local_id] to see more history.\nor\nUse open {username} full to load the complete local history.")
            self._open_view_render_signature = self._history_view_signature(username, rows, next_before)
            self._update_open_view_sensitive_expiry(rows)
            self._update_open_view_retention_cutoff(rows)

    def _expiry_loop(self) -> None:
        while not self._stop_event.is_set():
            username = self._open_view_username
            due_candidates: list[tuple[str, str, str]] = []
            if username and self._open_view_sensitive_expiry_at:
                due_candidates.append(("_open_view_sensitive_expiry_at", self._open_view_sensitive_expiry_at, "expiry"))
            if username and self._open_view_retention_cutoff_at:
                due_candidates.append(("_open_view_retention_cutoff_at", self._open_view_retention_cutoff_at, "retention"))
            if due_candidates:
                attr_name, due_at, reason = min(
                    due_candidates,
                    key=lambda item: parse_datetime(item[1]) or utc_now(),
                )
                if not self._wait_until_open_view_deadline_due(username, attr_name, due_at):
                    continue
                try:
                    if reason == "expiry":
                        self._request_secure_refresh_for_expiry()
                    else:
                        self._request_secure_refresh_for_retention()
                except Exception:
                    self._stop_event.wait(0.25)
                continue

            try:
                quiet_cleanup_at = self.runtime.next_retention_cutoff_at()
            except Exception:
                quiet_cleanup_at = None
            if quiet_cleanup_at and self._wait_until_global_deadline_due(quiet_cleanup_at):
                try:
                    self.runtime.purge_local_history()
                except Exception:
                    self._stop_event.wait(0.25)
                continue

            self._stop_event.wait(0.25)

    @staticmethod
    def _print_section(title: str) -> None:
        print(title)
        print("-" * len(title))

    def do_sync(self, arg: str) -> None:
        self._require_no_arguments(arg, usage="sync")
        results = self.runtime.sync_queue()
        if not results:
            print("No queued messages to process.")
            return
        self._print_section("Sync results")
        for item in results:
            self._print_processed(item)

    def do_contacts(self, arg: str) -> None:
        self._require_no_arguments(arg, usage="contacts")
        contacts = self.runtime.list_contacts()["contacts"]
        if not contacts:
            print("You do not have any contacts yet.")
            return
        self._print_section("Contacts")
        for index, contact in enumerate(contacts):
            if index:
                print()
            for line in format_contact_lines(contact, display_tz=CLI_DISPLAY_TIMEZONE):
                print(line)

    def do_requests(self, arg: str) -> None:
        self._require_no_arguments(arg, usage="requests")
        response = self.runtime.list_requests()
        self._print_section("Incoming requests")
        incoming = response.get("incoming", [])
        if not incoming:
            print("No incoming requests.")
        else:
            for row in incoming:
                for line in format_request_lines(row, outgoing=False, display_tz=CLI_DISPLAY_TIMEZONE):
                    print(line)
        print()
        self._print_section("Outgoing requests")
        outgoing = response.get("outgoing", [])
        if not outgoing:
            print("No outgoing requests.")
        else:
            for row in outgoing:
                for line in format_request_lines(row, outgoing=True, display_tz=CLI_DISPLAY_TIMEZONE):
                    print(line)

    def do_add(self, arg: str) -> None:
        username, note = self._parse_username_and_optional_text(arg, usage="add <username> [note]")
        result = self.runtime.send_friend_request(username, note)
        print(f"Friend request sent to {result['receiver_username']}. Request #{result['request_id']}.")

    def do_accept(self, arg: str) -> None:
        request_id = self._parse_positive_int_argument(arg, usage="accept <request_id>")
        self.runtime.accept_request(request_id)
        print(f"Accepted request #{request_id}.")

    def do_decline(self, arg: str) -> None:
        request_id = self._parse_positive_int_argument(arg, usage="decline <request_id>")
        self.runtime.decline_request(request_id)
        print(f"Declined request #{request_id}.")

    def do_cancel(self, arg: str) -> None:
        request_id = self._parse_positive_int_argument(arg, usage="cancel <request_id>")
        self.runtime.cancel_request(request_id)
        print(f"Cancelled request #{request_id}.")

    def do_block(self, arg: str) -> None:
        username = self._parse_single_token_argument(arg, usage="block <username>")
        print(self.runtime.block_user(username)["message"])

    def do_unblock(self, arg: str) -> None:
        username = self._parse_single_token_argument(arg, usage="unblock <username>")
        print(self.runtime.unblock_user(username)["message"])

    def do_remove(self, arg: str) -> None:
        username = self._parse_single_token_argument(arg, usage="remove <username>")
        normalized = username.lower()
        print(self.runtime.remove_friend(normalized)["message"])
        if self._open_view_username == normalized:
            self._clear_open_view()

    def do_send(self, arg: str) -> None:
        username, message_text = self._parse_send_arguments(arg, usage="send <username> <message text>")
        result = self.runtime.send_text(username, message_text)
        print(send_result_text(result, username, display_tz=CLI_DISPLAY_TIMEZONE))

    def do_sendttl(self, arg: str) -> None:
        username, ttl_seconds, message_text = self._parse_sendttl_arguments(arg)
        result = self.runtime.send_text(username, message_text, ttl_seconds=ttl_seconds)
        print(send_result_text(result, username, ttl_seconds=ttl_seconds, display_tz=CLI_DISPLAY_TIMEZONE))

    def do_conversations(self, arg: str) -> None:
        self._require_no_arguments(arg, usage="conversations")
        try:
            self.runtime.list_contacts()
        except Exception:
            pass
        rows = self.runtime.conversation_list()
        if not rows:
            print("No conversations yet.")
            return
        self._print_section("Conversations")
        for row in rows:
            contact, unread, last_activity = conversation_row_display(row, display_tz=CLI_DISPLAY_TIMEZONE)
            print(f"• {contact} — {last_activity} — {unread}")

    def do_open(self, arg: str) -> None:
        username, limit, before, full_history = self._parse_open_arguments(arg)
        rows, next_before = self._load_history_for_open(
            username,
            limit=limit,
            before_local_id=before,
            mark_read=True,
            full_history=full_history,
        )
        self._open_view_username = username.lower()
        self._open_view_limit = limit
        self._open_view_before = before
        self._open_view_full_history = full_history
        self._render_history_view(username, rows, next_before)

    def do_fingerprint(self, arg: str) -> None:
        username = self._parse_single_token_argument(arg, usage="fingerprint <username>")
        info = self.runtime.fingerprint_info(username)
        self._print_section(f"Safety number for {info.username}")
        for line in fingerprint_summary_lines(asdict(info)):
            print(line)

    def do_verify_contact(self, arg: str) -> None:
        username = self._parse_single_token_argument(arg, usage="verify_contact <username>")
        info = self.runtime.verify_contact(username)
        print(f"Verified {info.username}'s current identity.")
        print(f"Safety number: {info.display}")

    def do_rotate(self, arg: str) -> None:
        self._require_no_arguments(arg, usage="rotate")
        print(self.runtime.rotate_keys()["message"])

    def do_events(self, arg: str) -> None:
        self._require_no_arguments(arg, usage="events")
        events = self.runtime.unresolved_security_events()
        if not events:
            print("No unresolved security events.")
            return
        self._print_section("Security events")
        for row in events:
            created, contact, event_type, detail = event_row_display(row, display_tz=CLI_DISPLAY_TIMEZONE)
            print(f"• {created} — {contact or 'Unknown contact'} — {event_type}")
            print(f"  {detail}")

    def do_logout(self, arg: str) -> bool:
        self._require_no_arguments(arg, usage="logout")
        print(self.runtime.logout()["message"])
        self._stop_listener()
        return True

    def do_exit(self, arg: str) -> bool:
        self._require_no_arguments(arg, usage="exit")
        self._stop_listener()
        return True

    def do_quit(self, arg: str) -> bool:
        self._require_no_arguments(arg, usage="quit")
        self._stop_listener()
        return True

    def do_EOF(self, arg: str) -> bool:
        self._require_no_arguments(arg, usage="EOF")
        print("")
        self._stop_listener()
        return True

    def emptyline(self) -> bool:
        return False

    def default(self, line: str) -> None:
        print(f"Unknown command: {line}")

    def _format_command_error(self, exc: Exception) -> str:
        if isinstance(exc, APIError):
            return f"HTTP {exc.status_code}: {exc.detail}"
        if isinstance(exc, InvalidTag):
            return "Incorrect device passphrase or unreadable encrypted local vault data."
        if isinstance(exc, ValueError):
            return str(exc) or "Invalid command arguments."
        return str(exc) or exc.__class__.__name__

    def _print_command_error(self, line: str, message: str) -> None:
        command_name, _, _ = self.parseline(line)
        label = command_name or "command"
        print(f"Error [{label}]: {message}")

    def _stop_listener(self) -> None:
        self._stop_event.set()
        if self._listener_thread is not None and self._listener_thread.is_alive():
            self._listener_thread.join(timeout=2)
        if self._expiry_thread is not None and self._expiry_thread.is_alive():
            self._expiry_thread.join(timeout=2)
        self._listener_thread = None
        self._expiry_thread = None

    def _listener_loop(self) -> None:
        try:
            token = self.runtime.session_token()
        except Exception:
            print("No active session token found. Log in first, then open the shell.")
            return
        uri = f"{self.runtime.websocket_url()}?token={quote(token)}"
        ssl_context = self.runtime.websocket_ssl_context()
        while not self._stop_event.is_set():
            try:
                with ws_connect(uri, ssl=ssl_context, ping_interval=20, ping_timeout=20, max_size=2**20) as websocket:
                    while not self._stop_event.is_set():
                        try:
                            raw = websocket.recv(timeout=1)
                        except TimeoutError:
                            continue
                        event = json.loads(raw)
                        self._handle_ws_event(event)
            except Exception as exc:
                if not self._stop_event.is_set():
                    if self._is_session_expired_error(exc):
                        self._request_session_expired_logout()
                        return
                    with self._output_lock:
                        print()
                        print(f"[Live updates] Connection lost. Reconnecting in 2 seconds: {exc}")
                    time.sleep(2)

    def _handle_ws_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("type")
        payload = event.get("payload", {})
        if event_type == "message":
            try:
                result = self.runtime.process_envelope(payload["envelope"])
                self._print_processed(result)
            except Exception as exc:
                if self._is_session_expired_error(exc):
                    self._request_session_expired_logout()
                    return
                with self._output_lock:
                    print()
                    print(f"[Live updates] Could not process an incoming item: {exc}")
        elif event_type == "friend_request_received":
            sender = payload.get("sender_username") or "Unknown user"
            request_id = payload.get("request_id")
            note = str(payload.get("note") or "").strip()
            with self._output_lock:
                print()
                print(f"[Live updates] New friend request from {sender}. Request #{request_id}.")
                if note:
                    print(f"[Live updates] Note: {note_label(note)}")
        elif event_type == "friend_request_updated":
            request_id = payload.get("request_id")
            status = payload.get("status") or "updated"
            actor = payload.get("by") or "someone"
            if str(status).strip().lower() == "accepted":
                try:
                    self.runtime.list_contacts()
                except Exception:
                    pass
            with self._output_lock:
                print()
                print(f"[Live updates] Friend request #{request_id} is now {status}. Updated by {actor}.")
        elif event_type == "connected":
            username = payload.get("username") or "?"
            pending = payload.get("pending_messages") or 0
            if self._suppress_next_connected_notice:
                self._suppress_next_connected_notice = False
                return
            with self._output_lock:
                print()
                print(f"[Live updates] Connected as {username}. Pending queued messages: {pending}.")
        elif event_type == "pong":
            return
        else:
            with self._output_lock:
                print()
                print(f"[Live updates] Server event {event_type}: {payload}")

    def _print_processed(self, item: dict[str, Any]) -> None:
        item_type = item.get("type")
        with self._output_lock:
            if item_type == "duplicate":
                return
            if item_type == "chat":
                print()
                print(f"[New Message] {incoming_message_notice_text(item, display_tz=CLI_DISPLAY_TIMEZONE)}")
                print(f"[Hint] {incoming_message_hint_text(item)}")
            elif item_type == "discarded":
                return
            elif item_type == "delivery_ack":
                print()
                print(f"[Read] {delivery_ack_text(item, display_tz=CLI_DISPLAY_TIMEZONE)}")
            elif item_type == "error":
                print()
                print(f"[Sync error] {item['detail']}")
            else:
                print(item)


_attach_command_help()