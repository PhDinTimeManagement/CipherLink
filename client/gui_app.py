from __future__ import annotations

import argparse
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import Any, Callable

from client.gui_controller import CipherLinkGUIController
from client.presentation import (
    GUI_DISPLAY_TIMEZONE,
    activity_entry,
    chat_header,
    chat_secondary_header,
    contact_messaging_label,
    conversation_row_display,
    delivery_ack_text,
    event_type_label,
    event_row_display,
    fingerprint_summary_lines,
    format_timestamp,
    history_retention_notice,
    incoming_chat_text,
    incoming_message_notice_text,
    message_body_for_display,
    message_is_unavailable,
    note_label,
    recent_history_limit_label,
    send_result_text,
    short_id,
    sync_item_text,
    trust_state_label,
    identity_summary_text,
)
from shared.utils import parse_datetime, utc_now
from shared.utils import within_history_retention


DISAPPEARING_MESSAGE_CHECKBOX_LABEL = "Disappearing message"
DISAPPEARING_MESSAGE_AFTER_LABEL = "Disappears after"
DISAPPEARING_MESSAGE_UNIT_LABEL = "second(s)"
RECENT_CONVERSATION_CHAT_LIMIT = 20
APP_BRAND_NAME = "CipherLink"
GUI_WINDOW_TITLE = f"{APP_BRAND_NAME} Desktop Client"
GUI_PARSER_DESCRIPTION = f"{APP_BRAND_NAME} Desktop GUI client"
BASE_DIRECTORY_HINT_TEXT = "Hint: path/to/client_profiles"
AUTH_TAB_REGISTER = "Register"
AUTH_TAB_CONFIRM_OTP = "Confirm OTP"
AUTH_TAB_LOGIN = "Login"
AUTH_TAB_REOPEN_SESSION = "Reopen Session"

AUTH_FIELD_LABELS = {
    "profile_name": "Profile Name",
    "base_dir": "Base Directory",
    "username": "Username",
    "password": "Account Password",
    "device_passphrase": "Device Vault Passphrase",
    "otp": "OTP Code",
    "bootstrap": "Bootstrap JSON",
    "server_url": "Server URL",
    "ca_cert": "CA Certificate",
}

AUTH_TAB_REQUIRED_FIELDS = {
    AUTH_TAB_REGISTER: {"profile_name", "base_dir", "username", "password", "device_passphrase"},
    AUTH_TAB_CONFIRM_OTP: {"profile_name", "base_dir", "username", "password", "device_passphrase", "otp"},
    AUTH_TAB_LOGIN: {"profile_name", "base_dir", "username", "password", "device_passphrase", "otp"},
    AUTH_TAB_REOPEN_SESSION: {"profile_name", "base_dir", "device_passphrase"},
}


def required_label_text(label: str, *, required: bool) -> str:
    return f"{label} *" if required else label


def required_auth_fields(tab_name: str, *, server_mode: str = "bootstrap") -> set[str]:
    normalized_tab = str(tab_name or "").strip() or AUTH_TAB_REGISTER
    fields = set(AUTH_TAB_REQUIRED_FIELDS.get(normalized_tab, set()))
    if normalized_tab == AUTH_TAB_REGISTER:
        if str(server_mode or "").strip().lower() == "direct":
            fields.update({"server_url", "ca_cert"})
        else:
            fields.add("bootstrap")
    return fields


class AuthFrame(ttk.Frame):
    def __init__(self, master: tk.Misc, app: "CipherLinkDesktopApp") -> None:
        super().__init__(master, padding=16)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(4, weight=1)

        self.profile_name_var = tk.StringVar(value=app.initial_profile or "")
        self.base_dir_var = tk.StringVar(value=app.initial_base_dir or "")
        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.device_passphrase_var = tk.StringVar()
        self.otp_var = tk.StringVar()

        self.server_mode_var = tk.StringVar(value="bootstrap")
        self.bootstrap_path_var = tk.StringVar()
        self.server_url_var = tk.StringVar(value="https://127.0.0.1:8443")
        self.ca_cert_path_var = tk.StringVar()

        title = ttk.Label(
            self,
            text=APP_BRAND_NAME,
            font=("TkDefaultFont", 18, "bold"),
            anchor="center",
            justify="center",
        )
        title.grid(row=0, column=0, sticky="ew")

        profile_box = ttk.LabelFrame(self, text="Profile and Encrypted Local Storage", padding=12)
        profile_box.grid(row=2, column=0, sticky="ew")
        profile_box.columnconfigure(1, weight=1)
        self.profile_name_label = ttk.Label(profile_box, text=AUTH_FIELD_LABELS["profile_name"])
        self.profile_name_label.grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(profile_box, textvariable=self.profile_name_var).grid(row=0, column=1, sticky="ew", pady=4)
        self.base_dir_label = ttk.Label(profile_box, text=AUTH_FIELD_LABELS["base_dir"])
        self.base_dir_label.grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(profile_box, textvariable=self.base_dir_var).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(profile_box, text="Browse…", command=self._browse_base_dir).grid(row=1, column=2, padx=(8, 0), pady=4)
        self.base_dir_hint_label = ttk.Label(profile_box, text=BASE_DIRECTORY_HINT_TEXT)
        self.base_dir_hint_label.grid(row=2, column=1, columnspan=2, sticky="w", pady=(0, 4))

        creds_box = ttk.LabelFrame(self, text="Sign-in Details", padding=12)
        creds_box.grid(row=3, column=0, sticky="ew", pady=(12, 0))
        creds_box.columnconfigure(1, weight=1)
        self.username_label = ttk.Label(creds_box, text=AUTH_FIELD_LABELS["username"])
        self.username_label.grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(creds_box, textvariable=self.username_var).grid(row=0, column=1, sticky="ew", pady=4)
        self.password_label = ttk.Label(creds_box, text=AUTH_FIELD_LABELS["password"])
        self.password_label.grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(creds_box, textvariable=self.password_var, show="•").grid(row=1, column=1, sticky="ew", pady=4)
        self.device_passphrase_label = ttk.Label(creds_box, text=AUTH_FIELD_LABELS["device_passphrase"])
        self.device_passphrase_label.grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(creds_box, textvariable=self.device_passphrase_var, show="•").grid(row=2, column=1, sticky="ew", pady=4)
        self.otp_label = ttk.Label(creds_box, text=AUTH_FIELD_LABELS["otp"])
        self.otp_label.grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(creds_box, textvariable=self.otp_var).grid(row=3, column=1, sticky="ew", pady=4)

        self.notebook = ttk.Notebook(self)
        self.notebook.grid(row=4, column=0, sticky="nsew", pady=(12, 0))
        self.notebook.bind("<<NotebookTabChanged>>", lambda _event: self._update_required_field_labels())

        self.register_tab = ttk.Frame(self.notebook, padding=12)
        self.register_tab.columnconfigure(1, weight=1)
        self.notebook.add(self.register_tab, text=AUTH_TAB_REGISTER)

        ttk.Label(
            self.register_tab,
            text="Choose either a bootstrap bundle or a direct HTTPS server URL + trusted CA certificate.",
            wraplength=700,
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 12))
        ttk.Radiobutton(self.register_tab, text="Bootstrap File", variable=self.server_mode_var, value="bootstrap", command=self._update_server_mode).grid(row=1, column=0, columnspan=3, sticky="w")
        self.bootstrap_label = ttk.Label(self.register_tab, text=AUTH_FIELD_LABELS["bootstrap"])
        self.bootstrap_label.grid(row=2, column=0, sticky="w", padx=(0, 8), pady=4)
        self.bootstrap_entry = ttk.Entry(self.register_tab, textvariable=self.bootstrap_path_var)
        self.bootstrap_entry.grid(row=2, column=1, sticky="ew", pady=4)
        self.bootstrap_button = ttk.Button(self.register_tab, text="Browse…", command=self._browse_bootstrap)
        self.bootstrap_button.grid(row=2, column=2, padx=(8, 0), pady=4)

        ttk.Radiobutton(self.register_tab, text="Direct Server URL + CA Certificate", variable=self.server_mode_var, value="direct", command=self._update_server_mode).grid(row=3, column=0, columnspan=3, sticky="w", pady=(10, 0))
        self.server_url_label = ttk.Label(self.register_tab, text=AUTH_FIELD_LABELS["server_url"])
        self.server_url_label.grid(row=4, column=0, sticky="w", padx=(0, 8), pady=4)
        self.server_url_entry = ttk.Entry(self.register_tab, textvariable=self.server_url_var)
        self.server_url_entry.grid(row=4, column=1, sticky="ew", pady=4)
        self.ca_cert_label = ttk.Label(self.register_tab, text=AUTH_FIELD_LABELS["ca_cert"])
        self.ca_cert_label.grid(row=5, column=0, sticky="w", padx=(0, 8), pady=4)
        self.ca_cert_entry = ttk.Entry(self.register_tab, textvariable=self.ca_cert_path_var)
        self.ca_cert_entry.grid(row=5, column=1, sticky="ew", pady=4)
        self.ca_cert_button = ttk.Button(self.register_tab, text="Browse…", command=self._browse_ca_cert)
        self.ca_cert_button.grid(row=5, column=2, padx=(8, 0), pady=4)

        ttk.Button(self.register_tab, text="Register Account", command=self.app.handle_register).grid(row=6, column=0, columnspan=3, sticky="ew", pady=(12, 0))

        self.confirm_tab = ttk.Frame(self.notebook, padding=12)
        self.confirm_tab.columnconfigure(0, weight=1)
        self.notebook.add(self.confirm_tab, text=AUTH_TAB_CONFIRM_OTP)
        ttk.Label(
            self.confirm_tab,
            text=(
                "After scanning the provisioning URI or entering the secret into an authenticator app,\n"
                "enter the current OTP code above and confirm the registration."
            ),
            wraplength=700,
            justify="left",
        ).grid(row=0, column=0, sticky="w", pady=(0, 12))
        ttk.Button(self.confirm_tab, text="Confirm OTP", command=self.app.handle_confirm_otp).grid(row=1, column=0, sticky="ew")

        self.login_tab = ttk.Frame(self.notebook, padding=12)
        self.login_tab.columnconfigure(0, weight=1)
        self.notebook.add(self.login_tab, text=AUTH_TAB_LOGIN)
        ttk.Label(
            self.login_tab,
            text="Use password + OTP to authenticate an existing account.",
            wraplength=700,
            justify="left",
        ).grid(row=0, column=0, sticky="w", pady=(0, 12))
        ttk.Button(self.login_tab, text="Login", command=self.app.handle_login).grid(row=1, column=0, sticky="ew")

        self.reopen_tab = ttk.Frame(self.notebook, padding=12)
        self.reopen_tab.columnconfigure(0, weight=1)
        self.notebook.add(self.reopen_tab, text=AUTH_TAB_REOPEN_SESSION)
        ttk.Label(
            self.reopen_tab,
            text="Reopen an existing saved session using only the device vault passphrase.",
            wraplength=700,
            justify="left",
        ).grid(row=0, column=0, sticky="w", pady=(0, 12))
        ttk.Button(self.reopen_tab, text=AUTH_TAB_REOPEN_SESSION, command=self.app.handle_open_saved_session).grid(row=1, column=0, sticky="ew")

        self._update_server_mode()
        self._update_required_field_labels()

    def _browse_base_dir(self) -> None:
        selected = filedialog.askdirectory(title="Choose client profile base directory")
        if selected:
            self.base_dir_var.set(selected)

    def _browse_bootstrap(self) -> None:
        selected = filedialog.askopenfilename(
            title="Choose bootstrap JSON file",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if selected:
            self.bootstrap_path_var.set(selected)

    def _browse_ca_cert(self) -> None:
        selected = filedialog.askopenfilename(
            title="Choose trusted CA certificate",
            filetypes=[("Certificate files", "*.crt *.pem"), ("All files", "*.*")],
        )
        if selected:
            self.ca_cert_path_var.set(selected)

    def _update_server_mode(self) -> None:
        use_bootstrap = self.server_mode_var.get() == "bootstrap"
        state_bootstrap = "normal" if use_bootstrap else "disabled"
        state_direct = "disabled" if use_bootstrap else "normal"
        self.bootstrap_entry.configure(state=state_bootstrap)
        self.bootstrap_button.configure(state=state_bootstrap)
        self.server_url_entry.configure(state=state_direct)
        self.ca_cert_entry.configure(state=state_direct)
        self.ca_cert_button.configure(state=state_direct)
        self._update_required_field_labels()

    def _current_auth_tab(self) -> str:
        try:
            tab_id = self.notebook.select()
            return str(self.notebook.tab(tab_id, "text") or AUTH_TAB_REGISTER)
        except Exception:
            return AUTH_TAB_REGISTER

    def _set_label_required_state(self, label_widget: ttk.Label, field_name: str, required_fields: set[str]) -> None:
        label_widget.configure(
            text=required_label_text(
                AUTH_FIELD_LABELS[field_name],
                required=field_name in required_fields,
            )
        )

    def _update_required_field_labels(self) -> None:
        required_fields = required_auth_fields(self._current_auth_tab(), server_mode=self.server_mode_var.get())
        self._set_label_required_state(self.profile_name_label, "profile_name", required_fields)
        self._set_label_required_state(self.base_dir_label, "base_dir", required_fields)
        self._set_label_required_state(self.username_label, "username", required_fields)
        self._set_label_required_state(self.password_label, "password", required_fields)
        self._set_label_required_state(self.device_passphrase_label, "device_passphrase", required_fields)
        self._set_label_required_state(self.otp_label, "otp", required_fields)
        self._set_label_required_state(self.bootstrap_label, "bootstrap", required_fields)
        self._set_label_required_state(self.server_url_label, "server_url", required_fields)
        self._set_label_required_state(self.ca_cert_label, "ca_cert", required_fields)

    def switch_to_confirm_tab(self) -> None:
        self.notebook.select(self.confirm_tab)

    def switch_to_login_tab(self) -> None:
        self.notebook.select(self.login_tab)

    def switch_to_reopen_tab(self) -> None:
        self.notebook.select(self.reopen_tab)

    def profile_settings(self) -> tuple[str, str | None]:
        return self.profile_name_var.get().strip(), self.base_dir_var.get().strip() or None

    def credentials(self) -> dict[str, str]:
        return {
            "username": self.username_var.get().strip(),
            "password": self.password_var.get(),
            "device_passphrase": self.device_passphrase_var.get(),
            "otp_code": self.otp_var.get().strip(),
        }

    def registration_connection_settings(self) -> dict[str, str | None]:
        if self.server_mode_var.get() == "bootstrap":
            return {
                "bootstrap_path": self.bootstrap_path_var.get().strip() or None,
                "server_url": None,
                "ca_cert_path": None,
            }
        return {
            "bootstrap_path": None,
            "server_url": self.server_url_var.get().strip() or None,
            "ca_cert_path": self.ca_cert_path_var.get().strip() or None,
        }


class MainFrame(ttk.Frame):
    def __init__(self, master: tk.Misc, app: "CipherLinkDesktopApp") -> None:
        super().__init__(master, padding=10)
        self.app = app
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        toolbar = ttk.Frame(self)
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        toolbar.columnconfigure(0, weight=1)

        self.identity_var = tk.StringVar(value="Not connected")
        self.identity_label = ttk.Label(
            toolbar,
            textvariable=self.identity_var,
            font=("TkDefaultFont", 11, "bold"),
            justify="left",
        )
        self.identity_label.grid(row=0, column=0, sticky="w")

        button_box = ttk.Frame(toolbar)
        button_box.grid(row=0, column=1, sticky="e")
        ttk.Button(button_box, text="Sync", command=app.handle_sync).pack(side="left", padx=(0, 6))
        ttk.Button(button_box, text="Rotate keys", command=app.handle_rotate_keys).pack(side="left", padx=(0, 6))
        ttk.Button(button_box, text="Exit", command=app.handle_exit).pack(side="left")

        main_pane = ttk.PanedWindow(self, orient="horizontal")
        main_pane.grid(row=1, column=0, sticky="nsew")

        left = ttk.Frame(main_pane, padding=(0, 0, 8, 0))
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)
        main_pane.add(left, weight=1)

        self.sidebar_notebook = ttk.Notebook(left)
        self.sidebar_notebook.grid(row=0, column=0, sticky="nsew")
        self.sidebar_notebook.bind("<<NotebookTabChanged>>", app.handle_sidebar_tab_changed)

        self._build_conversations_tab()
        self._build_requests_tab()
        self._build_contacts_tab()
        self._build_events_tab()
        self._build_activity_panel(left, row=1, column=0, pady=(8, 0))

        right = ttk.Frame(main_pane)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        main_pane.add(right, weight=3)

        self.friend_section = ttk.LabelFrame(right, text="Friend", padding=12)
        self.friend_section.grid(row=0, column=0, sticky="ew")
        self.friend_section.columnconfigure(0, weight=1)
        self.chat_contact_var = tk.StringVar(value="")
        self.friend_name_label = ttk.Label(
            self.friend_section,
            textvariable=self.chat_contact_var,
            font=("TkDefaultFont", 14, "bold"),
        )
        self.friend_name_label.grid(row=0, column=0, sticky="w")
        self.chat_meta_var = tk.StringVar(value="")
        self.friend_meta_label = ttk.Label(
            self.friend_section,
            textvariable=self.chat_meta_var,
            justify="left",
            wraplength=960,
        )
        self.friend_meta_label.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        contact_button_box = ttk.Frame(self.friend_section)
        contact_button_box.grid(row=0, column=1, sticky="ne")
        self.fingerprint_button = ttk.Button(contact_button_box, text="Fingerprint", command=app.handle_show_fingerprint)
        self.fingerprint_button.pack(side="left", padx=(0, 6))
        self.verify_button = ttk.Button(contact_button_box, text="Verify", command=app.handle_verify_contact)
        self.verify_button.pack(side="left", padx=(0, 6))
        self.block_button = ttk.Button(contact_button_box, text="Block", command=app.handle_block_selected)
        self.block_button.pack(side="left", padx=(0, 6))
        self.unblock_button = ttk.Button(contact_button_box, text="Unblock", command=app.handle_unblock_selected)
        self.unblock_button.pack(side="left", padx=(0, 6))
        self.remove_button = ttk.Button(contact_button_box, text="Remove", command=app.handle_remove_selected)
        self.remove_button.pack(side="left")
        self.friend_action_buttons = [
            self.fingerprint_button,
            self.verify_button,
            self.block_button,
            self.unblock_button,
            self.remove_button,
        ]

        self.content_section_title_var = tk.StringVar(value="Chat Panel")
        self.content_section_label_frame = ttk.Frame(right)
        self.content_section_title_label = ttk.Label(
            self.content_section_label_frame,
            textvariable=self.content_section_title_var,
        )
        self.content_section_title_label.pack(side="left")

        self.content_section = ttk.LabelFrame(right, labelwidget=self.content_section_label_frame, padding=8)
        self.content_section.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        self.content_section.columnconfigure(0, weight=1)
        self.content_section.rowconfigure(0, weight=1)

        self.history_text = ScrolledText(self.content_section, wrap="word", state="disabled", height=20)
        self.history_text.grid(row=0, column=0, sticky="nsew")
        self.history_text.tag_configure("timestamp", foreground="#666666")
        self.history_text.tag_configure("incoming", spacing3=6, lmargin1=8, lmargin2=8)
        self.history_text.tag_configure("outgoing", spacing3=6, lmargin1=8, lmargin2=8)
        self.history_text.tag_configure("system", spacing3=6, lmargin1=8, lmargin2=8, foreground="#7a2f2f")
        self.history_text.tag_configure("body", lmargin1=16, lmargin2=16)
        self.history_text.tag_configure("placeholder", lmargin1=16, lmargin2=16, font=("TkDefaultFont", 10, "italic"))
        self.history_text.tag_configure("notice", spacing3=8, lmargin1=8, lmargin2=8, foreground="#204060")
        self.history_text.tag_configure(
            "incoming_header",
            spacing1=10,
            spacing3=2,
            lmargin1=8,
            lmargin2=8,
            rmargin=220,
            justify="left",
            foreground="#4e5b6d",
            font=("TkDefaultFont", 10, "bold"),
        )
        self.history_text.tag_configure(
            "incoming_meta",
            spacing3=2,
            lmargin1=8,
            lmargin2=8,
            rmargin=220,
            justify="left",
            foreground="#687786",
            font=("TkDefaultFont", 10, "bold"),
        )
        self.history_text.tag_configure(
            "incoming_body",
            spacing3=14,
            lmargin1=8,
            lmargin2=8,
            rmargin=220,
            justify="left",
        )
        self.history_text.tag_configure(
            "incoming_placeholder",
            spacing3=14,
            lmargin1=8,
            lmargin2=8,
            rmargin=220,
            justify="left",
            font=("TkDefaultFont", 10, "italic"),
            foreground="#5f6870",
        )
        self.history_text.tag_configure(
            "outgoing_header",
            spacing1=10,
            spacing3=2,
            lmargin1=200,
            lmargin2=200,
            rmargin=12,
            justify="right",
            foreground="#4e5b6d",
            font=("TkDefaultFont", 10, "bold"),
        )
        self.history_text.tag_configure(
            "outgoing_meta",
            spacing3=2,
            lmargin1=200,
            lmargin2=200,
            rmargin=12,
            justify="right",
            foreground="#687786",
            font=("TkDefaultFont", 10, "bold"),
        )
        self.history_text.tag_configure(
            "outgoing_body",
            spacing3=14,
            lmargin1=200,
            lmargin2=200,
            rmargin=12,
            justify="right",
        )
        self.history_text.tag_configure(
            "outgoing_placeholder",
            spacing3=14,
            lmargin1=200,
            lmargin2=200,
            rmargin=12,
            justify="right",
            font=("TkDefaultFont", 10, "italic"),
            foreground="#5f6870",
        )

        self.compose_section = ttk.LabelFrame(right, text="New Message", padding=12)
        self.compose_section.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        self.compose_section.columnconfigure(0, weight=1)
        self.message_input = tk.Text(self.compose_section, height=4, wrap="word")
        self.message_input.grid(row=0, column=0, sticky="ew")
        self.message_input.bind("<Control-Return>", lambda event: self.app.handle_send_message() or "break")
        self.ttl_enabled_var = tk.BooleanVar(value=False)
        self.ttl_seconds_var = tk.IntVar(value=30)
        compose_footer = ttk.Frame(self.compose_section)
        compose_footer.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        compose_footer.columnconfigure(0, weight=1)
        self.ttl_check = ttk.Checkbutton(
            compose_footer,
            text=DISAPPEARING_MESSAGE_CHECKBOX_LABEL,
            variable=self.ttl_enabled_var,
            command=self._toggle_ttl,
        )
        self.ttl_check.grid(row=0, column=0, columnspan=2, sticky="w")
        ttl_controls = ttk.Frame(compose_footer)
        ttl_controls.grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.ttl_after_label = ttk.Label(ttl_controls, text=DISAPPEARING_MESSAGE_AFTER_LABEL)
        self.ttl_after_label.grid(row=0, column=0, sticky="w")
        self.ttl_spin = ttk.Spinbox(ttl_controls, from_=1, to=86400, textvariable=self.ttl_seconds_var, width=8)
        self.ttl_spin.grid(row=0, column=1, sticky="w", padx=(8, 0))
        self.ttl_seconds_label = ttk.Label(ttl_controls, text=DISAPPEARING_MESSAGE_UNIT_LABEL)
        self.ttl_seconds_label.grid(row=0, column=2, sticky="w", padx=(6, 0))
        compose_button_box = ttk.Frame(compose_footer)
        compose_button_box.grid(row=1, column=1, sticky="e", pady=(6, 0))
        self.clear_message_button = ttk.Button(compose_button_box, text="Clear", command=self.clear_message_input)
        self.clear_message_button.pack(side="left", padx=(0, 6))
        self.send_message_button = ttk.Button(compose_button_box, text="Send", command=app.handle_send_message)
        self.send_message_button.pack(side="left")
        self.compose_controls = [
            self.ttl_check,
            self.ttl_spin,
            self.clear_message_button,
            self.send_message_button,
        ]
        self.compose_height_spacer = ttk.Frame(self.compose_section, height=0)
        self.compose_height_spacer.grid(row=2, column=0, sticky="ew")
        self._conversation_draft_text = ""
        self._toggle_ttl()
        self.after_idle(self._sync_compose_section_height)

        self._panel_section = "Conversations"
        self._compose_enabled = False
        self._content_is_interactive = True
        self._set_friend_controls_enabled(False)
        self.set_section_mode("Conversations", has_selected_friend=False)

    def _build_conversations_tab(self) -> None:
        frame = ttk.Frame(self.sidebar_notebook, padding=8)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        self.sidebar_notebook.add(frame, text="Conversations")

        self.conversations_tree = ttk.Treeview(
            frame,
            columns=("username", "unread", "last_activity"),
            show="headings",
            height=12,
        )
        self.conversations_tree.heading("username", text="Contact")
        self.conversations_tree.heading("unread", text="Unread")
        self.conversations_tree.heading("last_activity", text="Last Activity")
        self.conversations_tree.column("username", width=140, anchor="w")
        self.conversations_tree.column("unread", width=60, anchor="center")
        self.conversations_tree.column("last_activity", width=180, anchor="w")
        self.conversations_tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.conversations_tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.conversations_tree.configure(yscrollcommand=scroll.set)
        self.conversations_tree.bind("<<TreeviewSelect>>", lambda _event: self.app.handle_conversation_selected())
        self.conversations_tree.bind("<Double-1>", lambda _event: self.app.handle_conversation_selected())

    def _build_contacts_tab(self) -> None:
        frame = ttk.Frame(self.sidebar_notebook, padding=8)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        self.sidebar_notebook.add(frame, text="Contacts")

        self.contacts_tree = ttk.Treeview(
            frame,
            columns=("username", "messaging", "since"),
            show="headings",
            height=12,
        )
        for column, title, width in [
            ("username", "Contact", 130),
            ("messaging", "Messaging", 220),
            ("since", "Friend Since", 165),
        ]:
            self.contacts_tree.heading(column, text=title)
            self.contacts_tree.column(column, width=width, anchor="w")
        self.contacts_tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.contacts_tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.contacts_tree.configure(yscrollcommand=scroll.set)
        self.contacts_tree.bind("<<TreeviewSelect>>", lambda _event: self.app.handle_contact_selected())
        self.contacts_tree.bind("<Double-1>", lambda _event: self.app.handle_contact_selected())

        add_box = ttk.LabelFrame(frame, text="Add Contact", padding=8)
        add_box.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        add_box.columnconfigure(1, weight=1)
        self.add_friend_username_var = tk.StringVar()
        self.add_friend_note_var = tk.StringVar()
        ttk.Label(add_box, text="Username").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(add_box, textvariable=self.add_friend_username_var).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Label(add_box, text="Note").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(add_box, textvariable=self.add_friend_note_var).grid(row=1, column=1, sticky="ew", pady=4)
        ttk.Button(add_box, text="Send Friend Request", command=self.app.handle_add_friend).grid(row=2, column=0, columnspan=2, sticky="ew", pady=(8, 0))

    def _build_requests_tab(self) -> None:
        frame = ttk.Frame(self.sidebar_notebook, padding=8)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)
        self.sidebar_notebook.add(frame, text="Requests")

        ttk.Label(frame, text="Incoming Request").grid(row=0, column=0, sticky="w")
        self.incoming_tree = ttk.Treeview(
            frame,
            columns=("id", "sender", "created_at"),
            show="headings",
            height=6,
        )
        for column, title, width in [
            ("id", "ID", 50),
            ("sender", "From", 160),
            ("created_at", "Received", 185),
        ]:
            self.incoming_tree.heading(column, text=title)
            self.incoming_tree.column(column, width=width, anchor="w")
        self.incoming_tree.grid(row=1, column=0, sticky="nsew")
        self.incoming_tree.bind("<<TreeviewSelect>>", lambda _event: self.app.handle_incoming_request_selected())
        self.incoming_tree.bind("<Double-1>", lambda _event: self.app.handle_incoming_request_selected())
        incoming_buttons = ttk.Frame(frame)
        incoming_buttons.grid(row=2, column=0, sticky="ew", pady=(6, 6))
        ttk.Button(incoming_buttons, text="Accept", command=self.app.handle_accept_request).pack(side="left", padx=(0, 6))
        ttk.Button(incoming_buttons, text="Decline", command=self.app.handle_decline_request).pack(side="left")

        ttk.Label(frame, text="Outgoing Request").grid(row=3, column=0, sticky="w", pady=(0, 0))
        self.outgoing_tree = ttk.Treeview(
            frame,
            columns=("id", "receiver", "created_at"),
            show="headings",
            height=6,
        )
        for column, title, width in [
            ("id", "ID", 50),
            ("receiver", "To", 160),
            ("created_at", "Sent", 185),
        ]:
            self.outgoing_tree.heading(column, text=title)
            self.outgoing_tree.column(column, width=width, anchor="w")
        self.outgoing_tree.grid(row=4, column=0, sticky="nsew", pady=(2, 0))
        self.outgoing_tree.bind("<<TreeviewSelect>>", lambda _event: self.app.handle_outgoing_request_selected())
        self.outgoing_tree.bind("<Double-1>", lambda _event: self.app.handle_outgoing_request_selected())
        outgoing_buttons = ttk.Frame(frame)
        outgoing_buttons.grid(row=5, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(outgoing_buttons, text="Cancel", command=self.app.handle_cancel_request).pack(side="left")

    def _build_events_tab(self) -> None:
        frame = ttk.Frame(self.sidebar_notebook, padding=8)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        self.sidebar_notebook.add(frame, text="Security Alerts")

        self.events_tree = ttk.Treeview(
            frame,
            columns=("event_id", "created_at", "contact", "event_type"),
            displaycolumns=("created_at", "contact", "event_type"),
            show="headings",
            height=12,
        )
        for column, title, width in [
            ("created_at", "Time", 150),
            ("contact", "Contact", 110),
            ("event_type", "Issue", 120),
        ]:
            self.events_tree.heading(column, text=title)
            self.events_tree.column(column, width=width, anchor="w")
        self.events_tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=self.events_tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.events_tree.configure(yscrollcommand=scroll.set)
        self.events_tree.bind("<<TreeviewSelect>>", lambda _event: self.app.handle_security_event_selected())
        self.events_tree.bind("<Double-1>", lambda _event: self.app.handle_security_event_selected())

    def _build_activity_panel(
        self,
        parent: tk.Misc,
        *,
        row: int,
        column: int,
        pady: tuple[int, int] = (0, 0),
    ) -> None:
        self.activity_section = ttk.LabelFrame(parent, text="Recent Activity", padding=8)
        self.activity_section.grid(row=row, column=column, sticky="ew", pady=pady)
        self.activity_section.columnconfigure(0, weight=1)
        self.activity_section.rowconfigure(0, weight=1)
        self.activity_log = tk.Listbox(self.activity_section, height=7)
        self.activity_log.grid(row=0, column=0, sticky="nsew")
        activity_scroll = ttk.Scrollbar(self.activity_section, orient="vertical", command=self.activity_log.yview)
        activity_scroll.grid(row=0, column=1, sticky="ns")
        self.activity_log.configure(yscrollcommand=activity_scroll.set)
        ttk.Button(self.activity_section, text="Clear Log", command=lambda: self.activity_log.delete(0, "end")).grid(row=1, column=0, sticky="e", pady=(8, 0))

    def _toggle_ttl(self) -> None:
        state = "normal" if self.ttl_enabled_var.get() and self._compose_enabled else "disabled"
        self.ttl_spin.configure(state=state)

    def _sync_compose_section_height(self) -> None:
        if not getattr(self, "compose_height_spacer", None):
            return
        if not self.compose_section.winfo_ismapped():
            self.compose_height_spacer.configure(height=0)
            return
        try:
            self.compose_height_spacer.configure(height=0)
            self.update_idletasks()
            target_height = self.activity_section.winfo_reqheight()
            current_height = self.compose_section.winfo_reqheight()
            extra_height = max(0, target_height - current_height)
            self.compose_height_spacer.configure(height=extra_height)
        except tk.TclError:
            return

    def selected_conversation_username(self) -> str | None:
        selected = self.conversations_tree.selection()
        if not selected:
            return None
        values = self.conversations_tree.item(selected[0], "values")
        return str(values[0]) if values else None

    def selected_contact_username(self) -> str | None:
        selected = self.contacts_tree.selection()
        if not selected:
            return None
        values = self.contacts_tree.item(selected[0], "values")
        return str(values[0]) if values else None

    def selected_incoming_request_id(self) -> int | None:
        selected = self.incoming_tree.selection()
        if not selected:
            return None
        values = self.incoming_tree.item(selected[0], "values")
        return int(values[0]) if values else None

    def selected_outgoing_request_id(self) -> int | None:
        selected = self.outgoing_tree.selection()
        if not selected:
            return None
        values = self.outgoing_tree.item(selected[0], "values")
        return int(values[0]) if values else None

    def selected_event_contact(self) -> str | None:
        selected = self.events_tree.selection()
        if not selected:
            return None
        values = self.events_tree.item(selected[0], "values")
        return str(values[2]) if values else None

    def selected_event_id(self) -> int | None:
        selected = self.events_tree.selection()
        if not selected:
            return None
        values = self.events_tree.item(selected[0], "values")
        if not values:
            return None
        return int(values[0])

    def _message_input_text(self) -> str:
        return self.message_input.get("1.0", "end-1c")

    def _replace_message_input_text(self, value: str) -> None:
        previous_state = str(self.message_input.cget("state"))
        if previous_state == "disabled":
            self.message_input.configure(state="normal")
        self.message_input.delete("1.0", "end")
        if value:
            self.message_input.insert("1.0", value)
        if previous_state == "disabled":
            self.message_input.configure(state="disabled")

    def message_body(self) -> str:
        return self._message_input_text().rstrip()

    def ttl_seconds(self) -> int | None:
        if not self.ttl_enabled_var.get():
            return None
        return int(self.ttl_seconds_var.get())

    def clear_message_input(self) -> None:
        self._conversation_draft_text = ""
        self._replace_message_input_text("")

    def clear_sidebar_selection(self) -> None:
        for tree in (
            self.conversations_tree,
            self.contacts_tree,
            self.incoming_tree,
            self.outgoing_tree,
            self.events_tree,
        ):
            selection = tree.selection()
            if selection:
                tree.selection_remove(*selection)
            try:
                tree.focus("")
            except Exception:
                pass

    def clear_chat_view(self) -> None:
        self.chat_contact_var.set("")
        self.chat_meta_var.set("")
        self.history_text.configure(state="normal")
        self.history_text.delete("1.0", "end")
        self.history_text.configure(state="disabled")
        self._set_friend_controls_enabled(False)

    def clear_incoming_request_selection(self) -> None:
        selection = self.incoming_tree.selection()
        if selection:
            self.incoming_tree.selection_remove(*selection)
        try:
            self.incoming_tree.focus("")
        except Exception:
            pass

    def clear_outgoing_request_selection(self) -> None:
        selection = self.outgoing_tree.selection()
        if selection:
            self.outgoing_tree.selection_remove(*selection)
        try:
            self.outgoing_tree.focus("")
        except Exception:
            pass

    def set_friend_header(self, username: str | None, meta: str = "") -> None:
        self.chat_contact_var.set(username or "")
        self.chat_meta_var.set(meta)
        self._set_friend_controls_enabled(bool(username) and self._panel_section != "Requests")

    def _set_friend_controls_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for button in self.friend_action_buttons:
            button.configure(state=state)

    def _set_content_interactive(self, interactive: bool) -> None:
        self._content_is_interactive = interactive
        self.history_text.configure(takefocus=1 if interactive else 0, cursor="xterm" if interactive else "arrow")
        for sequence in (
            "<Button-1>",
            "<B1-Motion>",
            "<Double-1>",
            "<Triple-1>",
            "<ButtonRelease-1>",
            "<MouseWheel>",
            "<Button-4>",
            "<Button-5>",
            "<Key>",
        ):
            self.history_text.unbind(sequence)
            if not interactive:
                self.history_text.bind(sequence, lambda _event: "break")

    def set_section_mode(self, section_name: str, *, has_selected_friend: bool) -> None:
        normalized = str(section_name or "Conversations")
        self._panel_section = normalized
        content_title = "Chat Panel"
        friend_visible = normalized != "Requests"
        friend_enabled = friend_visible
        compose_enabled = normalized == "Conversations"
        content_interactive = normalized in {"Conversations", "Contacts", "Security Alerts"}
        if normalized == "Security Alerts":
            content_title = "Details"
            compose_enabled = False
        elif normalized == "Contacts":
            content_title = "Chat History"
            compose_enabled = False
        elif normalized == "Requests":
            content_title = "Note"
            compose_enabled = False

        previous_compose_enabled = self._compose_enabled
        if previous_compose_enabled and not compose_enabled:
            self._conversation_draft_text = self._message_input_text()
            self._replace_message_input_text("")
        elif not previous_compose_enabled and compose_enabled:
            self._replace_message_input_text(self._conversation_draft_text)
        elif not compose_enabled and self._message_input_text():
            self._replace_message_input_text("")

        self.friend_section.configure(text="Friend")
        if friend_visible:
            if not self.friend_section.winfo_manager():
                self.friend_section.grid(row=0, column=0, sticky="ew")
            self.content_section.grid_configure(pady=(8, 0))
        else:
            if self.friend_section.winfo_manager():
                self.friend_section.grid_remove()
            self.content_section.grid_configure(pady=(0, 0))
        self.content_section_title_var.set(content_title)
        self._compose_enabled = compose_enabled
        if compose_enabled:
            self.compose_section.grid()
            self.after_idle(self._sync_compose_section_height)
        else:
            self.compose_section.grid_remove()
        self.message_input.configure(state="normal" if compose_enabled else "disabled")
        control_state = "normal" if compose_enabled else "disabled"
        self.ttl_check.configure(state=control_state)
        self.clear_message_button.configure(state=control_state)
        self.send_message_button.configure(state=control_state)
        self._set_content_interactive(content_interactive)
        self._toggle_ttl()
        self._set_friend_controls_enabled(friend_enabled and has_selected_friend)

    def set_identity(self, summary: dict[str, Any]) -> None:
        self.identity_var.set(identity_summary_text(summary, display_tz=GUI_DISPLAY_TIMEZONE))

    def update_contacts(self, contacts: list[dict[str, Any]]) -> None:
        self._replace_tree_rows(
            self.contacts_tree,
            [
                (
                    str(row.get("username", "")),
                    contact_messaging_label(row),
                    format_timestamp(row.get("since"), fallback="Unknown", display_tz=GUI_DISPLAY_TIMEZONE),
                )
                for row in contacts
            ],
        )

    def update_conversations(self, conversations: list[dict[str, Any]]) -> None:
        self._replace_tree_rows(
            self.conversations_tree,
            [
                conversation_row_display(
                    row,
                    display_tz=GUI_DISPLAY_TIMEZONE,
                    zero_unread_label="--",
                )
                for row in conversations
            ],
        )

    def update_requests(self, requests_payload: dict[str, Any]) -> None:
        self._replace_tree_rows(
            self.incoming_tree,
            [
                (
                    row.get("request_id"),
                    str(row.get("sender_username") or ""),
                    format_timestamp(row.get("created_at"), fallback="Unknown", display_tz=GUI_DISPLAY_TIMEZONE),
                )
                for row in requests_payload.get("incoming", [])
            ],
        )
        self._replace_tree_rows(
            self.outgoing_tree,
            [
                (
                    row.get("request_id"),
                    str(row.get("receiver_username") or ""),
                    format_timestamp(row.get("created_at"), fallback="Unknown", display_tz=GUI_DISPLAY_TIMEZONE),
                )
                for row in requests_payload.get("outgoing", [])
            ],
        )

    def update_events(self, events: list[dict[str, Any]]) -> None:
        rows: list[tuple[Any, ...]] = []
        for row in events:
            created, contact, event_type, _detail = event_row_display(row, display_tz=GUI_DISPLAY_TIMEZONE)
            rows.append((row.get("id"), created, contact, event_type))
        self._replace_tree_rows(self.events_tree, rows)

    def render_chat(
        self,
        username: str,
        rows: list[dict[str, Any]],
        fingerprint_text: str,
        note: str | None = None,
        *,
        show_recent_limit_notice: bool = False,
    ) -> None:
        self.set_friend_header(username, fingerprint_text if note is None else f"{fingerprint_text}\n{note}")
        self.history_text.configure(state="normal")
        self.history_text.delete("1.0", "end")
        self.history_text.insert(
            "end",
            history_retention_notice(display_tz=GUI_DISPLAY_TIMEZONE) + "\n",
            ("notice",),
        )
        if show_recent_limit_notice:
            self.history_text.insert(
                "end",
                recent_history_limit_label(RECENT_CONVERSATION_CHAT_LIMIT) + "\n\n",
                ("notice",),
            )
        else:
            self.history_text.insert("end", "\n", ("notice",))
        if not rows:
            self.history_text.insert("end", "No local messages yet for this conversation.\n", ("system",))
        for row in rows:
            direction = row.get("direction")
            title = chat_header(row, username, display_tz=GUI_DISPLAY_TIMEZONE)
            secondary = chat_secondary_header(row, username, display_tz=GUI_DISPLAY_TIMEZONE)
            body = message_body_for_display(row)
            if direction == "out":
                body_tag = "outgoing_placeholder" if message_is_unavailable(row) else "outgoing_body"
                self.history_text.insert("end", title + "\n", ("outgoing_header",))
                if secondary:
                    self.history_text.insert("end", secondary + "\n", ("outgoing_meta",))
                self.history_text.insert("end", body + "\n\n", (body_tag,))
            elif direction == "in":
                body_tag = "incoming_placeholder" if message_is_unavailable(row) else "incoming_body"
                self.history_text.insert("end", title + "\n", ("incoming_header",))
                if secondary:
                    self.history_text.insert("end", secondary + "\n", ("incoming_meta",))
                self.history_text.insert("end", body + "\n\n", (body_tag,))
            else:
                body_tags = ("placeholder", "system") if message_is_unavailable(row) else ("body", "system")
                created_at = format_timestamp(row.get("created_at"), fallback="Unknown time", display_tz=GUI_DISPLAY_TIMEZONE)
                self.history_text.insert("end", f"System • {created_at}\n", ("timestamp", "system"))
                self.history_text.insert("end", body + "\n\n", body_tags)
        self.history_text.configure(state="disabled")
        self.history_text.see("end")

    def render_security_event_details(self, event: dict[str, Any], *, note: str | None = None) -> None:
        contact = str(event.get("contact_username") or "")
        event_type = str(event.get("event_type") or "")
        issue = event_type_label(event_type)
        created = format_timestamp(event.get("created_at"), fallback="Unknown time", display_tz=GUI_DISPLAY_TIMEZONE)
        detail = str(event.get("detail") or "No additional details were provided.")
        self.set_friend_header(contact, note or "")
        self.history_text.configure(state="normal")
        self.history_text.delete("1.0", "end")
        if event_type == "verification_required":
            recommended_action = [
                "1. Compare the current safety number with your friend out of band.",
                "2. Use Verify after you confirm the safety number.",
                "3. Normal messaging stays blocked until this friend is verified.",
            ]
        elif event_type == "peer_verification_required":
            recommended_action = [
                "1. Share your current safety number with your friend out of band.",
                "2. Ask this friend to verify your current safety number.",
                "3. Messaging stays blocked until they verify you.",
            ]
        elif event_type == "local_key_change":
            recommended_action = [
                "1. Because you rotated your own keys, share your current safety number with your friend again.",
                "2. Ask this friend to verify your new safety number.",
                "3. Messaging stays blocked until they do.",
            ]
        else:
            recommended_action = [
                "1. Compare the current safety number with your friend out of band.",
                "2. Use Verify after you confirm the new fingerprint.",
                "3. Messaging remains blocked until the new key is trusted.",
            ]
        lines = [
            f"Time: {created}",
            f"Friend: {contact or 'Unknown'}",
            f"Issue: {issue}",
            "",
            "Details:",
            detail,
            "",
            "Recommended Action:",
            *recommended_action,
        ]
        self.history_text.insert("end", "\n".join(lines) + "\n", ("body", "system"))
        self.history_text.configure(state="disabled")
        self.history_text.see("1.0")

    def render_request_note(self, row: dict[str, Any], *, outgoing: bool) -> None:
        actor = str(row.get("receiver_username") if outgoing else row.get("sender_username") or "")
        direction_label = "Outgoing request to" if outgoing else "Incoming request from"
        created_label = "Sent" if outgoing else "Received"
        created = format_timestamp(row.get("created_at"), fallback="Unknown time", display_tz=GUI_DISPLAY_TIMEZONE)
        note = note_label(row.get("note"))
        self.set_friend_header(None, "")
        self.history_text.configure(state="normal")
        self.history_text.delete("1.0", "end")
        lines = [
            f"{direction_label} {actor or 'Unknown'}",
            f"{created_label}: {created}",
            "",
            "Note:",
            note,
        ]
        self.history_text.insert("end", "\n".join(lines) + "\n", ("body", "system"))
        self.history_text.configure(state="disabled")
        self.history_text.see("1.0")

    def append_activity(self, message: str) -> None:
        self.activity_log.insert("end", activity_entry(message, display_tz=GUI_DISPLAY_TIMEZONE))
        self.activity_log.see("end")

    @staticmethod
    def _replace_tree_rows(tree: ttk.Treeview, rows: list[tuple[Any, ...]]) -> None:
        current_selection = tree.selection()
        current_value = None
        if current_selection:
            values = tree.item(current_selection[0], "values")
            current_value = values[0] if values else None
        tree.delete(*tree.get_children())
        item_to_select = None
        for row in rows:
            item_id = tree.insert("", "end", values=row)
            if current_value is not None and str(row[0]) == str(current_value):
                item_to_select = item_id
        if item_to_select is not None:
            tree.selection_set(item_to_select)
            tree.focus(item_to_select)


class CipherLinkDesktopApp(tk.Tk):
    def __init__(self, *, initial_profile: str | None = None, initial_base_dir: str | None = None) -> None:
        super().__init__()
        self.initial_profile = initial_profile
        self.initial_base_dir = initial_base_dir
        self.title(GUI_WINDOW_TITLE)
        self.geometry("1420x900")
        self.minsize(1180, 760)
        try:
            ttk.Style(self).theme_use("clam")
        except Exception:
            pass

        self._ui_queue: queue.Queue[tuple[str, str, Any, Any]] = queue.Queue()
        self.controller = CipherLinkGUIController(event_callback=lambda event: self._ui_queue.put(("controller", "", event, None)))
        self.status_var = tk.StringVar(value="Ready.")
        self.current_contact: str | None = None
        self.visible_chat_contact: str | None = None
        self.contacts_cache: dict[str, dict[str, Any]] = {}
        self.requests_cache: dict[str, dict[int, dict[str, Any]]] = {"incoming": {}, "outgoing": {}}
        self.events_cache: dict[int, dict[str, Any]] = {}
        self.current_fingerprint_info: dict[str, Any] | None = None
        self._busy_count = 0
        self._pending_conversation_load: str | None = None
        self._pending_contact_history_load: str | None = None
        self._rendered_contact_history_contact: str | None = None
        self._expiry_refresh_after_id: str | None = None

        self._build_menu()

        self.container = ttk.Frame(self, padding=0)
        self.container.pack(fill="both", expand=True)
        self.container.rowconfigure(0, weight=1)
        self.container.columnconfigure(0, weight=1)

        self.auth_frame = AuthFrame(self.container, self)
        self.main_frame = MainFrame(self.container, self)
        self.auth_frame.grid(row=0, column=0, sticky="nsew")
        self.main_frame.grid(row=0, column=0, sticky="nsew")
        self._show_auth()

        status_bar = ttk.Label(self, textvariable=self.status_var, anchor="w", relief="sunken", padding=(8, 4))
        status_bar.pack(fill="x", side="bottom")

        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.after(100, self._process_ui_events)

    def _build_menu(self) -> None:
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label=AUTH_TAB_REOPEN_SESSION, command=self.handle_open_saved_session)
        file_menu.add_command(label="Sync", command=self.handle_sync)
        file_menu.add_separator()
        file_menu.add_command(label="Logout", command=self.handle_logout)
        file_menu.add_command(label="Exit", command=self.on_close)
        menu.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menu, tearoff=False)
        tools_menu.add_command(label="Rotate keys", command=self.handle_rotate_keys)
        tools_menu.add_command(label="Show selected fingerprint", command=self.handle_show_fingerprint)
        tools_menu.add_command(label="Verify selected contact", command=self.handle_verify_contact)
        menu.add_cascade(label="Security", menu=tools_menu)

        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="About", command=self._show_about)
        menu.add_cascade(label="Help", menu=help_menu)
        self.config(menu=menu)

    def _show_about(self) -> None:
        self._show_info_dialog(
            f"About {APP_BRAND_NAME}",
            f"{GUI_WINDOW_TITLE}\n\n"
            f"GUI client for the existing {APP_BRAND_NAME} CLI/runtime implementation.\n"
            "The GUI reuses the same runtime, TLS, OTP, local vault, local storage, and E2EE messaging flow as the CLI.",
        )

    def _show_info_dialog(
        self,
        title: str,
        message: str,
        *,
        auto_sync: bool = False,
        sync_reason: str | None = None,
    ) -> None:
        messagebox.showinfo(title, message, parent=self)
        if auto_sync:
            self._request_implicit_sync(sync_reason or f"Closed the {title} dialog")

    def _show_error_dialog(
        self,
        title: str,
        message: str,
        *,
        auto_sync: bool = False,
        sync_reason: str | None = None,
    ) -> None:
        messagebox.showerror(title, message, parent=self)
        if auto_sync:
            self._request_implicit_sync(sync_reason or f"Acknowledged the {title} error")

    def _request_implicit_sync(self, reason: str) -> None:
        if not self.controller.can_sync():
            return
        self.handle_sync(silent=True, reason=reason)

    def _cancel_expiry_refresh(self) -> None:
        after_id = getattr(self, "_expiry_refresh_after_id", None)
        if after_id is not None:
            try:
                self.after_cancel(after_id)
            except Exception:
                pass
        self._expiry_refresh_after_id = None

    def _schedule_expiry_refresh(self) -> None:
        self._cancel_expiry_refresh()
        try:
            next_expiry_at = self.controller.next_refresh_at()
        except Exception:
            return
        expires_dt = parse_datetime(next_expiry_at)
        if expires_dt is None:
            return
        delay_ms = max(50, int((expires_dt - utc_now()).total_seconds() * 1000) + 50)
        self._expiry_refresh_after_id = self.after(delay_ms, self._handle_expiry_refresh_due)

    def _handle_expiry_refresh_due(self) -> None:
        self._expiry_refresh_after_id = None
        section = self._current_sidebar_section()
        visible_chat = self._current_visible_chat()
        if visible_chat is not None:
            self._refresh_local_views(reload_chat_username=visible_chat, reload_contact_history_username=None)
            return
        if section == "Contacts" and self.current_contact is not None:
            self._refresh_local_views(reload_chat_username=None, reload_contact_history_username=self.current_contact)
            return
        self._refresh_local_views(reload_chat_username=None, reload_contact_history_username=None)

    def _current_sidebar_section(self) -> str:
        try:
            tab_id = self.main_frame.sidebar_notebook.select()
            return str(self.main_frame.sidebar_notebook.tab(tab_id, "text") or "Conversations")
        except Exception:
            return "Conversations"

    @staticmethod
    def _is_live_chat_section(section_name: str | None) -> bool:
        return str(section_name or "") == "Conversations"

    def _has_live_chat_selection(self) -> bool:
        return self.current_contact is not None and self._current_sidebar_section() == "Conversations"

    def _has_contact_history_selection(self) -> bool:
        return self.current_contact is not None and self._current_sidebar_section() == "Contacts"

    def _current_visible_chat(self) -> str | None:
        if not self._is_live_chat_section(self._current_sidebar_section()):
            return None
        return self.visible_chat_contact

    def _set_visible_chat_contact(self, username: str | None) -> None:
        normalized = str(username or "").strip().lower() or None
        self.visible_chat_contact = normalized
        self.controller.set_visible_chat_contact(self._current_visible_chat())

    @staticmethod
    def _friend_header_lines(
        contact: dict[str, Any] | None,
        fingerprint: dict[str, Any] | None,
        fingerprint_error: str | None = None,
    ) -> tuple[str, str, str]:
        if fingerprint is None:
            safety_line = "Safety Number: unavailable"
            verified_line = "Verified status: Unknown"
        else:
            display = str(fingerprint.get("display") or "unavailable")
            status = trust_state_label(fingerprint.get("trust_state"))
            safety_line = f"Safety Number: {display}"
            verified_line = f"Verified status: {status}"
        if contact is None:
            block_line = "Block Status: Unknown"
        else:
            block_line = f"Block Status: {contact_messaging_label(contact)}"
        return (safety_line, verified_line, block_line)

    def _selected_request_record(self) -> tuple[dict[str, Any] | None, bool | None]:
        incoming_id = self.main_frame.selected_incoming_request_id()
        if incoming_id is not None:
            return self.requests_cache.get("incoming", {}).get(incoming_id), False
        outgoing_id = self.main_frame.selected_outgoing_request_id()
        if outgoing_id is not None:
            return self.requests_cache.get("outgoing", {}).get(outgoing_id), True
        return None, None

    def _refresh_selected_request_note(self) -> None:
        if self._current_sidebar_section() != "Requests":
            return
        record, outgoing = self._selected_request_record()
        self.current_contact = None
        self._set_visible_chat_contact(None)
        self.current_fingerprint_info = None
        self._pending_conversation_load = None
        self._pending_contact_history_load = None
        self._rendered_contact_history_contact = None
        if record is None or outgoing is None:
            self.main_frame.clear_chat_view()
            self._apply_right_panel_mode()
            return
        self._apply_right_panel_mode()
        self.main_frame.render_request_note(record, outgoing=outgoing)
        actor = str(record.get("receiver_username") if outgoing else record.get("sender_username") or "")
        self.status_var.set(f"Selected {'outgoing' if outgoing else 'incoming'} request for {actor or 'unknown'}.")

    def _conversation_rows_with_accepted_contacts(self, conversations: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for row in conversations or []:
            username = str(row.get("contact_username") or "").strip().lower()
            if not username:
                continue
            merged[username] = dict(row)

        for username, contact in self.contacts_cache.items():
            if str(contact.get("friendship_status") or "") != "accepted":
                continue
            if username in merged:
                continue
            merged[username] = {
                "contact_username": username,
                "unread_count": 0,
                "last_local_id": None,
                "last_activity_at": contact.get("initial_note_created_at") or contact.get("since"),
            }

        def sort_key(row: dict[str, Any]) -> tuple[float, str]:
            timestamp = parse_datetime(row.get("last_activity_at"))
            return ((timestamp.timestamp() if timestamp is not None else float("-inf")), str(row.get("contact_username") or ""))

        return sorted(merged.values(), key=sort_key, reverse=True)

    def _selection_still_exists(
        self,
        *,
        contacts: list[dict[str, Any]] | None,
        conversations: list[dict[str, Any]] | None,
        events: list[dict[str, Any]] | None,
    ) -> bool:
        if self.current_contact is None:
            return True
        username = self.current_contact.lower()
        section = self._current_sidebar_section()
        if section == "Conversations":
            return any(str(row.get("contact_username") or "").strip().lower() == username for row in conversations or [])
        if section == "Contacts":
            return any(str(row.get("username") or "").strip().lower() == username for row in contacts or [])
        if section == "Security Alerts":
            return any(str(row.get("contact_username") or "").strip().lower() == username for row in events or [])
        return False

    def _history_rows_with_initial_note(
        self,
        username: str,
        rows: list[dict[str, Any]] | None,
        *,
        max_rows: int | None = None,
    ) -> list[dict[str, Any]]:
        rendered_rows = list(rows or [])
        if any(str(row.get("message_id") or "").startswith("initial-note:") for row in rendered_rows):
            return rendered_rows
        if max_rows is not None and len(rendered_rows) >= max_rows:
            return rendered_rows
        contact = self.contacts_cache.get(username.lower())
        if contact is None:
            return rendered_rows
        note = str(contact.get("initial_note") or "").strip()
        if not note:
            return rendered_rows
        created_at = contact.get("initial_note_created_at") or contact.get("since") or utc_now().isoformat()
        if not within_history_retention(created_at):
            return rendered_rows
        direction = str(contact.get("initial_note_direction") or "").strip().lower()
        if direction not in {"in", "out"}:
            direction = "system"
        synthetic_row = {
            "local_id": 0,
            "message_id": f"initial-note:{username.lower()}:{created_at}",
            "direction": direction,
            "created_at": created_at,
            "payload": {"text": note},
            "expires_at": None,
            "sent_status": None,
            "delivered_at": None,
        }
        return [synthetic_row, *rendered_rows]

    def _apply_right_panel_mode(self) -> None:
        self.main_frame.set_section_mode(
            self._current_sidebar_section(),
            has_selected_friend=bool(self.current_contact),
        )

    def _focus_security_alerts(self, *, reason: str) -> None:
        notebook = self.main_frame.sidebar_notebook
        current_tab_id = None
        try:
            current_tab_id = notebook.select()
        except Exception:
            current_tab_id = None
        target_tab_id: str | None = None
        try:
            for tab_id in notebook.tabs():
                if str(notebook.tab(tab_id, "text") or "") == "Security Alerts":
                    target_tab_id = str(tab_id)
                    break
        except Exception:
            target_tab_id = None
        if target_tab_id is None:
            self._request_implicit_sync(reason)
            return
        if current_tab_id == target_tab_id:
            self._reset_sidebar_selection_and_chat_view()
            self._apply_right_panel_mode()
            self._request_implicit_sync(reason)
            return
        notebook.select(target_tab_id)

    def _is_session_expired_message(self, message: str) -> bool:
        return self.controller.is_session_expired_error(message)

    def _complete_forced_logout(self, result: dict[str, Any] | None = None) -> None:
        self._reset_sidebar_selection_and_chat_view(clear_message_draft=True)
        self.contacts_cache.clear()
        self.events_cache.clear()
        self._show_auth()
        logout_message = (result or {}).get("message") or "Logged out automatically after session expiration."
        self.main_frame.append_activity(logout_message)
        self.status_var.set("Session expired. Please log in again.")

    def _show_session_expired_dialog_and_logout(self, message: str) -> None:
        detail = f"{message}\n\nClick OK to log out automatically."
        messagebox.showerror("Session expired", detail, parent=self)
        try:
            result = self.controller.force_local_logout()
        except Exception:
            result = {"message": "Logged out automatically after session expiration."}
        self._complete_forced_logout(result)

    @staticmethod
    def _is_security_send_failure(label: str, message: str) -> bool:
        normalized_label = str(label or "").lower()
        normalized_message = str(message or "").lower()
        if not normalized_label.startswith("send to"):
            return False
        return any(
            token in normalized_message
            for token in (
                "refusing to send",
                "changed keys",
                "key changed",
                "verify-contact",
                "verify contact",
                "security warning",
            )
        )

    def _reset_sidebar_selection_and_chat_view(self, *, clear_message_draft: bool = False) -> None:
        self.current_contact = None
        self._set_visible_chat_contact(None)
        self.current_fingerprint_info = None
        self._pending_conversation_load = None
        self._pending_contact_history_load = None
        self._rendered_contact_history_contact = None
        self.main_frame.clear_sidebar_selection()
        self.main_frame.clear_chat_view()
        if clear_message_draft:
            self.main_frame.clear_message_input()
        self._apply_right_panel_mode()

    def _show_auth(self) -> None:
        self._cancel_expiry_refresh()
        self.auth_frame.tkraise()
        self.status_var.set("Ready. Create a profile, confirm OTP, log in, or reopen a session.")

    def _show_main(self) -> None:
        self.main_frame.tkraise()

    def on_close(self) -> None:
        try:
            self.controller.close()
        finally:
            self.destroy()

    def _set_busy(self, busy: bool) -> None:
        self._busy_count = max(0, self._busy_count + (1 if busy else -1))
        cursor = "watch" if self._busy_count > 0 else ""
        try:
            self.configure(cursor=cursor)
        except Exception:
            pass

    def _run_task(
        self,
        label: str,
        func: Callable[[], Any],
        *,
        on_success: Callable[[Any], None] | None = None,
        on_error: Callable[[str], None] | None = None,
    ) -> None:
        self._set_busy(True)
        self.status_var.set(f"{label}…")

        def runner() -> None:
            try:
                result = func()
            except Exception as exc:
                self._ui_queue.put(("task_error", label, exc, on_error))
            else:
                self._ui_queue.put(("task_success", label, result, on_success))

        threading.Thread(target=runner, name=f"gui-task-{label}", daemon=True).start()

    def _process_ui_events(self) -> None:
        try:
            while True:
                try:
                    event_type, label, payload, callback = self._ui_queue.get_nowait()
                except queue.Empty:
                    break

                try:
                    if event_type == "task_success":
                        self._set_busy(False)
                        self.status_var.set(f"{label} completed.")
                        if callback is not None:
                            callback(payload)
                    elif event_type == "task_error":
                        self._set_busy(False)
                        message = self.controller.format_user_error(payload)
                        self.status_var.set(f"{label} failed: {message}")
                        if self._is_session_expired_message(message):
                            self.main_frame.append_activity(f"{label}: {message}")
                            self._show_session_expired_dialog_and_logout(message)
                        elif callback is not None:
                            callback(message)
                        elif self._is_security_send_failure(label, message):
                            self._show_error_dialog(label, message)
                            self._focus_security_alerts(reason=f"Acknowledged the {label} error dialog")
                        else:
                            self._show_error_dialog(
                                label,
                                message,
                                auto_sync=True,
                                sync_reason=f"Acknowledged the {label} error dialog",
                            )
                        if not self._is_session_expired_message(message):
                            self.main_frame.append_activity(f"{label}: {message}")
                    elif event_type == "controller":
                        self._handle_controller_event(payload)
                except Exception as exc:
                    message = self.controller.format_user_error(exc)
                    dispatch_label = label or event_type or "UI event"
                    self.status_var.set(f"{dispatch_label} failed in the GUI: {message}")
                    try:
                        self.main_frame.append_activity(f"{dispatch_label}: {message}")
                    except Exception:
                        pass
        finally:
            self.after(100, self._process_ui_events)

    def _handle_controller_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("type")
        if event_type == "listener_status":
            level = event.get("level", "info")
            message = str(event.get("message", ""))
            self.status_var.set(message)
            level_label = str(level).replace("_", " ").title()
            self.main_frame.append_activity(f"{level_label}: {message}")
            return
        if event_type == "session_expired":
            message = str(event.get("message") or "HTTP 401: Session is invalid or expired.")
            self.main_frame.append_activity(message)
            self._show_session_expired_dialog_and_logout(message)
            return
        if event_type == "connected":
            username = event.get("username") or "?"
            pending = int(event.get("pending_messages") or 0)
            self.status_var.set(f"Live updates connected for {username}. Pending queued messages: {pending}.")
            self.main_frame.append_activity(f"Live updates connected for {username}. Pending queued messages: {pending}.")
            self._refresh_remote_snapshot(silent=True, reason="Realtime connection restored")
            return
        if event_type == "friend_request_received":
            sender = event.get("sender_username") or "unknown"
            note = note_label(event.get("note"))
            self.main_frame.append_activity(f"New friend request from {sender}. Note: {note}.")
            self.status_var.set(f"New friend request from {sender}.")
            self._refresh_remote_snapshot(silent=True, reason=f"Friend request from {sender}")
            return
        if event_type == "friend_request_updated":
            request_id = event.get("request_id")
            status = str(event.get("status") or "updated").replace("_", " ")
            actor = event.get("by") or "someone"
            self.main_frame.append_activity(f"Friend request #{request_id} is now {status}. Updated by {actor}.")
            self.status_var.set("Friend request updated.")
            self._refresh_remote_snapshot(silent=True, reason=f"Friend request #{request_id} updated")
            return
        if event_type == "chat":
            sender = event.get("from") or "unknown"
            self.main_frame.append_activity(incoming_message_notice_text(event, display_tz=GUI_DISPLAY_TIMEZONE))
            self.status_var.set(f"New message from {sender}.")
            visible_chat = self._current_visible_chat()
            reload_chat_username = sender if visible_chat == str(sender).lower() else None
            self._refresh_local_views(reload_chat_username=reload_chat_username, reload_contact_history_username=None)
            return
        if event_type == "discarded":
            self._refresh_local_views(reload_chat_username=self._current_visible_chat(), reload_contact_history_username=None)
            return
        if event_type == "duplicate":
            return
        if event_type == "delivery_ack":
            self.main_frame.append_activity(delivery_ack_text(event, display_tz=GUI_DISPLAY_TIMEZONE))
            self.status_var.set("A message was marked as read.")
            self._refresh_local_views(reload_chat_username=self._current_visible_chat(), reload_contact_history_username=None)
            return
        if event_type == "error":
            detail = event.get("detail") or "Unknown processing error"
            self.main_frame.append_activity(f"Sync error: {detail}")
            self.status_var.set(str(detail))
            self._refresh_local_views(reload_chat_username=None, reload_contact_history_username=None)
            return
        if event_type == "sync_results":
            source = str(event.get("source") or "manual")
            self._handle_sync_results(event.get("results") or [], source=source, show_empty=(source != "auto"))
            self._refresh_local_views(reload_chat_username=self._current_visible_chat(), reload_contact_history_username=None)
            return
        if event_type == "local_snapshot_required":
            self._refresh_local_views(reload_chat_username=self._current_visible_chat(), reload_contact_history_username=None)
            return
        self.main_frame.append_activity(f"Other live event: {event}")

    def _show_text_dialog(
        self,
        title: str,
        text: str,
        *,
        auto_sync: bool = False,
        sync_reason: str | None = None,
    ) -> None:
        dialog = tk.Toplevel(self)
        dialog.title(title)
        dialog.geometry("760x420")
        dialog.transient(self)
        dialog.grab_set()
        dialog.columnconfigure(0, weight=1)
        dialog.rowconfigure(0, weight=1)
        body = ScrolledText(dialog, wrap="word")
        body.grid(row=0, column=0, sticky="nsew", padx=12, pady=12)
        body.insert("1.0", text)
        body.configure(state="disabled")
        button_bar = ttk.Frame(dialog)
        button_bar.grid(row=1, column=0, sticky="e", padx=12, pady=(0, 12))

        closed = False

        def close_dialog() -> None:
            nonlocal closed
            if closed:
                return
            closed = True
            try:
                dialog.grab_release()
            except Exception:
                pass
            dialog.destroy()
            if auto_sync:
                self._request_implicit_sync(sync_reason or f"Closed the {title} dialog")

        ttk.Button(button_bar, text="Copy", command=lambda: self._copy_text(text)).pack(side="left", padx=(0, 8))
        ttk.Button(button_bar, text="Close", command=close_dialog).pack(side="left")
        dialog.protocol("WM_DELETE_WINDOW", close_dialog)

    def _copy_text(self, value: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(value)
        self.status_var.set("Copied to clipboard.")

    def _auth_field_values(self) -> dict[str, str]:
        profile_name, base_dir = self.auth_frame.profile_settings()
        credentials = self.auth_frame.credentials()
        connection = self.auth_frame.registration_connection_settings()
        return {
            "profile_name": profile_name,
            "base_dir": base_dir or "",
            "username": credentials["username"],
            "password": credentials["password"],
            "device_passphrase": credentials["device_passphrase"],
            "otp": credentials["otp_code"],
            "bootstrap": connection.get("bootstrap_path") or "",
            "server_url": connection.get("server_url") or "",
            "ca_cert": connection.get("ca_cert_path") or "",
        }

    def _missing_required_auth_fields(self, tab_name: str) -> list[str]:
        values = self._auth_field_values()
        required = required_auth_fields(tab_name, server_mode=self.auth_frame.server_mode_var.get())
        missing: list[str] = []
        for field_name in AUTH_FIELD_LABELS:
            if field_name not in required:
                continue
            value = values.get(field_name, "")
            if field_name in {"password", "device_passphrase"}:
                is_missing = value == ""
            else:
                is_missing = not str(value).strip()
            if is_missing:
                missing.append(field_name)
        return missing

    def _validate_required_auth_fields(self, tab_name: str, *, title: str) -> bool:
        missing_fields = self._missing_required_auth_fields(tab_name)
        if not missing_fields:
            return True
        message = "Fill in the required fields before continuing:\n\n" + "\n".join(
            f"• {AUTH_FIELD_LABELS[field_name]}" for field_name in missing_fields
        )
        messagebox.showerror(title, message, parent=self)
        return False

    def _require_profile_settings(self) -> tuple[str, str | None]:
        profile_name, base_dir = self.auth_frame.profile_settings()
        if not profile_name:
            raise ValueError("Profile name is required.")
        return profile_name, base_dir

    def _require_credentials(self, *, need_username: bool = True, need_password: bool = True, need_device_passphrase: bool = True, need_otp: bool = False) -> dict[str, str]:
        creds = self.auth_frame.credentials()
        if need_username and not creds["username"]:
            raise ValueError("Username is required.")
        if need_password and not creds["password"]:
            raise ValueError("Account password is required.")
        if need_device_passphrase and not creds["device_passphrase"]:
            raise ValueError("Device vault passphrase is required.")
        if need_otp and not creds["otp_code"]:
            raise ValueError("OTP code is required.")
        return creds

    def _require_selected_contact(self) -> str:
        if not self.current_contact:
            raise ValueError("Select a conversation or contact first.")
        return self.current_contact

    def handle_register(self) -> None:
        if not self._validate_required_auth_fields(AUTH_TAB_REGISTER, title="Register"):
            return
        try:
            profile_name, base_dir = self._require_profile_settings()
            creds = self._require_credentials(need_otp=False)
            connection = self.auth_frame.registration_connection_settings()
            if connection["bootstrap_path"] is None:
                if not connection["server_url"] or not connection["ca_cert_path"]:
                    raise ValueError("Registration requires either a bootstrap file or both server URL and CA certificate.")
        except Exception as exc:
            messagebox.showerror("Register", self.controller.format_user_error(exc), parent=self)
            return

        self._run_task(
            "Register",
            lambda: self.controller.register(
                profile_name=profile_name,
                base_dir=base_dir,
                username=creds["username"],
                password=creds["password"],
                device_passphrase=creds["device_passphrase"],
                bootstrap_path=connection["bootstrap_path"],
                server_url=connection["server_url"],
                ca_cert_path=connection["ca_cert_path"],
            ),
            on_success=self._after_register,
        )

    def _after_register(self, result: dict[str, Any]) -> None:
        self.auth_frame.switch_to_confirm_tab()
        self.status_var.set("Registration created. Configure your authenticator app, then confirm OTP.")
        self.main_frame.append_activity("Registration succeeded. Awaiting OTP confirmation.")
        display_text = (
            f"Username: {result.get('username')}\n\n"
            f"Message: {result.get('message')}\n\n"
            f"OTP secret (Base32):\n{result.get('otp_secret_base32')}\n\n"
            f"Provisioning URI:\n{result.get('otp_provisioning_uri')}\n"
        )
        self._show_text_dialog("Registration succeeded", display_text)

    def handle_confirm_otp(self) -> None:
        if not self._validate_required_auth_fields(AUTH_TAB_CONFIRM_OTP, title="Confirm OTP"):
            return
        try:
            profile_name, base_dir = self._require_profile_settings()
            creds = self._require_credentials(need_otp=True)
        except Exception as exc:
            messagebox.showerror("Confirm OTP", self.controller.format_user_error(exc), parent=self)
            return

        self._run_task(
            "Confirm OTP",
            lambda: self.controller.confirm_registration_otp(
                profile_name=profile_name,
                base_dir=base_dir,
                username=creds["username"],
                password=creds["password"],
                otp_code=creds["otp_code"],
                device_passphrase=creds["device_passphrase"],
            ),
            on_success=self._after_confirm_otp,
        )

    def _after_confirm_otp(self, result: dict[str, Any]) -> None:
        self.auth_frame.switch_to_login_tab()
        self.status_var.set(result.get("message", "OTP confirmed."))
        self.main_frame.append_activity(result.get("message", "OTP confirmed."))
        self._show_info_dialog(
            "Confirm OTP",
            result.get("message", "OTP confirmed."),
            auto_sync=True,
            sync_reason="Acknowledged the OTP confirmation dialog",
        )

    def handle_login(self) -> None:
        if not self._validate_required_auth_fields(AUTH_TAB_LOGIN, title="Log in"):
            return
        try:
            profile_name, base_dir = self._require_profile_settings()
            creds = self._require_credentials(need_otp=True)
        except Exception as exc:
            messagebox.showerror("Log in", self.controller.format_user_error(exc), parent=self)
            return

        self._run_task(
            "Log in",
            lambda: self.controller.login(
                profile_name=profile_name,
                base_dir=base_dir,
                username=creds["username"],
                password=creds["password"],
                otp_code=creds["otp_code"],
                device_passphrase=creds["device_passphrase"],
            ),
            on_success=self._after_authenticated,
        )

    def handle_open_saved_session(self) -> None:
        if not self._validate_required_auth_fields(AUTH_TAB_REOPEN_SESSION, title=AUTH_TAB_REOPEN_SESSION):
            return
        try:
            profile_name, base_dir = self._require_profile_settings()
            creds = self._require_credentials(need_username=False, need_password=False, need_device_passphrase=True, need_otp=False)
        except Exception as exc:
            messagebox.showerror(AUTH_TAB_REOPEN_SESSION, self.controller.format_user_error(exc), parent=self)
            return

        self._run_task(
            AUTH_TAB_REOPEN_SESSION,
            lambda: self.controller.open_saved_session(
                profile_name=profile_name,
                base_dir=base_dir,
                device_passphrase=creds["device_passphrase"],
            ),
            on_success=self._after_authenticated,
        )

    def _after_authenticated(self, result: dict[str, Any]) -> None:
        self._reset_sidebar_selection_and_chat_view(clear_message_draft=True)
        self._apply_snapshot(result["snapshot"])
        self._show_main()
        sync_results = result.get("sync") or []
        if sync_results:
            self._handle_sync_results(sync_results, source="startup", show_empty=False)
        self.status_var.set("Signed in. Your chats, contacts, and live updates are ready.")
        self._schedule_expiry_refresh()

    def handle_refresh_all(self, silent: bool = False) -> None:
        self.handle_sync(silent=silent, reason="Legacy refresh request")

    def _refresh_remote_snapshot(self, *, silent: bool = False, reason: str | None = None) -> None:
        def success(snapshot: dict[str, Any]) -> None:
            self._apply_snapshot(snapshot)
            visible_chat = self._current_visible_chat()
            if visible_chat:
                self._load_conversation_chat(visible_chat, silent=True)
            if not silent:
                self.main_frame.append_activity("Sync refreshed contacts, requests, conversations, and security alerts.")

        def error(message: str) -> None:
            if not silent:
                self._show_error_dialog("Sync", message)
            else:
                self.status_var.set(f"Automatic sync failed: {message}")

        label = "Sync" if not reason else f"Sync ({reason})"
        self._run_task(label, self.controller.refresh_snapshot, on_success=success, on_error=error)

    def _apply_snapshot(self, snapshot: dict[str, Any]) -> None:
        contacts = snapshot.get("contacts", [])
        self.contacts_cache = {row["username"]: row for row in contacts}
        requests_payload = snapshot.get("requests", {})
        self.requests_cache = {
            "incoming": {int(row["request_id"]): row for row in requests_payload.get("incoming", []) if row.get("request_id") is not None},
            "outgoing": {int(row["request_id"]): row for row in requests_payload.get("outgoing", []) if row.get("request_id") is not None},
        }
        events = snapshot.get("events", [])
        self.events_cache = {int(row["id"]): row for row in events if row.get("id") is not None}
        merged_conversations = self._conversation_rows_with_accepted_contacts(snapshot.get("conversations", []))
        self.main_frame.set_identity(snapshot.get("identity", {}))
        self.main_frame.update_contacts(contacts)
        self.main_frame.update_requests(requests_payload)
        self.main_frame.update_conversations(merged_conversations)
        self.main_frame.update_events(events)
        if not self._selection_still_exists(contacts=contacts, conversations=merged_conversations, events=events):
            self._reset_sidebar_selection_and_chat_view()
        section = self._current_sidebar_section()
        if section == "Security Alerts":
            self._refresh_selected_security_event_details()
        elif section == "Requests":
            self._refresh_selected_request_note()
        else:
            self._update_friend_header_from_cache()
        self._apply_right_panel_mode()
        self._schedule_expiry_refresh()

    def _refresh_local_views(
        self,
        *,
        reload_chat_username: str | None,
        reload_contact_history_username: str | None = None,
    ) -> None:
        def success(snapshot: dict[str, Any]) -> None:
            self.main_frame.set_identity(snapshot.get("identity", {}))
            self.main_frame.update_conversations(
                self._conversation_rows_with_accepted_contacts(snapshot.get("conversations", []))
            )
            events = snapshot.get("events", [])
            self.events_cache = {int(row["id"]): row for row in events if row.get("id") is not None}
            self.main_frame.update_events(events)
            if reload_chat_username:
                self._load_conversation_chat(reload_chat_username, silent=True)
            elif reload_contact_history_username:
                self._load_contact_history(reload_contact_history_username, silent=True)
            elif self._current_sidebar_section() == "Security Alerts":
                self._refresh_selected_security_event_details()
            elif self._current_sidebar_section() == "Requests":
                self._refresh_selected_request_note()
            else:
                self._update_friend_header_from_cache()
            self._apply_right_panel_mode()
            self._schedule_expiry_refresh()

        self._run_task("Update local view", self.controller.refresh_local_snapshot, on_success=success)

    def handle_sync(self, silent: bool = False, reason: str | None = None) -> None:
        def error(message: str) -> None:
            if not silent:
                self._show_error_dialog("Sync", message)
            else:
                self.status_var.set(f"Automatic sync failed: {message}")

        label = "Sync" if not reason else f"Sync ({reason})"
        self._run_task(
            label,
            self.controller.sync_and_refresh_snapshot,
            on_success=lambda payload: self._after_sync(payload, source=("manual" if not silent else "auto"), silent=silent),
            on_error=error,
        )

    def _after_sync(self, payload: dict[str, Any], source: str, *, silent: bool) -> None:
        self._apply_snapshot(payload.get("snapshot", {}))
        visible_chat = self._current_visible_chat()
        if visible_chat:
            self._load_conversation_chat(visible_chat, silent=True)
        elif self._current_sidebar_section() == "Security Alerts":
            self._refresh_selected_security_event_details()
        self._handle_sync_results(payload.get("results") or [], source=source, show_empty=not silent)
        if not silent:
            self.main_frame.append_activity("Sync refreshed contacts, requests, conversations, and security alerts.")
        self._schedule_expiry_refresh()

    def _handle_sync_results(self, results: list[dict[str, Any]], *, source: str, show_empty: bool = True) -> None:
        if not results:
            if not show_empty:
                return
            self.main_frame.append_activity(f"{source.title()} sync found no queued messages.")
            return
        for item in results:
            self.main_frame.append_activity(sync_item_text(item, source=source, display_tz=GUI_DISPLAY_TIMEZONE))

    def handle_sidebar_tab_changed(self, _event: object | None = None) -> None:
        self._reset_sidebar_selection_and_chat_view()
        if not self.controller.can_sync():
            return
        tab_name = self._current_sidebar_section() or "section"
        self.handle_sync(silent=True, reason=f"Opened {tab_name}")

    def handle_conversation_selected(self) -> None:
        username = self.main_frame.selected_conversation_username()
        if not username:
            return
        requested_username = username.lower()
        if (
            self.current_contact == requested_username
            and self._current_sidebar_section() == "Conversations"
            and (self.visible_chat_contact == requested_username or self._pending_conversation_load == requested_username)
        ):
            return
        self.current_contact = requested_username
        self.current_fingerprint_info = None
        self._pending_contact_history_load = None
        self._apply_right_panel_mode()
        self._load_conversation_chat(requested_username)

    def handle_contact_selected(self) -> None:
        username = self.main_frame.selected_contact_username()
        if not username:
            return
        requested_username = username.lower()
        if (
            self.current_contact == requested_username
            and self._current_sidebar_section() == "Contacts"
            and (
                self._rendered_contact_history_contact == requested_username
                or self._pending_contact_history_load == requested_username
            )
        ):
            return
        self.current_contact = requested_username
        self.current_fingerprint_info = None
        self._pending_conversation_load = None
        self._rendered_contact_history_contact = None
        self._set_visible_chat_contact(None)
        self._apply_right_panel_mode()
        self._load_contact_history(requested_username)

    def handle_incoming_request_selected(self) -> None:
        self.main_frame.clear_outgoing_request_selection()
        self._refresh_selected_request_note()

    def handle_outgoing_request_selected(self) -> None:
        self.main_frame.clear_incoming_request_selection()
        self._refresh_selected_request_note()

    def handle_security_event_selected(self) -> None:
        event_id = self.main_frame.selected_event_id()
        if event_id is None:
            self.current_contact = None
            self._set_visible_chat_contact(None)
            self.current_fingerprint_info = None
            self._pending_conversation_load = None
            self._pending_contact_history_load = None
            self._rendered_contact_history_contact = None
            self.main_frame.clear_chat_view()
            self._apply_right_panel_mode()
            return
        event = self.events_cache.get(event_id)
        if event is None:
            self.current_contact = None
            self._set_visible_chat_contact(None)
            self.current_fingerprint_info = None
            self._pending_conversation_load = None
            self._pending_contact_history_load = None
            self._rendered_contact_history_contact = None
            self.main_frame.clear_chat_view()
            self._apply_right_panel_mode()
            return
        self.current_contact = str(event.get("contact_username") or "") or None
        self._set_visible_chat_contact(None)
        self.current_fingerprint_info = None
        self._pending_conversation_load = None
        self._pending_contact_history_load = None
        self._rendered_contact_history_contact = None
        self._apply_right_panel_mode()
        self._render_security_event_details(event)
        if self.current_contact:
            self.status_var.set(f"Selected security alert for {self.current_contact}.")

    def _note_for_contact_context(
        self,
        requested_username: str,
        fingerprint: dict[str, Any] | None,
        fingerprint_error: str | None,
    ) -> tuple[str, str | None]:
        contact = self.contacts_cache.get(requested_username)
        safety_line, verified_line, block_line = self._friend_header_lines(contact, fingerprint, fingerprint_error)
        detail_lines = "\n".join(line for line in (verified_line, block_line) if line)
        return safety_line, detail_lines or None

    def _load_conversation_chat(self, username: str, *, silent: bool = False) -> None:
        requested_username = username.lower()
        limit = RECENT_CONVERSATION_CHAT_LIMIT
        requested_section = "Conversations"
        self._pending_conversation_load = requested_username

        def success(context: dict[str, Any]) -> None:
            try:
                if self.current_contact != requested_username or self._current_sidebar_section() != requested_section:
                    return
                fingerprint = context.get("fingerprint")
                fingerprint_error = context.get("fingerprint_error")
                self.current_fingerprint_info = fingerprint
                fingerprint_text, note = self._note_for_contact_context(requested_username, fingerprint, fingerprint_error)
                self.main_frame.update_conversations(
                    self._conversation_rows_with_accepted_contacts(context.get("conversations", []))
                )
                self.main_frame.render_chat(
                    requested_username,
                    self._history_rows_with_initial_note(
                        requested_username,
                        context.get("rows", []),
                        max_rows=limit,
                    ),
                    fingerprint_text,
                    note,
                    show_recent_limit_notice=True,
                )
                self._set_visible_chat_contact(requested_username)
                self._apply_right_panel_mode()
                self.status_var.set(f"Opened conversation with {requested_username}.")
                self._schedule_expiry_refresh()
                if not silent:
                    self.main_frame.append_activity(f"Opened conversation with {requested_username}.")
            finally:
                if self._pending_conversation_load == requested_username:
                    self._pending_conversation_load = None

        def error(message: str) -> None:
            if self._pending_conversation_load == requested_username:
                self._pending_conversation_load = None
            self._set_visible_chat_contact(None)

        self._run_task(
            f"Open {requested_username}",
            lambda: self.controller.load_chat_context(requested_username, limit=limit),
            on_success=success,
            on_error=error,
        )

    def _load_contact_history(self, username: str, *, silent: bool = False) -> None:
        requested_username = username.lower()
        limit = 50
        requested_section = "Contacts"
        self._pending_contact_history_load = requested_username
        self._rendered_contact_history_contact = None
        self._set_visible_chat_contact(None)

        def success(context: dict[str, Any]) -> None:
            try:
                if self.current_contact != requested_username or self._current_sidebar_section() != requested_section:
                    return
                fingerprint = context.get("fingerprint")
                fingerprint_error = context.get("fingerprint_error")
                self.current_fingerprint_info = fingerprint
                fingerprint_text, note = self._note_for_contact_context(requested_username, fingerprint, fingerprint_error)
                self.main_frame.render_chat(
                    requested_username,
                    self._history_rows_with_initial_note(
                        requested_username,
                        context.get("rows", []),
                        max_rows=limit,
                    ),
                    fingerprint_text,
                    note,
                    show_recent_limit_notice=False,
                )
                self._rendered_contact_history_contact = requested_username
                self._apply_right_panel_mode()
                self.status_var.set(f"Viewed chat history with {requested_username}.")
                self._schedule_expiry_refresh()
                if not silent:
                    self.main_frame.append_activity(f"Viewed chat history with {requested_username}.")
            finally:
                if self._pending_contact_history_load == requested_username:
                    self._pending_contact_history_load = None

        def error(message: str) -> None:
            if self._pending_contact_history_load == requested_username:
                self._pending_contact_history_load = None

        self._run_task(
            f"History {requested_username}",
            lambda: self.controller.load_contact_history_context(requested_username, limit=limit),
            on_success=success,
            on_error=error,
        )

    def _update_friend_header_from_cache(self) -> None:
        if self.current_contact is None:
            self._set_visible_chat_contact(None)
            self.main_frame.clear_chat_view()
            return
        contact = self.contacts_cache.get(self.current_contact)
        safety_line, verified_line, block_line = self._friend_header_lines(contact, self.current_fingerprint_info)
        self.main_frame.set_friend_header(self.current_contact, f"{safety_line}\n{verified_line}\n{block_line}")

    def _render_security_event_details(self, event: dict[str, Any]) -> None:
        contact = self.contacts_cache.get(self.current_contact or "") if self.current_contact else None
        safety_line, verified_line, block_line = self._friend_header_lines(contact, self.current_fingerprint_info)
        self._set_visible_chat_contact(None)
        self.main_frame.render_security_event_details(event, note=f"{safety_line}\n{verified_line}\n{block_line}")
        self._apply_right_panel_mode()

    def _refresh_selected_security_event_details(self) -> None:
        if self._current_sidebar_section() != "Security Alerts":
            return
        event_id = self.main_frame.selected_event_id()
        if event_id is None:
            self.current_contact = None
            self._set_visible_chat_contact(None)
            self.current_fingerprint_info = None
            self.main_frame.clear_chat_view()
            self._apply_right_panel_mode()
            return
        event = self.events_cache.get(event_id)
        if event is None:
            self.current_contact = None
            self._set_visible_chat_contact(None)
            self.current_fingerprint_info = None
            self.main_frame.clear_chat_view()
            self._apply_right_panel_mode()
            return
        self.current_contact = str(event.get("contact_username") or "") or None
        self._set_visible_chat_contact(None)
        self.current_fingerprint_info = None
        self._render_security_event_details(event)

    def handle_send_message(self) -> None:
        try:
            username = self._require_selected_contact()
            message_text = self.main_frame.message_body()
            ttl = self.main_frame.ttl_seconds()
            if not message_text:
                raise ValueError("Message text is required.")
        except Exception as exc:
            messagebox.showerror("Send message", self.controller.format_user_error(exc), parent=self)
            return

        self._run_task(
            f"Send to {username}",
            lambda: self.controller.send_text(username, message_text, ttl_seconds=ttl),
            on_success=lambda result, sent_ttl=ttl: self._after_send_message(username, result, sent_ttl),
        )

    def _after_send_message(self, username: str, result: dict[str, Any], ttl_seconds: int | None = None) -> None:
        self.main_frame.clear_message_input()
        self.main_frame.append_activity(
            send_result_text(result, username, ttl_seconds=ttl_seconds, display_tz=GUI_DISPLAY_TIMEZONE)
        )
        self._refresh_local_views(reload_chat_username=self._current_visible_chat() or username.lower())

    def handle_add_friend(self) -> None:
        username = self.main_frame.add_friend_username_var.get().strip()
        note = self.main_frame.add_friend_note_var.get().strip() or None
        if not username:
            messagebox.showerror("Add friend", "Target username is required.", parent=self)
            return
        self._run_task(
            f"Add friend {username}",
            lambda: self.controller.send_friend_request(username, note),
            on_success=lambda result: self._after_friend_request(username, result),
        )

    def _after_friend_request(self, username: str, result: dict[str, Any]) -> None:
        self.main_frame.add_friend_username_var.set("")
        self.main_frame.add_friend_note_var.set("")
        note_text = note_label(result.get('note')) if isinstance(result, dict) else 'No note'
        self.main_frame.append_activity(f"Friend request sent to {username}. Request #{result.get('request_id')}. Note: {note_text}.")
        self.handle_sync(silent=True, reason=f"Friend request sent to {username}")

    def handle_accept_request(self) -> None:
        request_id = self.main_frame.selected_incoming_request_id()
        if request_id is None:
            messagebox.showerror("Accept request", "Select an incoming friend request first.", parent=self)
            return
        self._run_task(
            f"Accept request {request_id}",
            lambda: self.controller.accept_request(request_id),
            on_success=lambda result: self._after_request_change(result, f"Accepted request {request_id}."),
        )

    def handle_decline_request(self) -> None:
        request_id = self.main_frame.selected_incoming_request_id()
        if request_id is None:
            messagebox.showerror("Decline request", "Select an incoming friend request first.", parent=self)
            return
        self._run_task(
            f"Decline request {request_id}",
            lambda: self.controller.decline_request(request_id),
            on_success=lambda result: self._after_request_change(result, f"Declined request {request_id}."),
        )

    def handle_cancel_request(self) -> None:
        request_id = self.main_frame.selected_outgoing_request_id()
        if request_id is None:
            messagebox.showerror("Cancel request", "Select an outgoing friend request first.", parent=self)
            return
        self._run_task(
            f"Cancel request {request_id}",
            lambda: self.controller.cancel_request(request_id),
            on_success=lambda result: self._after_request_change(result, f"Cancelled request {request_id}."),
        )

    def _after_request_change(self, result: dict[str, Any], message: str) -> None:
        self.main_frame.append_activity(message)
        self.handle_sync(silent=True, reason=message)

    def handle_show_fingerprint(self) -> None:
        try:
            username = self._require_selected_contact()
        except Exception as exc:
            messagebox.showerror("Fingerprint", self.controller.format_user_error(exc), parent=self)
            return

        def success(info: dict[str, Any]) -> None:
            self.current_fingerprint_info = info
            details = "\n".join(
                fingerprint_summary_lines(info)
                + [f"Raw fingerprint: {info['fingerprint']}", "", "Compare this safety number out of band before trusting the contact's key."]
            )
            if self._current_sidebar_section() == "Security Alerts":
                self._refresh_selected_security_event_details()
            else:
                self._update_friend_header_from_cache()
                self._apply_right_panel_mode()
            self._show_text_dialog(f"Safety number for {info['username']}", details)
            self.status_var.set(f"Displayed the safety number for {info['username']}.")

        self._run_task(f"Fingerprint {username}", lambda: self.controller.fingerprint_info(username), on_success=success)

    def handle_verify_contact(self) -> None:
        try:
            username = self._require_selected_contact()
        except Exception as exc:
            messagebox.showerror("Verify contact", self.controller.format_user_error(exc), parent=self)
            return
        if not messagebox.askyesno(
            "Verify contact",
            f"Mark the current fingerprint for {username} as verified on this client?\n\nOnly do this after comparing fingerprints out of band.",
            parent=self,
        ):
            return
        self._run_task(
            f"Verify {username}",
            lambda: self.controller.verify_contact(username),
            on_success=lambda result: self._after_verify_contact(result),
        )

    def _after_verify_contact(self, result: dict[str, Any]) -> None:
        self.current_fingerprint_info = result
        self.main_frame.append_activity(
            f"Verified {result['username']} for the current identity. Safety number: {result['display']} ({trust_state_label(result.get('trust_state'))})."
        )
        if self.current_contact == result["username"] and self._has_live_chat_selection():
            self._load_conversation_chat(result["username"], silent=True)
        elif self.current_contact == result["username"] and self._has_contact_history_selection():
            self._load_contact_history(result["username"], silent=True)
        elif self._current_sidebar_section() == "Security Alerts":
            self._refresh_selected_security_event_details()
        self.handle_sync(silent=True, reason=f"Verified {result['username']}")

    def handle_verify_selected_event_contact(self) -> None:
        username = self.main_frame.selected_event_contact()
        if not username:
            messagebox.showerror("Verify selected contact", "Select a security event row first.", parent=self)
            return
        self.current_contact = username
        self._apply_right_panel_mode()
        self.handle_verify_contact()

    def handle_rotate_keys(self) -> None:
        if not messagebox.askyesno(
            "Rotate keys",
            "Generate a new active identity / agreement keypair? Existing contacts will need to verify the new fingerprint.",
            parent=self,
        ):
            return
        self._run_task("Rotate keys", self.controller.rotate_keys, on_success=self._after_rotate_keys)

    def _after_rotate_keys(self, result: dict[str, Any]) -> None:
        self.main_frame.append_activity(result.get("message", "Keys rotated."))
        self._show_info_dialog(
            "Rotate keys",
            result.get("message", "Keys rotated."),
            auto_sync=True,
            sync_reason="Acknowledged the key rotation dialog",
        )

    def handle_block_selected(self) -> None:
        try:
            username = self._require_selected_contact()
        except Exception as exc:
            messagebox.showerror("Block user", self.controller.format_user_error(exc), parent=self)
            return
        if not messagebox.askyesno("Block user", f"Block {username}? This keeps the contact in place but disables messaging until the block is removed.", parent=self):
            return
        self._run_task(
            f"Block {username}",
            lambda: self.controller.block_user(username),
            on_success=lambda result: self._after_contact_action(username, result),
        )

    def handle_unblock_selected(self) -> None:
        try:
            username = self._require_selected_contact()
        except Exception as exc:
            messagebox.showerror("Unblock user", self.controller.format_user_error(exc), parent=self)
            return
        self._run_task(
            f"Unblock {username}",
            lambda: self.controller.unblock_user(username),
            on_success=lambda result: self._after_contact_action(username, result),
        )

    def handle_remove_selected(self) -> None:
        try:
            username = self._require_selected_contact()
        except Exception as exc:
            messagebox.showerror("Remove friend", self.controller.format_user_error(exc), parent=self)
            return
        if not messagebox.askyesno("Remove friend", f"Remove {username} from your contacts?", parent=self):
            return
        self._run_task(
            f"Remove {username}",
            lambda: self.controller.remove_friend(username),
            on_success=lambda result: self._after_remove_contact(username, result),
        )

    def _after_contact_action(self, username: str, result: dict[str, Any]) -> None:
        self.main_frame.append_activity(result.get("message", f"Updated contact {username}."))
        self.handle_sync(silent=True, reason=f"Updated contact {username}")

    def _after_remove_contact(self, username: str, result: dict[str, Any]) -> None:
        if self.current_contact == username.lower():
            self._reset_sidebar_selection_and_chat_view()
        self.main_frame.append_activity(result.get("message", f"Removed {username} from your contacts."))
        self.handle_sync(silent=True, reason=f"Updated contact {username}")

    def _start_logout(self) -> None:
        self._run_task("Logout", self.controller.logout, on_success=self._after_logout)

    def _ask_exit_choice(self) -> str:
        dialog = tk.Toplevel(self)
        dialog.title("Exit")
        dialog.transient(self)
        dialog.grab_set()
        dialog.resizable(False, False)
        dialog.columnconfigure(0, weight=1)

        ttk.Label(
            dialog,
            text=(
                "Choose what to do next.\n\n"
                "Logout ends the current session.\n"
                "EOF returns to the main screen without ending the session."
            ),
            justify="left",
            wraplength=360,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(16, 12))

        choice_var = tk.StringVar(value="Cancel")

        def set_choice(value: str) -> None:
            choice_var.set(value)
            try:
                dialog.grab_release()
            except Exception:
                pass
            dialog.destroy()

        button_bar = ttk.Frame(dialog)
        button_bar.grid(row=1, column=0, sticky="e", padx=16, pady=(0, 16))
        ttk.Button(button_bar, text="Logout", command=lambda: set_choice("Logout")).pack(side="left", padx=(0, 8))
        ttk.Button(button_bar, text="EOF", command=lambda: set_choice("EOF")).pack(side="left", padx=(0, 8))
        ttk.Button(button_bar, text="Cancel", command=lambda: set_choice("Cancel")).pack(side="left")
        dialog.protocol("WM_DELETE_WINDOW", lambda: set_choice("Cancel"))
        self.wait_window(dialog)
        return str(choice_var.get() or "Cancel")

    def _return_to_main_screen_without_logout(self) -> None:
        self._cancel_expiry_refresh()
        try:
            self.controller.close()
        except Exception:
            pass
        self.contacts_cache.clear()
        self.requests_cache = {"incoming": {}, "outgoing": {}}
        self.events_cache.clear()
        self._reset_sidebar_selection_and_chat_view(clear_message_draft=True)
        self.auth_frame.switch_to_reopen_tab()
        self._show_auth()
        self.status_var.set("Session preserved. Use Reopen Session to continue.")

    def handle_exit(self) -> None:
        choice = self._ask_exit_choice()
        if choice == "Logout":
            self._start_logout()
        elif choice == "EOF":
            self._return_to_main_screen_without_logout()

    def handle_logout(self) -> None:
        if not messagebox.askyesno("Logout", "Log out and revoke the current session?", parent=self):
            return
        self._start_logout()

    def _after_logout(self, result: dict[str, Any]) -> None:
        self._reset_sidebar_selection_and_chat_view(clear_message_draft=True)
        self.contacts_cache.clear()
        self.events_cache.clear()
        self._show_auth()
        self.main_frame.append_activity(result.get("message", "Logged out."))
        self._show_info_dialog("Logout", result.get("message", "Logged out."))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=GUI_PARSER_DESCRIPTION)
    parser.add_argument("--profile", default=None, help="Optional profile name to prefill in the GUI")
    parser.add_argument("--base-dir", default=None, help="Optional base directory to prefill in the GUI")
    return parser



def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    app = CipherLinkDesktopApp(initial_profile=args.profile, initial_base_dir=args.base_dir)
    app.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
