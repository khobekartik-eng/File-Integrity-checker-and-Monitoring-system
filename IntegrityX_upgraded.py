import hashlib
import csv
import hmac
import json
import os
import secrets
import sqlite3
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path as FilePath
from tkinter import filedialog, messagebox, ttk

APP_TITLE = "IntegrityX | File Integrity & Forensics"
DB_PATH = "integrityx.db"
CHUNK_SIZE = 1024 * 1024

# ---------- Theme ----------
BG = "#0b1220"
SIDEBAR = "#101a2d"
PANEL = "#121e32"
PANEL_ALT = "#17253b"
BORDER = "#263650"
TEXT = "#edf4ff"
MUTED = "#91a4bf"
TEAL = "#22d3c5"
GREEN = "#34d399"
RED = "#fb7185"
AMBER = "#fbbf24"
BLUE = "#60a5fa"


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def hash_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        before = os.fstat(stream.fileno())
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    return {
        "path": str(FilePath(path).resolve()),
        "name": FilePath(path).name,
        "size": after.st_size,
        "modified_utc": datetime.fromtimestamp(after.st_mtime, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "hash": digest.hexdigest(),
        "stable": (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns),
    }


def check_basic_file_health(path):
    """Conservative, format-aware checks using only Python's standard library."""
    import gzip
    import zipfile

    ext = FilePath(path).suffix.lower()
    try:
        with open(path, "rb") as f:
            head = f.read(16)
            f.seek(0, os.SEEK_END)
            size = f.tell()
            tail_size = min(size, 8192)
            f.seek(-tail_size, os.SEEK_END) if tail_size else None
            tail = f.read(tail_size) if tail_size else b""

        if size == 0:
            return "EMPTY FILE", "File is zero bytes; this may be intentional."
        if ext in (".jpg", ".jpeg"):
            if not head.startswith(b"\xff\xd8") or not tail.rstrip().endswith(b"\xff\xd9"):
                return "POTENTIAL CORRUPTION", "JPEG start/end markers are missing."
            return "BASIC CHECK PASSED", "JPEG start/end markers found."
        if ext == ".png":
            if not head.startswith(b"\x89PNG\r\n\x1a\n") or b"IEND" not in tail:
                return "POTENTIAL CORRUPTION", "PNG signature or IEND marker is missing."
            return "BASIC CHECK PASSED", "PNG signature and IEND marker found."
        if ext == ".gif":
            if not (head.startswith(b"GIF87a") or head.startswith(b"GIF89a")) or not tail.endswith(b";"):
                return "POTENTIAL CORRUPTION", "GIF signature or trailer is missing."
            return "BASIC CHECK PASSED", "GIF signature and trailer found."
        if ext == ".pdf":
            if not head.startswith(b"%PDF-") or b"%%EOF" not in tail:
                return "POTENTIAL CORRUPTION", "PDF header or EOF marker is missing."
            return "BASIC CHECK PASSED", "PDF header and EOF marker found."
        if ext in (".zip", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".jar", ".apk"):
            if not zipfile.is_zipfile(path):
                return "POTENTIAL CORRUPTION", "File does not appear to be a valid ZIP-based container."
            with zipfile.ZipFile(path) as archive:
                bad_member = archive.testzip()
            if bad_member:
                return "POTENTIAL CORRUPTION", f"ZIP member failed CRC check: {bad_member}"
            return "BASIC CHECK PASSED", "ZIP container and member CRC checks passed."
        if ext in (".gz", ".tgz"):
            with gzip.open(path, "rb") as stream:
                while stream.read(1024 * 1024):
                    pass
            return "BASIC CHECK PASSED", "GZIP stream decompressed successfully."
        if ext == ".bmp":
            if not head.startswith(b"BM") or size < 26:
                return "POTENTIAL CORRUPTION", "BMP signature or minimum header is invalid."
            return "BASIC CHECK PASSED", "BMP signature and minimum header found."
        if ext in (".wav",):
            if len(head) < 12 or head[:4] != b"RIFF" or head[8:12] != b"WAVE":
                return "POTENTIAL CORRUPTION", "WAV RIFF/WAVE header is missing."
            return "BASIC CHECK PASSED", "WAV RIFF/WAVE header found."
        return "NOT FORMAT-VALIDATED", "Generic readability and SHA-256 checks passed; no format-specific validator for this extension."
    except (OSError, EOFError, gzip.BadGzipFile, zipfile.BadZipFile, RuntimeError) as exc:
        return "POTENTIAL CORRUPTION", f"Validation error: {exc}"
    except Exception as exc:
        return "CHECK ERROR", f"{type(exc).__name__}: {exc}"


class IntegrityXApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1250x820")
        self.minsize(1050, 700)
        self.configure(bg=BG)

        self.selected_file = tk.StringVar()
        self.verify_file = tk.StringVar()
        self.case_id = tk.StringVar()
        self.examiner = tk.StringVar()
        self.evidence_id = tk.StringVar()
        self.baseline_id = tk.StringVar()
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.page_title = tk.StringVar(value="Dashboard")
        self.nav_buttons = {}
        self.pages = {}
        self.baseline_hash = None
        self.baseline_meta = None
        self.last_result = None
        self.current_user = None
        self.login_frame = None

        self._init_db()
        self._style()
        self._build_login_screen()

    # ---------- Authentication ----------
    def _build_login_screen(self):
        for child in self.winfo_children():
            child.destroy()
        self.configure(bg=BG)
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True)

        left = tk.Frame(outer, bg=SIDEBAR, width=400)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        tk.Label(left, text="◆  IntegrityX", bg=SIDEBAR, fg=TEAL,
                 font=("Segoe UI", 25, "bold")).pack(anchor="w", padx=34, pady=(65, 12))
        tk.Label(left, text="FILE INTEGRITY & DIGITAL FORENSICS", bg=SIDEBAR,
                 fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=36)
        tk.Label(left, text="Trust every check.\nRecord every action.", bg=SIDEBAR,
                 fg=TEXT, justify="left", font=("Segoe UI", 23, "bold")).pack(anchor="w", padx=34, pady=(60, 14))
        tk.Label(left, text="Authenticated testers\nSHA-256 verification\nSQLite-backed audit trail",
                 bg=SIDEBAR, fg=MUTED, justify="left", font=("Segoe UI", 11)).pack(anchor="w", padx=36)
        tk.Label(left, text="LOCAL WORKSPACE  |  VERSION 1.0", bg=SIDEBAR, fg=TEAL,
                 font=("Segoe UI", 8, "bold")).pack(side="bottom", anchor="w", padx=36, pady=28)

        right = tk.Frame(outer, bg=BG, padx=35, pady=30)
        right.pack(side="left", fill="both", expand=True)
        card = tk.Frame(right, bg=PANEL, padx=32, pady=30,
                        highlightbackground=BORDER, highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor="center", width=430, height=490)
        tk.Label(card, text="Welcome back", bg=PANEL, fg=TEXT,
                 font=("Segoe UI", 23, "bold")).pack(anchor="w")
        tk.Label(card, text="Sign in to access your forensic workspace.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(7, 24))

        self.login_username = tk.StringVar()
        self.login_password = tk.StringVar()
        tk.Label(card, text="USERNAME", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        user_entry = ttk.Entry(card, textvariable=self.login_username)
        user_entry.pack(fill="x", pady=(6, 16), ipady=4)
        tk.Label(card, text="PASSWORD", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        pass_entry = ttk.Entry(card, textvariable=self.login_password, show="●")
        pass_entry.pack(fill="x", pady=(6, 8), ipady=4)
        pass_entry.bind("<Return>", lambda _event: self._login())
        self.login_message = tk.Label(card, text="", bg=PANEL, fg=RED,
                                      font=("Segoe UI", 9), wraplength=350, justify="left")
        self.login_message.pack(anchor="w", pady=(3, 8))
        tk.Button(card, text="Sign in", command=self._login, bg=TEAL, fg="#062027",
                  activebackground="#17b8ac", relief="flat", bd=0, pady=11,
                  font=("Segoe UI", 10, "bold"), cursor="hand2").pack(fill="x", pady=(3, 10))
        tk.Button(card, text="Create tester account", command=self._build_register_screen,
                  bg=PANEL_ALT, fg=TEXT, activebackground="#243954", relief="flat",
                  bd=0, pady=10, font=("Segoe UI", 9, "bold"),
                  cursor="hand2").pack(fill="x")
        tk.Label(card, text="Passwords are stored as salted PBKDF2 hashes, not plain text.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 8), wraplength=350,
                 justify="left").pack(anchor="w", pady=(15, 0))
        user_entry.focus_set()

    def _build_register_screen(self):
        for child in self.winfo_children():
            child.destroy()
        outer = tk.Frame(self, bg=BG)
        outer.pack(fill="both", expand=True)
        card = tk.Frame(outer, bg=PANEL, padx=36, pady=28,
                        highlightbackground=BORDER, highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor="center", width=490, height=590)
        tk.Label(card, text="Create tester account", bg=PANEL, fg=TEXT,
                 font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(card, text="Your account identity will be linked to baselines and verification records.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9), wraplength=410,
                 justify="left").pack(anchor="w", pady=(7, 15))

        self.reg_full_name = tk.StringVar()
        self.reg_username = tk.StringVar()
        self.reg_password = tk.StringVar()
        self.reg_confirm = tk.StringVar()
        fields = [
            ("FULL NAME", self.reg_full_name, ""),
            ("USERNAME (3+ CHARACTERS, NO SPACES)", self.reg_username, ""),
            ("PASSWORD (MINIMUM 10 CHARACTERS)", self.reg_password, "●"),
            ("CONFIRM PASSWORD", self.reg_confirm, "●"),
        ]
        for label, variable, mask in fields:
            tk.Label(card, text=label, bg=PANEL, fg=MUTED,
                     font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(8, 0))
            ttk.Entry(card, textvariable=variable, show=mask).pack(fill="x", pady=(5, 2), ipady=3)
        self.register_message = tk.Label(card, text="", bg=PANEL, fg=RED,
                                         font=("Segoe UI", 9), wraplength=410, justify="left")
        self.register_message.pack(anchor="w", pady=(6, 2))
        tk.Button(card, text="Create account", command=self._create_tester_account, bg=TEAL, fg="#062027",
                  activebackground="#17b8ac", relief="flat", bd=0, pady=10,
                  font=("Segoe UI", 10, "bold"), cursor="hand2").pack(fill="x", pady=(5, 8))
        tk.Button(card, text="Back to sign in", command=self._build_login_screen,
                  bg=PANEL_ALT, fg=TEXT, activebackground="#243954", relief="flat",
                  bd=0, pady=9, font=("Segoe UI", 9, "bold"),
                  cursor="hand2").pack(fill="x")

    def _password_record(self, password, salt_hex=None):
        salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
        return salt.hex(), digest.hex()

    def _create_tester_account(self):
        full_name = self.reg_full_name.get().strip()
        username = self.reg_username.get().strip()
        password = self.reg_password.get()
        confirm = self.reg_confirm.get()
        if not full_name or not username or not password:
            self.register_message.configure(text="Please fill in all fields.")
            return
        if len(username) < 3 or any(ch.isspace() for ch in username):
            self.register_message.configure(text="Username must be at least 3 characters and contain no spaces.")
            return
        if len(password) < 10:
            self.register_message.configure(text="Use a password with at least 10 characters.")
            return
        if password != confirm:
            self.register_message.configure(text="Passwords do not match.")
            return
        salt, digest = self._password_record(password)
        try:
            with self._connect() as con:
                con.execute("""INSERT INTO users
                    (username,full_name,password_salt,password_hash,role,created_at,is_active)
                    VALUES (?,?,?,?,?,?,1)""",
                    (username, full_name, salt, digest, "Tester", utc_now()))
            messagebox.showinfo("Account created", "Tester account created. Sign in with your username and password.")
            self._build_login_screen()
            self.login_username.set(username)
        except sqlite3.IntegrityError:
            self.register_message.configure(text="That username already exists. Choose another one.")

    def _login(self):
        username = self.login_username.get().strip()
        password = self.login_password.get()
        if not username or not password:
            self.login_message.configure(text="Enter both username and password.")
            return
        with self._connect() as con:
            user = con.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE AND is_active=1",
                               (username,)).fetchone()
            event, user_id, valid = "LOGIN_FAILED", None, False
            if user:
                _salt, actual = self._password_record(password, user["password_salt"])
                valid = hmac.compare_digest(actual, user["password_hash"])
                if valid:
                    event, user_id = "LOGIN_SUCCESS", user["id"]
            con.execute("""INSERT INTO audit_logins
                (user_id,username_attempted,event,event_at) VALUES (?,?,?,?)""",
                (user_id, username, event, utc_now()))
        if not valid:
            self.login_message.configure(text="Invalid username or password.")
            return
        self.current_user = {"id": user["id"], "username": user["username"],
                             "full_name": user["full_name"], "role": user["role"]}
        self._build_shell()
        self.show_page("Dashboard")
        self.refresh_dashboard()

    def _logout(self):
        if self.current_user:
            with self._connect() as con:
                con.execute("""INSERT INTO audit_logins
                    (user_id,username_attempted,event,event_at) VALUES (?,?,?,?)""",
                    (self.current_user["id"], self.current_user["username"], "LOGOUT", utc_now()))
        self.current_user = None
        self.baseline_hash = None
        self.baseline_meta = None
        self.last_result = None
        self._build_login_screen()

    # ---------- Database ----------
    def _connect(self):
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self):
        with self._connect() as con:
            con.execute("""
                CREATE TABLE IF NOT EXISTS baselines (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id TEXT, examiner TEXT, evidence_id TEXT,
                    file_path TEXT NOT NULL, file_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL, sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL, modified_at TEXT,
                    stable INTEGER NOT NULL DEFAULT 1
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS checks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    baseline_id INTEGER, file_path TEXT NOT NULL,
                    file_name TEXT NOT NULL, file_size INTEGER NOT NULL,
                    current_sha256 TEXT NOT NULL, result TEXT NOT NULL,
                    checked_at TEXT NOT NULL, detail TEXT,
                    FOREIGN KEY(baseline_id) REFERENCES baselines(id)
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    full_name TEXT NOT NULL,
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'Tester',
                    created_at TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS audit_logins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    username_attempted TEXT NOT NULL,
                    event TEXT NOT NULL,
                    event_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS scan_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    root_path TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT NOT NULL,
                    scanned_count INTEGER NOT NULL DEFAULT 0,
                    duplicate_groups INTEGER NOT NULL DEFAULT 0,
                    duplicate_extra_bytes INTEGER NOT NULL DEFAULT 0,
                    issue_count INTEGER NOT NULL DEFAULT 0,
                    error_count INTEGER NOT NULL DEFAULT 0,
                    scanned_by INTEGER,
                    FOREIGN KEY(scanned_by) REFERENCES users(id)
                )
            """)
            con.execute("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL,
                    file_path TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    sha256 TEXT,
                    duplicate_group TEXT,
                    health_status TEXT NOT NULL,
                    health_detail TEXT,
                    read_error TEXT,
                    FOREIGN KEY(run_id) REFERENCES scan_runs(id)
                )
            """)
            # Link each baseline and verification record to the authenticated user.
            baseline_columns = {row["name"] for row in con.execute("PRAGMA table_info(baselines)")}
            if "created_by" not in baseline_columns:
                con.execute("ALTER TABLE baselines ADD COLUMN created_by INTEGER")
            check_columns = {row["name"] for row in con.execute("PRAGMA table_info(checks)")}
            if "tested_by" not in check_columns:
                con.execute("ALTER TABLE checks ADD COLUMN tested_by INTEGER")

    # ---------- Styling / layout ----------
    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TEntry", padding=8, fieldbackground="#0d1728",
                        foreground=TEXT, insertcolor=TEXT, bordercolor=BORDER)
        style.configure("TCombobox", padding=7, fieldbackground="#0d1728",
                        foreground=TEXT)
        style.configure("Treeview", background="#0d1728", foreground=TEXT,
                        fieldbackground="#0d1728", rowheight=30,
                        bordercolor=BORDER, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", background=PANEL_ALT,
                        foreground=TEXT, font=("Segoe UI", 9, "bold"), padding=8)
        style.map("Treeview", background=[("selected", "#174e63")])
        style.configure("Vertical.TScrollbar", background=PANEL_ALT, troughcolor=BG)

    def _build_shell(self):
        shell = tk.Frame(self, bg=BG)
        shell.pack(fill="both", expand=True)

        self.sidebar = tk.Frame(shell, bg=SIDEBAR, width=235)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        brand = tk.Frame(self.sidebar, bg=SIDEBAR, padx=20, pady=24)
        brand.pack(fill="x")
        tk.Label(brand, text="◆  IntegrityX", bg=SIDEBAR, fg=TEAL,
                 font=("Segoe UI", 19, "bold")).pack(anchor="w")
        tk.Label(brand, text="FILE FORENSICS PLATFORM", bg=SIDEBAR, fg=MUTED,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w", pady=(5, 0))

        tk.Frame(self.sidebar, bg=BORDER, height=1).pack(fill="x", padx=16, pady=(0, 14))
        nav_items = [
            ("Dashboard", "▦"),
            ("Evidence & Cases", "◈"),
            ("Create Baseline", "＋"),
            ("Verify Integrity", "✓"),
            ("Scan Files", "⌕"),
            ("Reports & Logs", "≡"),
            ("About & Settings", "⚙"),
        ]
        for name, symbol in nav_items:
            btn = tk.Button(
                self.sidebar, text=f"  {symbol}    {name}", anchor="w",
                command=lambda n=name: self.show_page(n),
                bg=SIDEBAR, fg=MUTED, activebackground="#1b2d47",
                activeforeground=TEXT, relief="flat", bd=0,
                font=("Segoe UI", 10, "bold"), padx=16, pady=13, cursor="hand2"
            )
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[name] = btn

        bottom = tk.Frame(self.sidebar, bg=SIDEBAR, padx=18, pady=18)
        bottom.pack(side="bottom", fill="x")
        tk.Label(bottom, text="LOCAL WORKSPACE", bg=SIDEBAR, fg=MUTED,
                 font=("Segoe UI", 8, "bold")).pack(anchor="w")
        tk.Label(bottom, text="SQLite • SHA-256", bg=SIDEBAR, fg=TEAL,
                 font=("Segoe UI", 9)).pack(anchor="w", pady=(5, 0))

        self.main = tk.Frame(shell, bg=BG)
        self.main.pack(side="left", fill="both", expand=True)
        topbar = tk.Frame(self.main, bg=BG, padx=28, pady=20)
        topbar.pack(fill="x")
        title_box = tk.Frame(topbar, bg=BG)
        title_box.pack(side="left", fill="x", expand=True)
        tk.Label(title_box, textvariable=self.page_title, bg=BG, fg=TEXT,
                 font=("Segoe UI", 22, "bold")).pack(anchor="w")
        tk.Label(title_box, text="File integrity monitoring and digital evidence workspace",
                 bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w", pady=(4, 0))
        self.status_badge = tk.Label(topbar, text="● SYSTEM READY", bg="#12342f",
                                     fg=GREEN, font=("Segoe UI", 9, "bold"),
                                     padx=13, pady=9)
        self.status_badge.pack(side="right")
        if self.current_user:
            user_box = tk.Frame(topbar, bg=BG)
            user_box.pack(side="right", padx=(0, 18))
            tk.Label(user_box, text=f"{self.current_user['full_name']}  •  {self.current_user['role']}",
                     bg=BG, fg=TEXT, font=("Segoe UI", 9, "bold")).pack(anchor="e")
            tk.Button(user_box, text="Log out", command=self._logout, bg=PANEL_ALT, fg=TEXT,
                      activebackground="#243954", relief="flat", bd=0, padx=10, pady=5,
                      font=("Segoe UI", 8, "bold"), cursor="hand2").pack(anchor="e", pady=(5, 0))

        self.page_host = tk.Frame(self.main, bg=BG, padx=28, pady=0)
        self.page_host.pack(fill="both", expand=True)
        footer = tk.Frame(self.main, bg=BG, padx=28, pady=12)
        footer.pack(fill="x", side="bottom")
        tk.Frame(footer, bg=BORDER, height=1).pack(fill="x", pady=(0, 9))
        tk.Label(footer, text="IntegrityX • Local processing only • Verify your baseline source independently",
                 bg=BG, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w")

    def show_page(self, name):
        for child in self.page_host.winfo_children():
            child.destroy()
        self.page_title.set(name)
        for key, btn in self.nav_buttons.items():
            active = key == name
            btn.configure(bg="#17334b" if active else SIDEBAR,
                          fg=TEAL if active else MUTED)
        builders = {
            "Dashboard": self._page_dashboard,
            "Evidence & Cases": self._page_cases,
            "Create Baseline": self._page_baseline,
            "Verify Integrity": self._page_verify,
            "Scan Files": self._page_scan_files,
            "Reports & Logs": self._page_reports,
            "About & Settings": self._page_about,
        }
        builders[name]()

    # ---------- UI helpers ----------
    def _label(self, parent, text, color=MUTED, size=9, bold=False, **kwargs):
        return tk.Label(parent, text=text, bg=kwargs.pop("bg", PANEL),
                        fg=color, font=("Segoe UI", size, "bold" if bold else "normal"),
                        **kwargs)

    def _panel(self, parent, padx=18, pady=16):
        return tk.Frame(parent, bg=PANEL, padx=padx, pady=pady,
                        highlightbackground=BORDER, highlightthickness=1)

    def _button(self, parent, text, command, primary=False, color=None):
        bg = color or (TEAL if primary else PANEL_ALT)
        fg = "#062027" if primary else TEXT
        return tk.Button(parent, text=text, command=command, bg=bg, fg=fg,
                         activebackground=TEAL if primary else "#243954",
                         activeforeground="#062027" if primary else TEXT,
                         relief="flat", bd=0, padx=14, pady=10,
                         font=("Segoe UI", 9, "bold"), cursor="hand2")

    def _entry_field(self, parent, label, variable, row, column=0, width=30):
        frame = tk.Frame(parent, bg=PANEL)
        frame.grid(row=row, column=column, sticky="ew", padx=(0, 12), pady=8)
        self._label(frame, label.upper(), size=8, bold=True).pack(anchor="w", pady=(0, 6))
        entry = ttk.Entry(frame, textvariable=variable, width=width)
        entry.pack(fill="x")
        return entry

    def _section_heading(self, parent, title, subtitle=""):
        self._label(parent, title, color=TEXT, size=13, bold=True).pack(anchor="w")
        if subtitle:
            self._label(parent, subtitle, size=9).pack(anchor="w", pady=(4, 12))

    def _tree(self, parent, columns, headings, height=8):
        wrap = tk.Frame(parent, bg=PANEL)
        wrap.pack(fill="both", expand=True, pady=(10, 0))
        tree = ttk.Treeview(wrap, columns=columns, show="headings", height=height)
        for col, heading in zip(columns, headings):
            tree.heading(col, text=heading)
            tree.column(col, width=140, anchor="w")
        yscroll = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=yscroll.set)
        tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        return tree

    # ---------- Dashboard ----------
    def _page_dashboard(self):
        self._section_heading(self.page_host, "Workspace overview",
                              "Monitor baselines and recent file integrity verification activity.")
        stats = tk.Frame(self.page_host, bg=BG)
        stats.pack(fill="x", pady=(2, 18))
        with self._connect() as con:
            baseline_count = con.execute("SELECT COUNT(*) FROM baselines").fetchone()[0]
            check_count = con.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
            match_count = con.execute("SELECT COUNT(*) FROM checks WHERE result='MATCH'").fetchone()[0]
            mismatch_count = con.execute("SELECT COUNT(*) FROM checks WHERE result='MISMATCH'").fetchone()[0]
        cards = [
            ("BASELINES", baseline_count, TEAL, "Saved trusted references"),
            ("FILES CHECKED", check_count, BLUE, "Verification attempts"),
            ("MATCHED", match_count, GREEN, "Same SHA-256 hash"),
            ("MISMATCHED", mismatch_count, RED, "Different file contents"),
        ]
        for title, value, accent, subtitle in cards:
            card = self._panel(stats, padx=16, pady=15)
            card.pack(side="left", fill="both", expand=True, padx=(0, 10))
            self._label(card, title, size=8, bold=True).pack(anchor="w")
            self._label(card, str(value), color=accent, size=25, bold=True).pack(anchor="w", pady=(7, 3))
            self._label(card, subtitle, size=8).pack(anchor="w")
        quick = self._panel(self.page_host)
        quick.pack(fill="x", pady=(0, 16))
        self._section_heading(quick, "Quick actions", "Choose a task to get started.")
        actions = tk.Frame(quick, bg=PANEL)
        actions.pack(fill="x")
        self._button(actions, "＋  Create new baseline", lambda: self.show_page("Create Baseline"), True).pack(side="left", padx=(0, 8))
        self._button(actions, "✓  Verify a file", lambda: self.show_page("Verify Integrity")).pack(side="left", padx=8)
        self._button(actions, "≡  View reports", lambda: self.show_page("Reports & Logs")).pack(side="left", padx=8)
        recent = self._panel(self.page_host)
        recent.pack(fill="both", expand=True)
        self._section_heading(recent, "Recent verification activity")
        tree = self._tree(recent, ("time", "tester", "file", "result", "hash"), ("CHECKED AT (UTC)", "TESTER", "FILE", "RESULT", "CURRENT SHA-256"), 6)
        with self._connect() as con:
            rows = con.execute("""SELECT c.checked_at,c.file_name,c.result,c.current_sha256,u.username
                FROM checks c LEFT JOIN users u ON u.id=c.tested_by ORDER BY c.id DESC LIMIT 8""").fetchall()
        for row in rows:
            tree.insert("", "end", values=(row["checked_at"], row["username"] or "Unknown",
                row["file_name"], row["result"], row["current_sha256"][:18] + "…"))

    # ---------- Evidence and cases ----------
    def _page_cases(self):
        self._section_heading(self.page_host, "Evidence & case records",
                              "Case metadata is stored with every baseline created in this workspace.")
        form = self._panel(self.page_host)
        form.pack(fill="x", pady=(0, 16))
        self._entry_field(form, "Case / reference ID", self.case_id, 0, 0)
        self._entry_field(form, "Examiner / analyst", self.examiner, 0, 1)
        self._entry_field(form, "Evidence item ID", self.evidence_id, 0, 2)
        self._label(form, "Enter or update these fields here, then create a baseline to save the metadata.",
                    size=9).grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        records = self._panel(self.page_host)
        records.pack(fill="both", expand=True)
        self._section_heading(records, "Saved baseline records")
        tree = self._tree(records, ("id", "case", "evidence", "file", "size", "created"), 
                          ("ID", "CASE ID", "EVIDENCE ID", "FILE", "SIZE (BYTES)", "CREATED (UTC)"), 11)
        with self._connect() as con:
            rows = con.execute("SELECT id,case_id,evidence_id,file_name,file_size,created_at FROM baselines ORDER BY id DESC").fetchall()
        for r in rows:
            tree.insert("", "end", values=(r["id"], r["case_id"] or "—", r["evidence_id"] or "—",
                                          r["file_name"], f'{r["file_size"]:,}', r["created_at"]))

    # ---------- Baseline creation ----------
    def _page_baseline(self):
        self._section_heading(self.page_host, "Create trusted baseline",
                              "Hash a known-good file and save its SHA-256 reference in the local SQLite database.")
        card = self._panel(self.page_host)
        card.pack(fill="x", pady=(0, 15))
        self._section_heading(card, "01 / Select original evidence")
        row = tk.Frame(card, bg=PANEL)
        row.pack(fill="x", pady=(0, 12))
        ttk.Entry(row, textvariable=self.selected_file).pack(side="left", fill="x", expand=True, padx=(0, 10))
        self._button(row, "Browse files", self._browse_baseline).pack(side="right")
        fields = tk.Frame(card, bg=PANEL)
        fields.pack(fill="x")
        for i in range(3):
            fields.columnconfigure(i, weight=1)
        self._entry_field(fields, "Case / reference ID", self.case_id, 0, 0)
        self._entry_field(fields, "Examiner / analyst", self.examiner, 0, 1)
        self._entry_field(fields, "Evidence item ID", self.evidence_id, 0, 2)
        self._button(card, "Calculate SHA-256 & save baseline", self._create_baseline, True).pack(anchor="w", pady=(15, 0))
        result = self._panel(self.page_host)
        result.pack(fill="both", expand=True)
        self._section_heading(result, "Baseline result")
        self.baseline_result = tk.Text(result, height=8, bg="#0d1728", fg=TEXT,
                                       insertbackground=TEXT, relief="flat", wrap="word",
                                       padx=12, pady=12, font=("Consolas", 9))
        self.baseline_result.pack(fill="both", expand=True)
        self.baseline_result.insert("1.0", "No baseline created in this session yet.")
        self.baseline_result.configure(state="disabled")

    def _browse_baseline(self):
        path = filedialog.askopenfilename(title="Choose trusted original file")
        if path:
            self.selected_file.set(path)

    def _create_baseline(self):
        path = self.selected_file.get().strip()
        if not path or not FilePath(path).is_file():
            messagebox.showwarning("Select a file", "Choose an existing, accessible file first.")
            return
        self.status_var.set("Calculating SHA-256…")
        self.status_badge.configure(text="● HASHING FILE", fg=AMBER, bg="#3b2c13")
        def work():
            try:
                meta = hash_file(path)
                with self._connect() as con:
                    cur = con.execute("""INSERT INTO baselines
                        (case_id,examiner,evidence_id,file_path,file_name,file_size,sha256,created_at,modified_at,stable,created_by)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                        (self.case_id.get().strip(), self.examiner.get().strip(),
                         self.evidence_id.get().strip(), meta["path"], meta["name"],
                         meta["size"], meta["hash"], utc_now(), meta["modified_utc"], int(meta["stable"]),
                         self.current_user["id"]))
                    baseline_id = cur.lastrowid
                self.after(0, lambda: self._baseline_done(meta, baseline_id))
            except Exception as exc:
                self.after(0, lambda e=str(exc): self._operation_error("Baseline error", e))
        threading.Thread(target=work, daemon=True).start()

    def _baseline_done(self, meta, baseline_id):
        self.baseline_hash = meta["hash"]
        self.baseline_meta = meta
        self.baseline_id.set(str(baseline_id))
        self.status_var.set("Baseline saved to SQLite")
        self.status_badge.configure(text="● SYSTEM READY", fg=GREEN, bg="#12342f")
        stable_note = "" if meta["stable"] else "\nWARNING: File metadata changed during hashing; consider creating a fresh baseline."
        text = (f"BASELINE ID: {baseline_id}\nFILE: {meta['name']}\nPATH: {meta['path']}\n"
                f"SIZE: {meta['size']:,} bytes\nMODIFIED (UTC): {meta['modified_utc']}\n"
                f"CREATED (UTC): {utc_now()}\nSHA-256:\n{meta['hash']}{stable_note}")
        self._set_text(self.baseline_result, text)
        messagebox.showinfo("Baseline saved", f"SHA-256 baseline saved successfully.\nBaseline ID: {baseline_id}")
        self.refresh_dashboard()

    # ---------- Verify ----------
    def _page_verify(self):
        self._section_heading(self.page_host, "Verify file integrity",
                              "Select a saved baseline and a current file. The SHA-256 hashes are compared by the Python backend.")
        select = self._panel(self.page_host)
        select.pack(fill="x", pady=(0, 14))
        self._section_heading(select, "02 / Choose reference and current file")
        self._label(select, "SAVED BASELINE", size=8, bold=True).pack(anchor="w", pady=(4, 6))
        with self._connect() as con:
            rows = con.execute("SELECT id,case_id,file_name,sha256 FROM baselines ORDER BY id DESC").fetchall()
        options = [f'{r["id"]} | {r["case_id"] or "No case"} | {r["file_name"]} | {r["sha256"][:12]}…' for r in rows]
        self.baseline_lookup = {options[i]: dict(rows[i]) for i in range(len(rows))}
        self.baseline_choice = tk.StringVar(value=options[0] if options else "")
        combo = ttk.Combobox(select, textvariable=self.baseline_choice, values=options, state="readonly")
        combo.pack(fill="x", pady=(0, 12))
        row = tk.Frame(select, bg=PANEL)
        row.pack(fill="x")
        ttk.Entry(row, textvariable=self.verify_file).pack(side="left", fill="x", expand=True, padx=(0, 10))
        self._button(row, "Browse current file", self._browse_verify).pack(side="right")
        self._button(select, "Run integrity verification", lambda: self._verify(combo), True).pack(anchor="w", pady=(14, 0))
        result = self._panel(self.page_host)
        result.pack(fill="both", expand=True)
        self._section_heading(result, "Verification verdict")
        self.verify_verdict = self._label(result, "AWAITING VERIFICATION", color=MUTED, size=16, bold=True)
        self.verify_verdict.pack(anchor="w", pady=(0, 10))
        self.verify_result = tk.Text(result, height=9, bg="#0d1728", fg=TEXT,
                                     insertbackground=TEXT, relief="flat", wrap="word",
                                     padx=12, pady=12, font=("Consolas", 9))
        self.verify_result.pack(fill="both", expand=True)
        self.verify_result.insert("1.0", "Verification details will appear here.")
        self.verify_result.configure(state="disabled")

    def _browse_verify(self):
        path = filedialog.askopenfilename(title="Choose current file to verify")
        if path:
            self.verify_file.set(path)

    def _verify(self, combo):
        baseline = self.baseline_lookup.get(self.baseline_choice.get())
        path = self.verify_file.get().strip()
        if not baseline:
            messagebox.showwarning("Baseline required", "Create a baseline first, or choose a saved baseline.")
            return
        if not path or not FilePath(path).is_file():
            messagebox.showwarning("Current file required", "Choose an existing file to verify.")
            return
        self.status_var.set("Verifying file…")
        self.status_badge.configure(text="● VERIFYING", fg=AMBER, bg="#3b2c13")
        def work():
            try:
                current = hash_file(path)
                result = "INCONCLUSIVE" if not current["stable"] else ("MATCH" if current["hash"] == baseline["sha256"] else "MISMATCH")
                detail = {
                    "MATCH": "The current file SHA-256 matches the saved baseline.",
                    "MISMATCH": "The current file SHA-256 differs from the saved baseline.",
                    "INCONCLUSIVE": "The file changed while being hashed. Repeat verification when stable.",
                }[result]
                checked_at = utc_now()
                with self._connect() as con:
                    con.execute("""INSERT INTO checks
                        (baseline_id,file_path,file_name,file_size,current_sha256,result,checked_at,detail,tested_by)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                        (baseline["id"], current["path"], current["name"], current["size"],
                         current["hash"], result, checked_at, detail, self.current_user["id"]))
                payload = (baseline, current, result, detail, checked_at)
                self.after(0, lambda: self._verify_done(payload))
            except Exception as exc:
                self.after(0, lambda e=str(exc): self._operation_error("Verification error", e))
        threading.Thread(target=work, daemon=True).start()

    def _verify_done(self, payload):
        baseline, current, result, detail, checked_at = payload
        color = GREEN if result == "MATCH" else RED if result == "MISMATCH" else AMBER
        self.verify_verdict.configure(text=result.replace("_", " ") + (" — HASH VERIFIED" if result == "MATCH" else ""), fg=color)
        text = (f"RESULT: {result}\nDETAIL: {detail}\nCHECKED AT (UTC): {checked_at}\n\n"
                f"BASELINE ID: {baseline['id']}\nBASELINE FILE: {baseline['file_name']}\n"
                f"BASELINE SHA-256:\n{baseline['sha256']}\n\nCURRENT FILE: {current['name']}\n"
                f"PATH: {current['path']}\nSIZE: {current['size']:,} bytes\nCURRENT SHA-256:\n{current['hash']}")
        self._set_text(self.verify_result, text)
        self.last_result = {"baseline_id": baseline["id"], "current": current, "result": result,
                            "detail": detail, "checked_at": checked_at, "baseline_hash": baseline["sha256"]}
        self.status_var.set("Verification complete")
        self.status_badge.configure(text="● SYSTEM READY", fg=GREEN, bg="#12342f")
        self.refresh_dashboard()

    # ---------- Duplicate and corruption scanning ----------
    def _page_scan_files(self):
        self._section_heading(
            self.page_host, "Duplicate & file health scanner",
            "Scan a folder recursively. Original files are never changed or deleted."
        )
        controls = self._panel(self.page_host)
        controls.pack(fill="x", pady=(0, 12))
        self._section_heading(controls, "01 / Choose a folder")
        row = tk.Frame(controls, bg=PANEL)
        row.pack(fill="x", pady=(0, 8))
        self.scan_folder_var = getattr(self, "scan_folder_var", tk.StringVar())
        ttk.Entry(row, textvariable=self.scan_folder_var).pack(
            side="left", fill="x", expand=True, padx=(0, 10)
        )
        self._button(row, "Browse folder", self._browse_scan_folder).pack(side="right")
        action_row = tk.Frame(controls, bg=PANEL)
        action_row.pack(fill="x", pady=(6, 0))
        self.scan_button = self._button(action_row, "Start full scan", self._start_file_scan, True)
        self.scan_button.pack(side="left")
        self._button(action_row, "Export CSV", self._export_scan_csv).pack(side="left", padx=8)
        self.scan_progress = ttk.Progressbar(action_row, mode="indeterminate", length=180)
        self.scan_progress.pack(side="left", padx=12)
        self.scan_summary = self._label(
            controls, "Ready to scan. Select a folder to begin.", color=MUTED, size=9
        )
        self.scan_summary.pack(anchor="w", pady=(10, 0))

        results = self._panel(self.page_host)
        results.pack(fill="both", expand=True)
        self._section_heading(
            results, "Scan results",
            "Duplicate = identical SHA-256 content. Corruption checks are conservative and format-dependent."
        )
        self.scan_tree = self._tree(
            results,
            ("name", "size", "duplicate", "health", "path"),
            ("FILE", "SIZE (BYTES)", "DUPLICATE GROUP", "HEALTH CHECK", "FULL PATH"),
            12
        )
        self.scan_tree.column("name", width=170)
        self.scan_tree.column("size", width=100, anchor="e")
        self.scan_tree.column("duplicate", width=130)
        self.scan_tree.column("health", width=175)
        self.scan_tree.column("path", width=380)
        if not hasattr(self, "scan_results"):
            self.scan_results = []

    def _browse_scan_folder(self):
        folder = filedialog.askdirectory(title="Choose folder to scan")
        if folder:
            self.scan_folder_var.set(folder)

    def _start_file_scan(self):
        root = self.scan_folder_var.get().strip()
        if not root or not FilePath(root).is_dir():
            messagebox.showwarning("Folder required", "Choose an existing folder first.")
            return
        if getattr(self, "_scan_running", False):
            messagebox.showinfo("Scan running", "A scan is already in progress.")
            return

        self._scan_running = True
        self.scan_button.configure(state="disabled")
        self.scan_progress.start(10)
        self.scan_summary.configure(text="Scanning files and calculating SHA-256 hashes…", fg=AMBER)
        self.status_var.set("Scanning folder…")
        self.status_badge.configure(text="● SCANNING", fg=AMBER, bg="#3b2c13")
        root_path = str(FilePath(root).resolve())
        user_id = self.current_user["id"] if self.current_user else None
        started_at = utc_now()

        def work():
            records = []
            walk_errors = []
            for current_root, dirs, files in os.walk(root_path, onerror=lambda e: walk_errors.append(str(e))):
                # Avoid following directory symlinks; this prevents loops and escaping the chosen tree.
                dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(current_root, d))]
                for filename in files:
                    path = os.path.join(current_root, filename)
                    if os.path.islink(path):
                        continue
                    record = {
                        "path": str(FilePath(path).resolve()),
                        "name": filename,
                        "size": 0,
                        "hash": None,
                        "duplicate_group": "",
                        "health": "READ ERROR",
                        "detail": "",
                        "read_error": "",
                    }
                    try:
                        meta = hash_file(path)
                        record["size"] = meta["size"]
                        record["hash"] = meta["hash"]
                        if not meta["stable"]:
                            record["health"] = "CHANGED DURING SCAN"
                            record["detail"] = "File metadata changed while hashing; result may be inconclusive."
                        else:
                            status, detail = check_basic_file_health(path)
                            record["health"] = status
                            record["detail"] = detail
                    except (OSError, PermissionError) as exc:
                        record["read_error"] = str(exc)
                        record["detail"] = str(exc)
                    except Exception as exc:
                        record["read_error"] = f"{type(exc).__name__}: {exc}"
                        record["detail"] = record["read_error"]
                    records.append(record)

            # Only hash+size matches are grouped as duplicates; file names do not matter.
            groups = {}
            for record in records:
                if record["hash"] and record["size"] >= 0:
                    groups.setdefault((record["size"], record["hash"]), []).append(record)
            duplicate_group_count = 0
            extra_bytes = 0
            for (_size, _digest), group in groups.items():
                if len(group) > 1:
                    duplicate_group_count += 1
                    extra_bytes += group[0]["size"] * (len(group) - 1)
                    group_id = f"DUP-{duplicate_group_count:04d}"
                    for record in group:
                        record["duplicate_group"] = group_id

            issue_count = sum(
                1 for r in records
                if r["health"] in ("POTENTIAL CORRUPTION", "EMPTY FILE", "READ ERROR", "CHECK ERROR", "CHANGED DURING SCAN")
            )
            error_count = sum(1 for r in records if r["read_error"])
            finished_at = utc_now()
            try:
                with self._connect() as con:
                    cur = con.execute("""INSERT INTO scan_runs
                        (root_path,started_at,finished_at,scanned_count,duplicate_groups,
                         duplicate_extra_bytes,issue_count,error_count,scanned_by)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                        (root_path, started_at, finished_at, len(records), duplicate_group_count,
                         extra_bytes, issue_count, error_count, user_id))
                    run_id = cur.lastrowid
                    con.executemany("""INSERT INTO scan_results
                        (run_id,file_path,file_name,file_size,sha256,duplicate_group,
                         health_status,health_detail,read_error)
                        VALUES (?,?,?,?,?,?,?,?,?)""",
                        [(run_id, r["path"], r["name"], r["size"], r["hash"],
                          r["duplicate_group"], r["health"], r["detail"], r["read_error"])
                         for r in records])
                payload = {
                    "records": records, "run_id": run_id, "root": root_path,
                    "duplicates": duplicate_group_count, "extra_bytes": extra_bytes,
                    "issues": issue_count, "errors": error_count, "walk_errors": walk_errors,
                    "count": len(records)
                }
                self.after(0, lambda p=payload: self._file_scan_done(p))
            except Exception as exc:
                self.after(0, lambda e=str(exc): self._file_scan_failed(e))

        threading.Thread(target=work, daemon=True).start()

    def _file_scan_done(self, payload):
        self._scan_running = False
        self.scan_button.configure(state="normal")
        self.scan_progress.stop()
        self.scan_results = payload["records"]
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)
        for r in self.scan_results:
            self.scan_tree.insert("", "end", values=(
                r["name"], f'{r["size"]:,}', r["duplicate_group"] or "—",
                r["health"], r["path"]
            ))
        summary = (
            f"Scan #{payload['run_id']} complete | Files: {payload['count']} | "
            f"Duplicate groups: {payload['duplicates']} | Estimated duplicate extra storage: "
            f"{payload['extra_bytes']:,} bytes | Potential issues/empty files: {payload['issues']} | "
            f"Read errors: {payload['errors']}"
        )
        if payload["walk_errors"]:
            summary += f" | Folder access warnings: {len(payload['walk_errors'])}"
        self.scan_summary.configure(text=summary, fg=GREEN)
        self.status_var.set("Scan complete")
        self.status_badge.configure(text="● SYSTEM READY", fg=GREEN, bg="#12342f")
        messagebox.showinfo("Scan complete", summary)
        self.refresh_dashboard()

    def _file_scan_failed(self, error):
        self._scan_running = False
        self.scan_button.configure(state="normal")
        self.scan_progress.stop()
        self.status_var.set("Scan failed")
        self.status_badge.configure(text="● ERROR", fg=RED, bg="#3b1722")
        messagebox.showerror("Scan failed", error)

    def _export_scan_csv(self):
        records = getattr(self, "scan_results", [])
        if not records:
            messagebox.showinfo("No results", "Run a scan before exporting results.")
            return
        target = filedialog.asksaveasfilename(
            title="Export IntegrityX scan results", defaultextension=".csv",
            initialfile="integrityx_scan_results.csv",
            filetypes=[("CSV report", "*.csv")]
        )
        if not target:
            return
        try:
            with open(target, "w", newline="", encoding="utf-8-sig") as stream:
                writer = csv.DictWriter(stream, fieldnames=[
                    "path", "name", "size", "hash", "duplicate_group",
                    "health", "detail", "read_error"
                ])
                writer.writeheader()
                for record in records:
                    writer.writerow(record)
            messagebox.showinfo("Export complete", f"CSV report saved:\n{target}")
        except OSError as exc:
            messagebox.showerror("Export error", str(exc))

    # ---------- Reports / logs ----------
    def _page_reports(self):
        self._section_heading(self.page_host, "Reports & activity logs",
                              "Review verification records saved to SQLite and export a selected result as a text report.")
        toolbar = self._panel(self.page_host)
        toolbar.pack(fill="x")
        top = tk.Frame(toolbar, bg=PANEL)
        top.pack(fill="x")
        self._label(top, "Search by file name, result, or hash", size=9).pack(side="left")
        search_entry = ttk.Entry(top, textvariable=self.search_var, width=34)
        search_entry.pack(side="left", padx=10)
        tree_panel = self._panel(self.page_host)
        tree_panel.pack(fill="both", expand=True, pady=(14, 0))
        self.report_tree = self._tree(tree_panel,
            ("id", "time", "tester", "file", "result", "size", "hash"),
            ("ID", "CHECKED AT (UTC)", "TESTER", "FILE", "RESULT", "SIZE", "SHA-256"), 14)
        buttons = tk.Frame(tree_panel, bg=PANEL)
        buttons.pack(fill="x", pady=(10, 0))
        self._button(buttons, "Refresh logs", self._refresh_logs).pack(side="left")
        self._button(buttons, "Export selected report", self._export_selected, True).pack(side="left", padx=8)
        search_entry.bind("<KeyRelease>", lambda _e: self._refresh_logs())
        self._refresh_logs()

    def _refresh_logs(self):
        if not hasattr(self, "report_tree") or not self.report_tree.winfo_exists():
            return
        for item in self.report_tree.get_children():
            self.report_tree.delete(item)
        term = self.search_var.get().strip().lower()
        with self._connect() as con:
            rows = con.execute("""SELECT c.id,c.checked_at,c.file_name,c.result,c.file_size,c.current_sha256,
            c.detail,c.baseline_id,c.file_path,u.username AS tester
            FROM checks c LEFT JOIN users u ON u.id=c.tested_by ORDER BY c.id DESC""").fetchall()
        self.report_rows = {}
        for r in rows:
            if term and not any(term in str(r[k] or "").lower() for k in ("file_name", "result", "current_sha256", "detail", "tester")):
                continue
            iid = self.report_tree.insert("", "end", values=(r["id"], r["checked_at"], r["tester"] or "Unknown",
                r["file_name"], r["result"], f'{r["file_size"]:,}', r["current_sha256"][:20] + "…"))
            self.report_rows[iid] = dict(r)

    def _export_selected(self):
        selection = self.report_tree.selection()
        if not selection:
            messagebox.showinfo("Select a record", "Select a verification row first.")
            return
        row = self.report_rows[selection[0]]
        target = filedialog.asksaveasfilename(title="Export verification report",
            defaultextension=".txt", initialfile=f"integrity_report_{row['id']}.txt",
            filetypes=[("Text report", "*.txt")])
        if not target:
            return
        content = (
            "INTEGRITYX - FILE INTEGRITY VERIFICATION REPORT\n" + "=" * 54 + "\n\n"
            f"Record ID: {row['id']}\nBaseline ID: {row['baseline_id']}\n"
            f"Tester username: {row.get('tester') or 'Unknown'}\n"
            f"Checked at (UTC): {row['checked_at']}\nResult: {row['result']}\n"
            f"Detail: {row['detail']}\nFile: {row['file_name']}\nPath: {row['file_path']}\n"
            f"Size: {row['file_size']} bytes\nCurrent SHA-256: {row['current_sha256']}\n"
        )
        try:
            FilePath(target).write_text(content, encoding="utf-8")
            messagebox.showinfo("Report exported", f"Report saved:\n{target}")
        except OSError as exc:
            messagebox.showerror("Export error", str(exc))

    # ---------- About ----------
    def _page_about(self):
        self._section_heading(self.page_host, "About IntegrityX",
                              "A local-first demonstration project for file integrity monitoring and digital forensics.")
        about = self._panel(self.page_host)
        about.pack(fill="x", pady=(0, 14))
        self._label(about, "CORE CAPABILITIES", color=TEAL, size=10, bold=True).pack(anchor="w")
        capabilities = [
            "Username/password authentication with tester accounts",
            "Passwords stored as salted PBKDF2-HMAC-SHA256 hashes",
            "Each baseline and verification is linked to the signed-in tester ID",
            "Login success, failed login attempts, and logout events are audited",
            "SHA-256 file hashing using Python hashlib",
            "Baseline metadata and verification history stored in SQLite",
            "Case, examiner, and evidence item metadata",
            "Match / mismatch / inconclusive verification results",
            "Searchable activity logs and text report export",
            "File hashing runs in a background thread to keep the interface responsive",
        ]
        for item in capabilities:
            self._label(about, "•  " + item, color=TEXT, size=10).pack(anchor="w", pady=5)
        note = self._panel(self.page_host)
        note.pack(fill="x")
        self._label(note, "IMPORTANT LIMITATIONS", color=AMBER, size=10, bold=True).pack(anchor="w")
        self._label(note, "This application checks file contents against a saved baseline. It does not prove that a baseline is trustworthy, acquire forensic disk images, or create a cryptographically signed chain-of-custody record. Keep original evidence protected and document how baselines were obtained.",
                    color=MUTED, size=9, wraplength=820, justify="left").pack(anchor="w", pady=(8, 0))
        paths = self._panel(self.page_host)
        paths.pack(fill="x", pady=(14, 0))
        self._label(paths, "LOCAL DATABASE", color=TEAL, size=8, bold=True).pack(anchor="w")
        self._label(paths, str(FilePath(DB_PATH).resolve()), color=TEXT, size=9).pack(anchor="w", pady=(4, 0))
        self._button(paths, "Open database folder", lambda: self._open_db_folder()).pack(anchor="w", pady=(10, 0))

    def _open_db_folder(self):
        try:
            os.startfile(str(FilePath(DB_PATH).resolve().parent))
        except Exception as exc:
            messagebox.showerror("Cannot open folder", str(exc))

    # ---------- Shared helpers ----------
    def _set_text(self, widget, value):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.configure(state="disabled")

    def _operation_error(self, title, error):
        self.status_var.set("Operation failed")
        self.status_badge.configure(text="● ERROR", fg=RED, bg="#3b1722")
        messagebox.showerror(title, error)

    def refresh_dashboard(self):
        # Rebuild dashboard when currently visible so counters and recent activity stay fresh.
        if self.page_title.get() == "Dashboard" and hasattr(self, "page_host"):
            self.show_page("Dashboard")


if __name__ == "__main__":
    app = IntegrityXApp()
    app.mainloop()
