import os
import io
import csv
import json
import hashlib
import zipfile
import struct
from datetime import datetime, timezone
from functools import wraps
from collections import defaultdict

from flask import (
    Flask, request, redirect, url_for, session, flash, render_template_string,
    send_file, abort
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from jinja2 import DictLoader

# IntegrityX Flask web application - single-file deployment.
# Existing tables User/Baseline/Check/Audit retain their names and columns.
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-before-deployment")
app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", 20 * 1024 * 1024))

_db_url = os.environ.get("DATABASE_URL", "sqlite:///integrityx.db")
if _db_url.startswith("postgres://"):
    _db_url = _db_url.replace("postgres://", "postgresql://", 1)
# Render/Neon commonly provide postgres:// or postgresql:// URLs.
app.config["SQLALCHEMY_DATABASE_URI"] = _db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
db = SQLAlchemy(app)


def stamp():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def digest_stream(stream):
    h = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        size += len(chunk)
        h.update(chunk)
    return h.hexdigest(), size


def read_upload(upload):
    """Read an uploaded stream into memory up to configured upload limit."""
    upload.stream.seek(0)
    data = upload.stream.read(app.config["MAX_CONTENT_LENGTH"] + 1)
    upload.stream.seek(0)
    if len(data) > app.config["MAX_CONTENT_LENGTH"]:
        raise ValueError("File exceeds the configured upload limit.")
    return data


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(160), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class Baseline(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    case_id = db.Column(db.String(100))
    evidence_id = db.Column(db.String(100))
    filename = db.Column(db.String(255), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    created = db.Column(db.String(40), nullable=False)


class Check(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    baseline_id = db.Column(db.Integer, nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    result = db.Column(db.String(20), nullable=False)
    checked = db.Column(db.String(40), nullable=False)


class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    event = db.Column(db.String(40), nullable=False)
    at = db.Column(db.String(40), nullable=False)


class ScanEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    result = db.Column(db.String(40), nullable=False)
    details = db.Column(db.Text, nullable=False, default="")
    scanned = db.Column(db.String(40), nullable=False)


with app.app_context():
    db.create_all()


def logged(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


# ----- File screening helpers -----
MAGIC = {
    ".jpg": (b"\xff\xd8\xff",), ".jpeg": (b"\xff\xd8\xff",),
    ".png": (b"\x89PNG\r\n\x1a\n",), ".gif": (b"GIF87a", b"GIF89a"),
    ".pdf": (b"%PDF-",), ".zip": (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"),
    ".docx": (b"PK\x03\x04",), ".xlsx": (b"PK\x03\x04",), ".pptx": (b"PK\x03\x04",),
    ".gz": (b"\x1f\x8b",), ".bmp": (b"BM",), ".wav": (b"RIFF",),
    ".mp3": (b"ID3",), ".exe": (b"MZ",), ".dll": (b"MZ",),
}
SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi", ".com", ".jar"}
SUSPICIOUS_TEXT_MARKERS = [b"powershell -enc", b"invoke-expression", b"wscript.shell", b"cmd.exe /c", b"createobject(\"wscript.shell\")"]


def analyze_file(filename, data):
    """Lightweight integrity/type sanity checks, not a full antivirus scan."""
    ext = os.path.splitext(filename.lower())[1]
    issues = []
    if not data:
        issues.append("Zero-byte/empty file")
    signatures = MAGIC.get(ext)
    if data and signatures and not any(data.startswith(sig) for sig in signatures):
        issues.append("File extension does not match the expected file signature")
    if ext in {".jpg", ".jpeg"} and data and (len(data) < 4 or not data.endswith(b"\xff\xd9")):
        issues.append("JPEG may be truncated or structurally incomplete (missing end marker)")
    if ext == ".png" and data:
        if len(data) < 20 or b"IEND" not in data[-16:]:
            issues.append("PNG may be truncated or missing its IEND marker")
    if ext == ".pdf" and data and b"%%EOF" not in data[-2048:]:
        issues.append("PDF may be truncated or missing EOF marker")
    if ext in {".zip", ".docx", ".xlsx", ".pptx"} and data:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                bad = zf.testzip()
                if bad:
                    issues.append("Archive CRC error in member: " + str(bad)[:120])
        except (zipfile.BadZipFile, OSError, EOFError):
            issues.append("Archive/container is corrupt or unreadable")
    if ext in SUSPICIOUS_EXTENSIONS:
        issues.append("Executable or script file type: review carefully before preserving as evidence")
    lower = data[:2 * 1024 * 1024].lower()
    if any(marker in lower for marker in SUSPICIOUS_TEXT_MARKERS):
        issues.append("Potentially suspicious command/script marker found (heuristic)")
    if issues:
        status = "REVIEW"
    else:
        status = "NO BASIC ISSUES FOUND"
    return status, issues


# ----- Small responsive UI embedded in this file (no templates folder required) -----
BASE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · IntegrityX</title><style>
:root{--bg:#0b1020;--panel:#121a2e;--line:#25304b;--text:#eaf0ff;--muted:#9eaccb;--accent:#5eead4;--danger:#fda4af;--ok:#86efac}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at top,#172647 0,#0b1020 60%);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}.nav{display:flex;gap:10px;align-items:center;justify-content:space-between;padding:16px max(4vw,18px);border-bottom:1px solid var(--line);background:#0b1020dd;position:sticky;top:0}.brand{font-size:21px;font-weight:800;letter-spacing:.4px}.brand span{color:var(--accent)}.links{display:flex;gap:12px;flex-wrap:wrap}.links a,.btn{color:var(--text);text-decoration:none;border:1px solid var(--line);padding:9px 12px;border-radius:10px;background:#18233b;cursor:pointer}.links a:hover,.btn:hover{border-color:var(--accent)}main{max-width:1100px;margin:28px auto;padding:0 18px}.panel{background:linear-gradient(145deg,#141e35,#10182a);border:1px solid var(--line);border-radius:18px;padding:22px;margin:14px 0;box-shadow:0 10px 40px #0002}.hero{display:flex;justify-content:space-between;gap:20px;align-items:center;flex-wrap:wrap}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}.metric{background:#0c1426;border:1px solid var(--line);border-radius:14px;padding:16px}.metric b{font-size:27px;display:block;color:var(--accent)}label{display:block;margin:12px 0 6px;color:#cbd5ed}input,select,textarea{width:100%;padding:12px;border-radius:10px;background:#080f1e;color:var(--text);border:1px solid #33415f}input[type=file]{padding:10px}button{font:inherit}.btn.primary{background:var(--accent);color:#06211e;font-weight:800;border-color:var(--accent)}.btn.danger{border-color:#713b50}.flash{padding:12px 14px;border:1px solid var(--line);border-radius:10px;margin:10px 0}.flash.success{border-color:#226b56;color:var(--ok)}.flash.error{border-color:#874052;color:var(--danger)}table{width:100%;border-collapse:collapse;overflow-wrap:anywhere}th,td{text-align:left;padding:11px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted)}.pill{display:inline-block;padding:3px 8px;border-radius:20px;background:#1c2c47;font-size:12px}.small{font-size:13px}.hash{font-family:ui-monospace,monospace;overflow-wrap:anywhere}.footer{text-align:center;color:var(--muted);padding:28px}.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px}ul{padding-left:22px}@media(max-width:600px){.nav{align-items:flex-start;flex-direction:column}.links{gap:6px}.links a{padding:7px 9px}.panel{padding:16px}table{font-size:13px}}
</style></head><body><header class="nav"><div class="brand">Integrity<span>X</span> <span class="muted small">FORENSIC WORKSPACE</span></div><nav class="links">{% if session.get('uid') %}<a href="{{ url_for('dashboard') }}">Dashboard</a><a href="{{ url_for('baseline') }}">Create baseline</a><a href="{{ url_for('verify') }}">Verify</a><a href="{{ url_for('scan') }}">Evidence scan</a><a href="{{ url_for('reports') }}">Reports</a><a href="{{ url_for('logout') }}">Logout</a>{% else %}<a href="{{ url_for('login') }}">Login</a><a href="{{ url_for('register') }}">Register</a>{% endif %}</nav></header><main>{% with messages=get_flashed_messages(with_categories=true) %}{% for category,message in messages %}<div class="flash {{ category }}">{{ message }}</div>{% endfor %}{% endwith %}{% block content %}{% endblock %}</main><div class="footer">IntegrityX · SHA-256 evidence integrity workflow · {{ year }}</div></body></html>'''


# Register the base HTML as a real Jinja template. Passing its entire source
# as an extends variable makes Jinja treat the source as a template name.
app.jinja_loader = DictLoader({"base.html": BASE})

def page(title, body, **context):
    content = "{% extends 'base.html' %}{% block content %}" + body + "{% endblock %}"
    return render_template_string(content, title=title, year=datetime.now().year, **context)


@app.route("/")
def index():
    return redirect(url_for("dashboard" if "uid" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not name or len(username) < 3 or len(password) < 10:
            flash("Name, username (3+ characters) and password (10+ characters) are required.", "error")
        elif User.query.filter(db.func.lower(User.username) == username.lower()).first():
            flash("Username already exists.", "error")
        else:
            db.session.add(User(username=username, full_name=name, password_hash=generate_password_hash(password)))
            db.session.add(Audit(username=username, event="REGISTER", at=stamp()))
            db.session.commit()
            flash("Account created. Please sign in.", "success")
            return redirect(url_for("login"))
    body = '''<section class="panel" style="max-width:520px;margin:30px auto"><h1>Create account</h1><p class="muted">Register to manage your own evidence baselines and reports.</p><form method="post"><label>Full name</label><input name="name" required maxlength="160"><label>Username</label><input name="username" required minlength="3" maxlength="80"><label>Password (minimum 10 characters)</label><input type="password" name="password" required minlength="10"><p><button class="btn primary" type="submit">Create account</button></p></form><p class="muted">Already registered? <a href="{{ url_for('login') }}">Sign in</a></p></section>'''
    return page("Register", body)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = User.query.filter(db.func.lower(User.username) == username.lower()).first()
        if user and check_password_hash(user.password_hash, request.form.get("password", "")):
            session.clear()
            session["uid"] = user.id
            session["username"] = user.username
            session["name"] = user.full_name
            db.session.add(Audit(username=user.username, event="LOGIN", at=stamp()))
            db.session.commit()
            return redirect(url_for("dashboard"))
        db.session.add(Audit(username=username or "(blank)", event="LOGIN_FAILED", at=stamp()))
        db.session.commit()
        flash("Incorrect username or password.", "error")
    body = '''<section class="panel" style="max-width:520px;margin:30px auto"><h1>IntegrityX Login</h1><p class="muted">Digital evidence integrity and forensic review workspace.</p><form method="post"><label>Username</label><input name="username" autocomplete="username" required><label>Password</label><input type="password" name="password" autocomplete="current-password" required><p><button class="btn primary" type="submit">Login securely</button></p></form><p class="muted">New user? <a href="{{ url_for('register') }}">Create an account</a></p></section>'''
    return page("Login", body)


@app.route("/logout")
def logout():
    if session.get("username"):
        db.session.add(Audit(username=session["username"], event="LOGOUT", at=stamp()))
        db.session.commit()
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@logged
def dashboard():
    uid = session["uid"]
    baselines = Baseline.query.filter_by(user_id=uid).order_by(Baseline.id.desc()).limit(8).all()
    checks = Check.query.filter_by(user_id=uid).order_by(Check.id.desc()).limit(8).all()
    scans = ScanEvent.query.filter_by(user_id=uid).order_by(ScanEvent.id.desc()).limit(6).all()
    total_baselines = Baseline.query.filter_by(user_id=uid).count()
    total_checks = Check.query.filter_by(user_id=uid).count()
    matches = Check.query.filter_by(user_id=uid, result="MATCH").count()
    mismatches = Check.query.filter_by(user_id=uid, result="MISMATCH").count()
    body = '''<section class="panel hero"><div><p class="pill">SIGNED IN · {{ session.get('username') }}</p><h1>Welcome, {{ session.get('name') }}</h1><p class="muted">Upload evidence, review basic file health, create a trusted SHA-256 baseline, then verify later copies against it.</p></div><div><a class="btn primary" href="{{ url_for('baseline') }}">＋ Create baseline</a> <a class="btn" href="{{ url_for('scan') }}">Scan evidence</a></div></section>
<div class="grid"><div class="metric"><span class="muted">Baselines</span><b>{{ total_baselines }}</b></div><div class="metric"><span class="muted">Integrity checks</span><b>{{ total_checks }}</b></div><div class="metric"><span class="muted">Exact matches</span><b>{{ matches }}</b></div><div class="metric"><span class="muted">Mismatches</span><b>{{ mismatches }}</b></div></div>
<section class="panel"><div class="hero"><h2>Recent evidence baselines</h2><a href="{{ url_for('reports') }}">Open reports →</a></div>{% if baselines %}<table><tr><th>Evidence</th><th>Case / Evidence ID</th><th>Size</th><th>SHA-256</th><th>Created</th></tr>{% for b in baselines %}<tr><td>{{ b.filename }}</td><td>{{ b.case_id or '—' }} / {{ b.evidence_id or '—' }}</td><td>{{ b.size }} B</td><td class="hash small">{{ b.sha256 }}</td><td>{{ b.created }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">No baselines yet. Run an evidence scan first, then create a baseline for evidence that passes your review.</p>{% endif %}</section>
<div class="two"><section class="panel"><h2>Recent integrity checks</h2>{% if checks %}<table><tr><th>File</th><th>Result</th><th>Checked</th></tr>{% for c in checks %}<tr><td>{{ c.filename }}<div class="muted small">Baseline #{{ c.baseline_id }}</div></td><td><span class="pill">{{ c.result }}</span></td><td>{{ c.checked }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">No checks yet.</p>{% endif %}</section><section class="panel"><h2>Recent file scans</h2>{% if scans %}<table><tr><th>File</th><th>Result</th><th>Scanned</th></tr>{% for s in scans %}<tr><td>{{ s.filename }}</td><td><span class="pill">{{ s.result }}</span></td><td>{{ s.scanned }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">No scans yet.</p>{% endif %}</section></div>'''
    return page("Dashboard", body, baselines=baselines, checks=checks, scans=scans,
                total_baselines=total_baselines, total_checks=total_checks, matches=matches, mismatches=mismatches)


@app.route("/baseline", methods=["GET", "POST"])
@logged
def baseline():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or not f.filename:
            flash("Choose an evidence file first.", "error")
            return redirect(url_for("baseline"))
        try:
            data = read_upload(f)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("baseline"))
        filename = secure_filename(f.filename) or "evidence-file"
        # A baseline should only be stored after basic screening. This is not an antivirus guarantee.
        status, issues = analyze_file(filename, data)
        if status != "NO BASIC ISSUES FOUND":
            flash("Baseline not created: review scan warnings first — " + "; ".join(issues), "error")
            return redirect(url_for("scan"))
        h = hashlib.sha256(data).hexdigest()
        b = Baseline(user_id=session["uid"], case_id=request.form.get("case_id", "").strip(),
                     evidence_id=request.form.get("evidence_id", "").strip(), filename=filename,
                     size=len(data), sha256=h, created=stamp())
        db.session.add(b)
        db.session.add(ScanEvent(user_id=session["uid"], filename=filename, sha256=h, size=len(data),
                                 result="NO BASIC ISSUES FOUND", details="Basic signature/structure checks passed; not an antivirus scan.", scanned=stamp()))
        db.session.commit()
        flash("Baseline saved after basic file checks. SHA-256: " + h, "success")
        return redirect(url_for("dashboard"))
    body = '''<section class="panel"><h1>Create evidence baseline</h1><p class="muted">IntegrityX first checks basic file signatures/structure. Files with warnings are not automatically baselined. Review the warnings and investigate the original evidence before proceeding.</p><form method="post" enctype="multipart/form-data"><div class="two"><div><label>Case ID (optional)</label><input name="case_id" maxlength="100" placeholder="e.g. CASE-2026-001"></div><div><label>Evidence ID (optional)</label><input name="evidence_id" maxlength="100" placeholder="e.g. EVD-001"></div></div><label>Select evidence file</label><input type="file" name="file" required><p><button class="btn primary" type="submit">Analyze & create baseline</button></p></form></section><section class="panel"><b>Forensic note</b><p class="muted">The SHA-256 hash identifies the exact uploaded bytes. Keep the original evidence and acquisition notes separately; this web tool does not certify chain of custody or prove that a file is malware-free.</p></section>'''
    return page("Create baseline", body)


@app.route("/verify", methods=["GET", "POST"])
@logged
def verify():
    uid = session["uid"]
    baselines = Baseline.query.filter_by(user_id=uid).order_by(Baseline.id.desc()).all()
    if request.method == "POST":
        try:
            bid = int(request.form.get("baseline_id", "0"))
        except ValueError:
            bid = 0
        b = Baseline.query.filter_by(id=bid, user_id=uid).first()
        f = request.files.get("file")
        if not b or not f or not f.filename:
            flash("Select a baseline and upload a file.", "error")
            return redirect(url_for("verify"))
        try:
            data = read_upload(f)
        except ValueError as exc:
            flash(str(exc), "error")
            return redirect(url_for("verify"))
        h = hashlib.sha256(data).hexdigest()
        result = "MATCH" if h == b.sha256 else "MISMATCH"
        db.session.add(Check(user_id=uid, baseline_id=b.id, filename=secure_filename(f.filename) or "file",
                             size=len(data), sha256=h, result=result, checked=stamp()))
        db.session.add(Audit(username=session["username"], event="VERIFY_" + result, at=stamp()))
        db.session.commit()
        flash(f"{result}: " + ("file bytes match the saved baseline." if result == "MATCH" else "file differs from the saved baseline."), "success" if result == "MATCH" else "error")
        return redirect(url_for("reports"))
    body = '''<section class="panel"><h1>Verify integrity</h1><p class="muted">Select one of your saved baselines and upload the candidate file. A matching SHA-256 hash means the uploaded bytes are identical to the baseline bytes.</p>{% if baselines %}<form method="post" enctype="multipart/form-data"><label>Baseline</label><select name="baseline_id" required><option value="">Choose baseline…</option>{% for b in baselines %}<option value="{{ b.id }}">#{{ b.id }} · {{ b.filename }} · {{ b.created }} · {{ b.sha256[:12] }}…</option>{% endfor %}</select><label>Candidate file</label><input type="file" name="file" required><p><button class="btn primary" type="submit">Calculate & compare SHA-256</button></p></form>{% else %}<p>No baselines exist yet. <a href="{{ url_for('baseline') }}">Create a baseline</a> first.</p>{% endif %}</section>'''
    return page("Verify integrity", body, baselines=baselines)


@app.route("/scan", methods=["GET", "POST"])
@logged
def scan():
    results = []
    if request.method == "POST":
        files = [f for f in request.files.getlist("files") if f and f.filename]
        if not files:
            flash("Select one or more files to scan.", "error")
            return redirect(url_for("scan"))
        seen = defaultdict(list)
        for f in files:
            filename = secure_filename(f.filename) or "evidence-file"
            try:
                data = read_upload(f)
            except ValueError as exc:
                results.append({"filename": filename, "size": 0, "sha256": "—", "status": "REVIEW", "issues": [str(exc)], "duplicate": False})
                continue
            h = hashlib.sha256(data).hexdigest()
            status, issues = analyze_file(filename, data)
            seen[(len(data), h)].append(filename)
            results.append({"filename": filename, "size": len(data), "sha256": h, "status": status, "issues": issues, "duplicate": False})
        known_baselines = Baseline.query.filter_by(user_id=session["uid"]).all()
        known_by_hash = {(b.size, b.sha256): b for b in known_baselines}
        for result in results:
            if result["sha256"] == "—":
                continue
            key = (result["size"], result["sha256"])
            if len(seen[key]) > 1:
                result["duplicate"] = True
                result["issues"].append("Exact duplicate detected within this upload batch")
            elif key in known_by_hash:
                result["duplicate"] = True
                baseline_match = known_by_hash[key]
                result["issues"].append(f"Exact duplicate of saved baseline #{baseline_match.id} ({baseline_match.filename})")
        # Persist each scan result for the current user's reports/history.
        for result in results:
            db.session.add(ScanEvent(user_id=session["uid"], filename=result["filename"], sha256=result["sha256"],
                                     size=result["size"], result=("DUPLICATE" if result["duplicate"] else result["status"]),
                                     details="; ".join(result["issues"]) or "No basic issues found. Not an antivirus scan.", scanned=stamp()))
        db.session.add(Audit(username=session["username"], event="EVIDENCE_SCAN", at=stamp()))
        db.session.commit()
        duplicates_count = sum(1 for r in results if r["duplicate"])
        review_count = sum(1 for r in results if r["status"] == "REVIEW")
        flash(f"Scanned {len(results)} file(s): {review_count} require review; {duplicates_count} duplicate item(s) detected in this batch.", "success" if not review_count and not duplicates_count else "error")
    body = '''<section class="panel"><h1>Evidence health & duplicate scan</h1><p class="muted">Supports arbitrary file extensions for hashing. Basic corruption/signature checks apply only to known formats. Duplicate detection is based on exact size + SHA-256 within the files uploaded in this batch. Suspicious markers are heuristics, not antivirus.</p><form method="post" enctype="multipart/form-data"><label>Choose multiple files</label><input type="file" name="files" multiple required><p><button class="btn primary" type="submit">Scan selected evidence</button></p></form></section>{% if results %}<section class="panel"><div class="hero"><h2>Scan results</h2><a class="btn" href="{{ url_for('export_scan_csv') }}">Export scan history CSV</a></div><table><tr><th>File</th><th>Size</th><th>Status</th><th>Duplicate</th><th>SHA-256</th><th>Findings</th></tr>{% for r in results %}<tr><td>{{ r.filename }}</td><td>{{ r.size }} B</td><td><span class="pill">{{ r.status }}</span></td><td>{{ 'YES' if r.duplicate else 'No' }}</td><td class="hash small">{{ r.sha256 }}</td><td>{% if r.issues %}<ul>{% for issue in r.issues %}<li>{{ issue }}</li>{% endfor %}</ul>{% else %}<span class="muted">No basic issues found</span>{% endif %}</td></tr>{% endfor %}</table></section>{% endif %}<section class="panel"><h3>What these checks can and cannot say</h3><ul><li><b>Corruption:</b> checks selected structural markers and archive CRC for supported formats; not every damaged file can be detected.</li><li><b>Duplicate:</b> exact byte-for-byte duplicates in this upload batch.</li><li><b>Suspicious:</b> simple filename and text-marker heuristics only.</li><li><b>Not provided:</b> full malware scanning, proof of authenticity, or automatic image manipulation detection.</li></ul></section>'''
    return page("Evidence scan", body, results=results)


@app.route("/reports")
@logged
def reports():
    uid = session["uid"]
    baselines = Baseline.query.filter_by(user_id=uid).order_by(Baseline.id.desc()).all()
    checks = Check.query.filter_by(user_id=uid).order_by(Check.id.desc()).all()
    scans = ScanEvent.query.filter_by(user_id=uid).order_by(ScanEvent.id.desc()).limit(100).all()
    audits = Audit.query.filter_by(username=session["username"]).order_by(Audit.id.desc()).limit(50).all()
    body = '''<section class="panel hero"><div><h1>Forensic reports & activity</h1><p class="muted">Export saved baseline records, integrity comparisons, scan findings, and activity logs for this account.</p></div><div><a class="btn primary" href="{{ url_for('export_report', fmt='csv') }}">Download CSV</a> <a class="btn" href="{{ url_for('export_report', fmt='json') }}">Download JSON</a></div></section>
<section class="panel"><h2>Integrity checks</h2>{% if checks %}<table><tr><th>File</th><th>Baseline ID</th><th>Result</th><th>Candidate SHA-256</th><th>Time</th></tr>{% for c in checks %}<tr><td>{{ c.filename }}</td><td>{{ c.baseline_id }}</td><td><span class="pill">{{ c.result }}</span></td><td class="hash small">{{ c.sha256 }}</td><td>{{ c.checked }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">No integrity checks saved.</p>{% endif %}</section>
<section class="panel"><h2>Evidence scan history</h2>{% if scans %}<table><tr><th>File</th><th>Status</th><th>Size</th><th>SHA-256</th><th>Findings</th><th>Time</th></tr>{% for s in scans %}<tr><td>{{ s.filename }}</td><td>{{ s.result }}</td><td>{{ s.size }} B</td><td class="hash small">{{ s.sha256 }}</td><td>{{ s.details }}</td><td>{{ s.scanned }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">No scan history saved.</p>{% endif %}</section>
<section class="panel"><h2>Recent account activity</h2>{% if audits %}<table><tr><th>Event</th><th>Username</th><th>Time</th></tr>{% for a in audits %}<tr><td>{{ a.event }}</td><td>{{ a.username }}</td><td>{{ a.at }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">No activity logged.</p>{% endif %}</section>'''
    return page("Reports", body, baselines=baselines, checks=checks, scans=scans, audits=audits)


def report_payload(uid):
    baselines = Baseline.query.filter_by(user_id=uid).order_by(Baseline.id.asc()).all()
    checks = Check.query.filter_by(user_id=uid).order_by(Check.id.asc()).all()
    scans = ScanEvent.query.filter_by(user_id=uid).order_by(ScanEvent.id.asc()).all()
    return {
        "application": "IntegrityX",
        "generated_at": stamp(),
        "notice": "SHA-256 verifies byte identity. Basic file checks and heuristic markers are not a full antivirus scan or proof of authenticity.",
        "baselines": [{"id": b.id, "case_id": b.case_id, "evidence_id": b.evidence_id, "filename": b.filename, "size": b.size, "sha256": b.sha256, "created": b.created} for b in baselines],
        "integrity_checks": [{"id": c.id, "baseline_id": c.baseline_id, "filename": c.filename, "size": c.size, "sha256": c.sha256, "result": c.result, "checked": c.checked} for c in checks],
        "scan_history": [{"id": s.id, "filename": s.filename, "size": s.size, "sha256": s.sha256, "result": s.result, "details": s.details, "scanned": s.scanned} for s in scans],
    }


@app.route("/export/<fmt>")
@logged
def export_report(fmt):
    if fmt == "json":
        raw = json.dumps(report_payload(session["uid"]), indent=2, ensure_ascii=False).encode("utf-8")
        return send_file(io.BytesIO(raw), mimetype="application/json", as_attachment=True, download_name="integrityx_forensic_report.json")
    if fmt != "csv":
        abort(404)
    payload = report_payload(session["uid"])
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["record_type", "id", "case_id", "evidence_id", "filename", "size_bytes", "sha256", "result", "timestamp", "details"])
    for b in payload["baselines"]:
        writer.writerow(["BASELINE", b["id"], b["case_id"], b["evidence_id"], b["filename"], b["size"], b["sha256"], "BASELINE_CREATED", b["created"], ""])
    for c in payload["integrity_checks"]:
        writer.writerow(["INTEGRITY_CHECK", c["id"], "", "", c["filename"], c["size"], c["sha256"], c["result"], c["checked"], "baseline_id=" + str(c["baseline_id"])])
    for s in payload["scan_history"]:
        writer.writerow(["EVIDENCE_SCAN", s["id"], "", "", s["filename"], s["size"], s["sha256"], s["result"], s["scanned"], s["details"]])
    raw = io.BytesIO(output.getvalue().encode("utf-8-sig"))
    return send_file(raw, mimetype="text/csv; charset=utf-8", as_attachment=True, download_name="integrityx_forensic_report.csv")


@app.route("/export-scan.csv")
@logged
def export_scan_csv():
    scans = ScanEvent.query.filter_by(user_id=session["uid"]).order_by(ScanEvent.id.asc()).all()
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["id", "filename", "size_bytes", "sha256", "result", "details", "scanned_at"])
    for s in scans:
        writer.writerow([s.id, s.filename, s.size, s.sha256, s.result, s.details, s.scanned])
    return send_file(io.BytesIO(output.getvalue().encode("utf-8-sig")), mimetype="text/csv; charset=utf-8", as_attachment=True, download_name="integrityx_scan_history.csv")


@app.errorhandler(413)
def too_large(_error):
    flash(f"Upload is too large. Current maximum is {app.config['MAX_CONTENT_LENGTH'] // (1024 * 1024)} MB per request.", "error")
    return redirect(request.referrer or url_for("dashboard"))


@app.errorhandler(500)
def internal_error(_error):
    db.session.rollback()
    return "IntegrityX encountered a server error. Check deployment logs and DATABASE_URL configuration.", 500


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))

    
    
       

