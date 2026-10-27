import os
import io
import re
import csv
import json
import zlib
import hashlib
import zipfile
import struct
import time
import xml.etree.ElementTree as ET

import requests
from datetime import datetime, timezone, timedelta
from functools import wraps, lru_cache
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


class ScanReport(db.Model):
    """Full per-file scan report (JSON). New table: existing tables keep their columns."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    scan_event_id = db.Column(db.Integer)
    baseline_id = db.Column(db.Integer)
    filename = db.Column(db.String(255), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    verdict = db.Column(db.String(40), nullable=False)
    report_json = db.Column(db.Text, nullable=False)
    created = db.Column(db.String(40), nullable=False)


with app.app_context():
    db.create_all()


def logged(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


# ----- Evidence screening engine -----
# Pure functions (no database access) so every check can be unit-tested on its own.
# IMPORTANT: this is screening, not a full antivirus. "Not detected" never means "safe".

EICAR_SIGNATURE = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
                   b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
                   b"!$H+H*")
KNOWN_BAD_HASHES = {hashlib.sha256(EICAR_SIGNATURE).hexdigest(): "EICAR Standard Anti-Virus Test File"}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".msi",
    ".com", ".pif", ".jar", ".lnk", ".reg", ".sh", ".docm", ".xlsm", ".pptm",
}
SUSPICIOUS_TEXT_MARKERS = [
    b"powershell -enc", b"powershell -e ", b"powershell.exe -nop", b"invoke-expression", b"downloadstring(",
    b"frombase64string(", b"wscript.shell", b"cmd.exe /c", b"mshta ", b"regsvr32 /s", b"certutil -urlcache",
    b"vbscript:", b"createobject(\"wscript.shell\")",
]
DOUBLE_EXT_RE = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|zip)\.(exe|scr|bat|cmd|js|vbs|ps1|com|hta|pif|lnk)$", re.I)

# Expected content family for a file extension. Used for extension-vs-content mismatch detection.
EXT_FAMILY = {
    ".jpg": "jpeg", ".jpeg": "jpeg", ".png": "png", ".gif": "gif", ".bmp": "bmp", ".webp": "webp",
    ".tif": "tiff", ".tiff": "tiff", ".pdf": "pdf", ".zip": "zip", ".docx": "docx", ".xlsx": "xlsx",
    ".pptx": "pptx", ".docm": "docx", ".xlsm": "xlsx", ".pptm": "pptx", ".doc": "ole", ".xls": "ole",
    ".ppt": "ole", ".msi": "ole", ".gz": "gzip", ".wav": "wav", ".mp3": "mp3", ".exe": "pe", ".dll": "pe",
    ".scr": "pe", ".txt": "text", ".csv": "text", ".json": "text", ".xml": "text", ".log": "text",
    ".md": "text", ".html": "text", ".htm": "text",
}
TYPE_LABELS = {
    "jpeg": "JPEG image", "png": "PNG image", "gif": "GIF image", "bmp": "BMP image", "webp": "WebP image",
    "tiff": "TIFF image", "pdf": "PDF document", "zip": "ZIP archive", "docx": "Word document (OOXML)",
    "xlsx": "Excel workbook (OOXML)", "pptx": "PowerPoint (OOXML)", "jar": "Java archive (JAR)",
    "apk": "Android package (APK)", "ole": "Legacy Office/OLE container", "gzip": "GZIP archive",
    "wav": "WAV audio", "mp3": "MP3 audio", "pe": "Windows executable (PE)", "elf": "Linux executable (ELF)",
    "macho": "macOS executable (Mach-O)", "rar": "RAR archive", "7z": "7-Zip archive", "text": "Plain text",
    "unknown": "Unknown binary/format", "empty": "Empty file",
}
IMAGE_FORMATS = {"jpeg", "png", "gif", "bmp", "webp", "tiff"}
VALIDATABLE = IMAGE_FORMATS | {"pdf", "zip", "docx", "xlsx", "pptx", "ole", "gzip", "wav"}
OOXML_REQUIRED = {
    "docx": ("[Content_Types].xml", "word/document.xml"),
    "xlsx": ("[Content_Types].xml", "xl/workbook.xml"),
    "pptx": ("[Content_Types].xml", "ppt/presentation.xml"),
}
EDITING_SOFTWARE_RE = re.compile(
    r"photoshop|lightroom|gimp|snapseed|pixelmator|affinity|paint\.net|canva|facetune|picsart|capture one|"
    r"luminar|darktable|stable diffusion|midjourney|dall-?e|firefly|adobe|photoscape|fotor|inpaint", re.I)
AI_PNG_KEYS = {"parameters", "prompt", "workflow", "invokeai_metadata", "sd-metadata", "dream"}
SCREENING_NOTICE = ("Local signature/heuristic screening only. 'Not detected' does not mean the file is safe or "
                    "clean, and unknown malware cannot be ruled out. Image checks cannot confirm or exclude manipulation.")


def clean_filename(name):
    """Keep a readable (Unicode-friendly) base name; strip paths and control characters."""
    name = (name or "").replace("\\", "/").split("/")[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
    return name[:255] or "evidence-file"


def human_size(n):
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def file_ext(filename):
    return os.path.splitext(filename.lower())[1]


def _extra_known_bad():
    """Optional operator-supplied hashes: KNOWN_BAD_SHA256='hash:label,hash2:label2'."""
    found = {}
    for item in os.environ.get("KNOWN_BAD_SHA256", "").split(","):
        digest, _, label = item.strip().partition(":")
        digest = digest.strip().lower()
        if len(digest) == 64:
            found[digest] = label.strip() or "Operator-supplied known-bad hash"
    return found


@lru_cache(maxsize=1)
def _magika_instance():
    from magika import Magika
    return Magika()


def identify_file_type(data):
    """Optional AI-based file identification via Magika when the package is installed."""
    try:
        identified = _magika_instance().identify_bytes(data)
        output = getattr(identified, "output", None)
        label = getattr(output, "label", None) or getattr(output, "ct_label", None)
        return str(label) if label else "Identified (label unavailable)"
    except ImportError:
        return "Unavailable (install magika package)"
    except Exception:
        return "Inconclusive (file type model error)"


def looks_text(sample):
    if not sample or b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError as exc:
        if exc.start >= len(sample) - 3:  # sample cut in the middle of a multi-byte character
            return True
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b < 127)
    return printable / len(sample) > 0.95


def zip_member_names(data):
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return [i.filename for i in zf.infolist()[:5000]]
    except Exception:
        return None


def sniff_type(data):
    """Identify the real content type from signatures (independent of the file name)."""
    if not data:
        return "empty"
    head = data[:16]
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if b"%PDF-" in data[:1024]:
        return "pdf"
    if head.startswith(b"MZ"):
        return "pe"
    if head.startswith(b"\x7fELF"):
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "macho"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if head[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if head[:4] == b"RIFF" and data[8:12] == b"WAVE":
        return "wav"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if head.startswith(b"BM") and len(data) >= 26 and data[6:10] == b"\x00\x00\x00\x00":
        return "bmp"
    if head.startswith(b"ID3") or (len(head) > 1 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0):
        return "mp3"
    if head.startswith(b"Rar!"):
        return "rar"
    if head.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        names = zip_member_names(data) or []
        lowered = {n.lower() for n in names}
        if "word/document.xml" in lowered:
            return "docx"
        if "xl/workbook.xml" in lowered:
            return "xlsx"
        if "ppt/presentation.xml" in lowered:
            return "pptx"
        if "meta-inf/manifest.mf" in lowered:
            return "jar"
        if "androidmanifest.xml" in lowered:
            return "apk"
        return "zip"
    if looks_text(data[:4096]):
        return "text"
    return "unknown"


def type_mismatch(ext, sniffed):
    """Return a description when the extension and the real content disagree, else None."""
    expected = EXT_FAMILY.get(ext)
    if not expected or sniffed in ("empty", "unknown"):
        return None
    if expected == sniffed:
        return None
    if expected in ("docx", "xlsx", "pptx") and sniffed == "zip":
        return None  # structure problem, reported by the corruption check instead
    if expected == "zip" and sniffed in ("docx", "xlsx", "pptx", "jar", "apk"):
        return None
    if expected == "text" and sniffed == "text":
        return None
    return (f"Extension '{ext}' suggests {TYPE_LABELS.get(expected, expected)}, but the content is "
            f"{TYPE_LABELS.get(sniffed, sniffed)}")


# ----- Corruption / structural validation -----
def _jpeg_structure(data):
    problems, info = [], {}
    n = len(data)
    if not data.startswith(b"\xff\xd8\xff"):
        return ["Missing JPEG start-of-image marker (FFD8FF)"], info
    i, seen_sof, seen_sos, eoi_at = 2, False, False, None
    while i < n:
        k = data.find(b"\xff", i)
        if k == -1:
            break
        j = k + 1
        while j < n and data[j] == 0xFF:
            j += 1
        if j >= n:
            break
        marker = data[j]
        i = j + 1
        if marker in (0x00, 0x01) or 0xD0 <= marker <= 0xD8:
            continue
        if marker == 0xD9:
            eoi_at = i
            break
        if i + 2 > n:
            problems.append("JPEG segment header is cut off (file truncated)")
            break
        seg_len = (data[i] << 8) | data[i + 1]
        if seg_len < 2 or i + seg_len > n:
            problems.append("JPEG segment extends beyond end of file (truncated or damaged)")
            break
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC) and seg_len >= 8:
            info["height"] = (data[i + 3] << 8) | data[i + 4]
            info["width"] = (data[i + 5] << 8) | data[i + 6]
            seen_sof = True
        if marker == 0xDA:
            seen_sos = True
        i += seg_len
    if not problems:
        if not seen_sof:
            problems.append("JPEG has no frame header (SOF); image structure is incomplete")
        elif not seen_sos:
            problems.append("JPEG has no scan data (SOS); image structure is incomplete")
        elif eoi_at is None:
            problems.append("JPEG end-of-image marker (FFD9) is missing; file is likely truncated")
    if eoi_at is not None:
        info["trailing"] = n - eoi_at
    return problems, info


def _png_structure(data):
    problems, info = [], {}
    n = len(data)
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ["Missing PNG signature"], info
    view = memoryview(data)
    pos, first, seen_idat, seen_iend, crc_errors = 8, True, False, False, 0
    text_keys = []
    while pos + 8 <= n:
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        ctype = bytes(view[pos + 4:pos + 8])
        end = pos + 12 + length
        if end > n:
            problems.append(f"PNG chunk {ctype.decode('latin-1')!r} runs past end of file (truncated)")
            break
        stored = struct.unpack(">I", data[end - 4:end])[0]
        if (zlib.crc32(view[pos + 4:end - 4]) & 0xFFFFFFFF) != stored:
            crc_errors += 1
            if crc_errors <= 3:
                problems.append(f"PNG chunk {ctype.decode('latin-1')!r} has a bad CRC (data damaged)")
        if first and ctype != b"IHDR":
            problems.append("PNG does not start with an IHDR chunk")
        if ctype == b"IHDR" and length >= 8:
            info["width"], info["height"] = struct.unpack(">II", data[pos + 8:pos + 16])
        if ctype == b"IDAT":
            seen_idat = True
        if ctype in (b"tEXt", b"iTXt", b"zTXt"):
            text_keys.append(data[pos + 8:pos + 8 + min(length, 40)].split(b"\x00")[0].decode("latin-1"))
        first = False
        pos = end
        if ctype == b"IEND":
            seen_iend = True
            break
    if not seen_idat:
        problems.append("PNG has no image data (IDAT) chunk")
    if not seen_iend:
        problems.append("PNG IEND end chunk is missing (file incomplete)")
    else:
        info["trailing"] = n - pos
    if crc_errors > 3:
        problems.append(f"{crc_errors} PNG chunks failed CRC verification in total")
    info["text_keys"] = text_keys
    return problems, info


def _pillow_decode(data):
    """Full image decode. Returns (state, detail): ok / error / skipped / unavailable."""
    try:
        from PIL import Image
    except ImportError:
        return "unavailable", None
    try:
        with Image.open(io.BytesIO(data)) as im:
            if im.size[0] * im.size[1] > 60_000_000:
                return "skipped", "image has more than 60 megapixels; full decode skipped for safety"
            im.load()
        return "ok", None
    except Exception as exc:
        if "DecompressionBomb" in type(exc).__name__:
            return "skipped", "image is extremely large (possible decompression bomb); full decode skipped"
        return "error", f"{type(exc).__name__}: {str(exc)[:140]}"


def _pdf_checks(data, out):
    head, tail = data[:1024], data[-2048:]
    if b"%PDF-" not in head:
        out["problems"].append("Missing %PDF- header")
    if b"%%EOF" not in tail:
        out["problems"].append("Missing %%EOF end marker (PDF likely truncated)")
    if b"startxref" not in tail:
        out["problems"].append("Missing startxref pointer (cross-reference table cannot be located)")
    out["validated_by"].append("PDF header/trailer markers")
    try:
        from pypdf import PdfReader
    except ImportError:
        out["notes"].append("pypdf not installed: deep PDF structure check was not performed")
        return
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            out["notes"].append("PDF is encrypted/password-protected; page structure could not be validated")
            out["limits"].append("Encrypted PDF content could not be inspected")
            return
        pages = len(reader.pages)
        if pages == 0:
            out["problems"].append("PDF contains no readable pages")
        else:
            _ = reader.pages[0].mediabox
            out["validated_by"].append(f"pypdf parse ({pages} page(s) located)")
            out["info"]["pages"] = pages
    except Exception as exc:
        out["problems"].append("PDF parser could not read the document structure (" + type(exc).__name__ + ")")


def _xml_wellformed(raw):
    if len(raw) > 5 * 1024 * 1024 or b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        return True  # skipped on purpose (size / entity-expansion safety)
    try:
        ET.fromstring(raw)
        return True
    except ET.ParseError:
        return False


def _zip_checks(data, kind, out):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:
        out["problems"].append("Archive/container is corrupt or unreadable (invalid ZIP structure)")
        return
    with zf:
        infos = zf.infolist()
        names = {i.filename for i in infos}
        encrypted = any(i.flag_bits & 0x1 for i in infos)
        total = sum(i.file_size for i in infos)
        out["info"]["members"] = len(infos)
        if encrypted:
            out["notes"].append("Archive has password-protected members; CRC test skipped for them")
            out["limits"].append("Encrypted archive members could not be inspected")
        elif total > 300 * 1024 * 1024:
            out["notes"].append("Archive expands to more than 300 MB; full CRC test skipped for safety")
        else:
            try:
                bad = zf.testzip()
                if bad:
                    out["problems"].append("Archive CRC error in member: " + str(bad)[:120])
                else:
                    out["validated_by"].append(f"ZIP central directory + CRC test ({len(infos)} member(s))")
            except Exception as exc:
                out["problems"].append("Archive member could not be read (" + type(exc).__name__ + ")")
        if kind in OOXML_REQUIRED:
            missing = [p for p in OOXML_REQUIRED[kind] if p not in names]
            if missing:
                out["problems"].append(f"Office document is missing required part(s): {', '.join(missing)}")
            else:
                out["validated_by"].append("Office (OOXML) required parts present")
                try:
                    main_part = OOXML_REQUIRED[kind][1]
                    for part in ("[Content_Types].xml", main_part):
                        if not _xml_wellformed(zf.read(part)):
                            out["problems"].append(f"Office part '{part}' is not well-formed XML")
                except Exception as exc:
                    out["problems"].append("Office part could not be read (" + type(exc).__name__ + ")")


def _gzip_check(data, out):
    decomp = zlib.decompressobj(31)
    try:
        cap = 64 * 1024 * 1024
        produced = decomp.decompress(data, cap)
        if decomp.eof:
            out["validated_by"].append("GZIP stream + CRC verified")
        elif len(produced) >= cap:
            out["notes"].append("GZIP stream is larger than 64 MB when expanded; verified only up to that limit")
            out["validated_by"].append("GZIP stream (partial)")
        else:
            out["problems"].append("GZIP stream ends early (file truncated)")
    except zlib.error:
        out["problems"].append("GZIP data is corrupt")


def validate_integrity(filename, data, sniffed):
    """Readability + format-specific structural validation. Never claims universal corruption detection."""
    ext = file_ext(filename)
    expected = EXT_FAMILY.get(ext)
    out = {"status": "Unable to verify", "css": "warn", "problems": [], "notes": [], "validated_by": [],
           "limits": [], "info": {}, "format": None}
    if not data:
        out.update(status="Corrupted", css="bad")
        out["problems"].append("File is empty (zero bytes) or could not be read")
        return out
    out["validated_by"].append("File is readable (bytes read successfully)")
    fmt = sniffed if sniffed in VALIDATABLE else (expected if expected in VALIDATABLE else None)
    if expected in OOXML_REQUIRED and sniffed in ("zip", "docx", "xlsx", "pptx"):
        fmt = expected
    out["format"] = fmt
    if fmt == "jpeg":
        out["problems"], out["info"] = _jpeg_structure(data)
        out["validated_by"].append("JPEG marker/segment walk")
    elif fmt == "png":
        out["problems"], out["info"] = _png_structure(data)
        out["validated_by"].append("PNG chunk walk + CRC verification")
    elif fmt == "gif":
        if not data.startswith((b"GIF87a", b"GIF89a")):
            out["problems"].append("Missing GIF header")
        elif not data.rstrip(b"\x00").endswith(b";"):
            out["problems"].append("GIF trailer (;) is missing; file likely truncated")
        out["validated_by"].append("GIF header/trailer")
    elif fmt == "bmp":
        declared = struct.unpack("<I", data[2:6])[0] if len(data) >= 6 else 0
        if not data.startswith(b"BM"):
            out["problems"].append("Missing BMP header")
        elif declared > len(data):
            out["problems"].append("BMP declares a larger size than the file contains (truncated)")
        out["validated_by"].append("BMP header/size field")
    elif fmt == "webp":
        declared = struct.unpack("<I", data[4:8])[0] + 8 if len(data) >= 8 else 0
        if declared > len(data):
            out["problems"].append("WebP declares a larger size than the file contains (truncated)")
        out["validated_by"].append("WebP RIFF size field")
    elif fmt == "wav":
        declared = struct.unpack("<I", data[4:8])[0] + 8 if len(data) >= 8 else 0
        if declared > len(data):
            out["problems"].append("WAV declares a larger size than the file contains (truncated)")
        out["validated_by"].append("WAV RIFF size field")
    elif fmt == "pdf":
        _pdf_checks(data, out)
    elif fmt in ("zip", "docx", "xlsx", "pptx"):
        _zip_checks(data, fmt, out)
    elif fmt == "ole":
        if len(data) < 512:
            out["problems"].append("OLE container is smaller than its 512-byte header")
        out["validated_by"].append("OLE header size")
    elif fmt == "gzip":
        _gzip_check(data, out)
    elif ext == ".json" and sniffed == "text":
        try:
            json.loads(data.decode("utf-8-sig"))
            out["validated_by"].append("JSON parser")
        except Exception:
            out["problems"].append("File is not valid JSON")
    elif ext == ".xml" and sniffed == "text":
        if _xml_wellformed(data):
            out["validated_by"].append("XML well-formedness")
        else:
            out["problems"].append("File is not well-formed XML")
    if fmt in IMAGE_FORMATS:
        state, detail = _pillow_decode(data)
        if state == "ok":
            out["validated_by"].append("Pillow full image decode")
        elif state == "error":
            out["problems"].append("Image decoder could not decode the full image: " + detail)
        elif state == "skipped":
            out["notes"].append(detail)
        else:
            out["notes"].append("Pillow not installed: full image decode was not performed")
    if out["problems"]:
        out.update(status="Corrupted", css="bad")
    elif len(out["validated_by"]) > 1:
        out.update(status="Valid", css="ok")
    else:
        out["notes"].append("No format-specific validator exists for this file type; integrity could not be confirmed")
    return out


# ----- Suspicious-file / malware screening -----
def malware_screen(filename, data, sniffed, sha, corruption, vt_result):
    ext = file_ext(filename)
    indicators, blockers = [], list(corruption.get("limits", []))
    checks = ["Known-bad hash list", "EICAR test signature", "Extension vs real content type",
              "Executable / script content markers"]
    if not data:
        blockers.append("File is empty; nothing to screen")
    known = dict(KNOWN_BAD_HASHES)
    known.update(_extra_known_bad())
    if sha in known:
        indicators.append(f"SHA-256 matches known test/bad hash list: {known[sha]}")
    if data and EICAR_SIGNATURE in data:
        exact = data.strip() == EICAR_SIGNATURE
        indicators.append("EICAR Anti-Virus Test File " + ("detected (exact test file)" if exact else "string embedded in this file")
                          + " (harmless test signature used to validate antivirus-style detection)")
    mismatch = type_mismatch(ext, sniffed)
    if mismatch:
        indicators.append("File type mismatch: " + mismatch)
    if sniffed in ("pe", "elf", "macho"):
        indicators.append(f"Executable binary content detected ({TYPE_LABELS[sniffed]})")
    if data.startswith(b"#!"):
        indicators.append("Script with interpreter line (#!) found")
    if ext in SUSPICIOUS_EXTENSIONS:
        indicators.append(f"Executable, script or macro-enabled file type '{ext}': review before preserving as evidence")
    if DOUBLE_EXT_RE.search(filename):
        indicators.append("Double extension (document-looking name that ends in an executable type)")
    if data and sniffed not in ("pe",) and b"This program cannot be run in DOS mode" in data:
        indicators.append("Embedded Windows executable (PE) content found inside this file")
    lowered = data[:2 * 1024 * 1024].lower()
    hits = [m.decode() for m in SUSPICIOUS_TEXT_MARKERS if m in lowered]
    if hits:
        indicators.append("Suspicious command/script markers found: " + ", ".join(hits[:4]))
    if sniffed == "pdf":
        checks.append("PDF active-content keywords")
        tags = [name for name, pattern in (
            ("/JavaScript", rb"/JavaScript"), ("/JS", rb"/JS(?![A-Za-z])"), ("/Launch", rb"/Launch"),
            ("/OpenAction", rb"/OpenAction"), ("/EmbeddedFile", rb"/EmbeddedFile"), ("/RichMedia", rb"/RichMedia"))
            if re.search(pattern, data)]
        if tags:
            indicators.append("PDF active-content keywords present: " + ", ".join(tags) + " (may run actions/scripts or carry attachments)")
    if sniffed == "ole":
        checks.append("Legacy Office macro marker")
        if b"_VBA_PROJECT" in data or "_VBA_PROJECT".encode("utf-16-le") in data:
            indicators.append("VBA macro project found in legacy Office file")
    if sniffed in ("zip", "docx", "xlsx", "pptx", "jar", "apk"):
        checks.append("Archive member inspection")
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infos = zf.infolist()
                lowered_names = [i.filename.lower() for i in infos]
                if any(n.endswith("vbaproject.bin") for n in lowered_names):
                    indicators.append("Office macro project (vbaProject.bin) found")
                if any("/embeddings/" in n or "/activex/" in n for n in lowered_names):
                    indicators.append("Embedded OLE/ActiveX objects found in Office document")
                exec_members = [i.filename for i in infos if file_ext(i.filename) in SUSPICIOUS_EXTENSIONS and sniffed not in ("jar", "apk")]
                if exec_members:
                    indicators.append("Archive contains executable/script member(s): " + ", ".join(exec_members[:3]))
                total = sum(i.file_size for i in infos)
                if total > 300 * 1024 * 1024 and total > 100 * max(len(data), 1):
                    indicators.append("Extreme archive expansion ratio (possible archive bomb)")
                encrypted_seen = False
                for info in infos[:50]:
                    if info.flag_bits & 0x1:
                        encrypted_seen = True
                        continue
                    if info.is_dir() or info.file_size == 0 or info.file_size > 2 * 1024 * 1024:
                        continue
                    member = zf.read(info)
                    if EICAR_SIGNATURE in member:
                        indicators.append(f"EICAR test signature found inside archive member '{info.filename[:80]}'")
                    elif member.startswith(b"MZ") and file_ext(info.filename) not in SUSPICIOUS_EXTENSIONS:
                        indicators.append(f"Windows executable disguised as archive member '{info.filename[:80]}'")
                if encrypted_seen:
                    blockers.append("Encrypted archive members could not be inspected")
        except Exception:
            blockers.append("Archive contents could not be opened for inspection")
    if corruption.get("status") == "Corrupted" and not indicators:
        blockers.append("File is damaged, so its content may not be fully inspectable")
    vt_match = re.match(r"Completed: (\d+) malicious, (\d+) suspicious", vt_result or "")
    if vt_match:
        checks.append("VirusTotal (external, opt-in)")
        flagged = int(vt_match.group(1)) + int(vt_match.group(2))
        if flagged:
            indicators.append(f"VirusTotal engines flagged this file ({vt_result})")
    if indicators:
        status, css = "Suspicious", "bad"
    elif blockers:
        status, css = "Unable to determine", "warn"
    else:
        status, css = "Not detected", "neutral"
    return {"status": status, "css": css, "indicators": indicators, "blockers": blockers, "checks": checks}


# ----- Image forensics -----
def _clean_meta(value):
    if isinstance(value, bytes):
        value = value.decode("latin-1", "replace")
    return re.sub(r"[\x00-\x1f\x7f]", "", str(value)).strip()[:200]


def _parse_exif_dt(value):
    text = _clean_meta(value)
    for fmt in ("%Y:%m:%d %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def image_forensics(filename, data, fmt, structure):
    result = {"applicable": fmt in IMAGE_FORMATS, "status": "Not applicable", "css": "neutral",
              "metadata": {}, "findings": [], "limitations": []}
    if not result["applicable"]:
        return result
    meta, findings = result["metadata"], result["findings"]
    meta["Format (from content)"] = TYPE_LABELS.get(fmt, fmt)
    width, height = structure.get("width"), structure.get("height")
    exif_readable = False
    try:
        from PIL import Image
        with Image.open(io.BytesIO(data)) as im:
            width, height = im.size
            meta["Pillow format / mode"] = f"{im.format} / {im.mode}"
            dpi = im.info.get("dpi")
            if dpi:
                meta["DPI"] = " x ".join(str(round(float(x))) for x in dpi[:2])
            meta["ICC colour profile"] = "Present" if im.info.get("icc_profile") else "Not present"
            exif = im.getexif()
            exif_readable = True
            sub = {}
            try:
                sub = dict(exif.get_ifd(0x8769))
            except Exception:
                pass
            base = {0x010F: "Camera make", 0x0110: "Camera model", 0x0131: "Software", 0x0132: "Modified (DateTime)",
                    0x0112: "Orientation"}
            subs = {0x9003: "Captured (DateTimeOriginal)", 0x9004: "Digitized (DateTimeDigitized)",
                    0xA002: "EXIF pixel width", 0xA003: "EXIF pixel height", 0xA434: "Lens model"}
            for tag, label in base.items():
                if exif.get(tag) not in (None, ""):
                    meta[label] = _clean_meta(exif.get(tag))
            for tag, label in subs.items():
                if sub.get(tag) not in (None, ""):
                    meta[label] = _clean_meta(sub.get(tag))
            meta["EXIF block"] = "Present" if (len(exif) or sub) else "Not present"
            meta["GPS data"] = "Present (coordinates not displayed)" if 0x8825 in exif else "Not present"
            if fmt == "png":
                for key in im.info:
                    if isinstance(key, str) and key.lower() in AI_PNG_KEYS:
                        findings.append({"level": "warn", "text": f"PNG metadata key '{key}' is typical of AI image-generation tools (informational; not proof)"})
                    if isinstance(key, str) and key.lower() == "software":
                        meta["Software"] = _clean_meta(im.info[key])
    except ImportError:
        result["limitations"].append("Pillow is not installed: EXIF/metadata could not be read")
    except Exception as exc:
        result["limitations"].append("Image could not be opened for metadata extraction (" + type(exc).__name__ + ")")
    if width and height:
        meta["Dimensions (decoded)"] = f"{width} x {height} px"
    software = meta.get("Software", "")
    if software and EDITING_SOFTWARE_RE.search(software):
        findings.append({"level": "warn", "text": f"Software tag '{software}' names editing/generation software (the image was saved by it; not proof of manipulation)"})
    ex_w, ex_h = meta.get("EXIF pixel width"), meta.get("EXIF pixel height")
    if ex_w and ex_h and width and height:
        try:
            pair = (int(ex_w), int(ex_h))
            if pair not in ((width, height), (height, width)):
                findings.append({"level": "warn", "text": f"EXIF declares {pair[0]} x {pair[1]} px but the image is {width} x {height} px (resized, cropped or re-saved)"})
        except ValueError:
            findings.append({"level": "warn", "text": "EXIF pixel dimensions are not valid numbers"})
    captured, modified = meta.get("Captured (DateTimeOriginal)"), meta.get("Modified (DateTime)")
    dt_captured, dt_modified = (_parse_exif_dt(captured) if captured else None), (_parse_exif_dt(modified) if modified else None)
    for label, raw, parsed in (("Captured", captured, dt_captured), ("Modified", modified, dt_modified)):
        if raw and parsed is None:
            findings.append({"level": "warn", "text": f"EXIF '{label}' date is malformed: '{raw}'"})
        elif parsed and parsed > datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1):
            findings.append({"level": "warn", "text": f"EXIF '{label}' date ({raw}) is in the future"})
    if dt_captured and dt_modified and abs((dt_modified - dt_captured).total_seconds()) > 1:
        findings.append({"level": "warn", "text": "EXIF modified time differs from capture time (file was re-saved after capture; also common for harmless edits)"})
    if meta.get("EXIF block") == "Not present":
        findings.append({"level": "info", "text": "No EXIF block present (stripped, or normal for screenshots, exports and social-media images)"})
    trailing = structure.get("trailing")
    if trailing and trailing > 16:
        meta["Bytes after end marker"] = str(trailing)
        findings.append({"level": "warn", "text": f"{trailing} bytes follow the image end marker (appended data; some cameras do this legitimately)"})
    if not exif_readable and not any(f["level"] == "warn" for f in findings):
        result.update(status="Unable to determine", css="warn")
    elif any(f["level"] == "warn" for f in findings):
        result.update(status="Indicators noted (not conclusive)", css="warn")
    else:
        result.update(status="No inconsistencies noted", css="neutral")
    result["limitations"].append("Metadata can be edited or removed. These checks cannot confirm that an image is manipulated, nor prove that it is untouched.")
    return result


# ----- Verdict + report assembly -----
def decide_verdict(corruption, suspicious, duplicate):
    reasons, baseline_refs = [], [r for r in duplicate["references"] if r["kind"] == "baseline"]
    if suspicious["status"] == "Suspicious":
        reasons += suspicious["indicators"]
    if corruption["status"] == "Corrupted":
        reasons += corruption["problems"]
    if baseline_refs:
        reasons.append("Identical content is already saved as " + baseline_refs[0]["label"])
    if suspicious["status"] == "Unable to determine":
        reasons += suspicious["blockers"]
    if suspicious["status"] == "Suspicious":
        code, label, css = "SUSPICIOUS", "REJECTED: suspicious indicators found (no automatic approval)", "bad"
    elif corruption["status"] == "Corrupted":
        code, label, css = "CORRUPTED", "REJECTED: file is corrupted, incomplete or unreadable", "bad"
    elif baseline_refs:
        code, label, css = "DUPLICATE", f"NOT APPROVED: exact duplicate of existing baseline #{baseline_refs[0]['id']}", "warn"
    elif suspicious["status"] == "Unable to determine":
        code, label, css = "REVIEW", "REVIEW REQUIRED: screening was inconclusive (no automatic approval)", "warn"
    else:
        code, label, css = "APPROVED", "APPROVED: passed all checks, eligible for baseline", "ok"
    return {"code": code, "label": label, "css": css, "approved": code == "APPROVED", "reasons": reasons}


def collect_warnings(report):
    warnings = []
    dup, cor, sus, img = report["duplicate"], report["corruption"], report["suspicious"], report["image"]
    if dup["is_duplicate"]:
        warnings.append("Duplicate content: " + dup["summary"])
    warnings += cor["problems"] + cor["notes"]
    if cor["status"] == "Unable to verify":
        warnings.append("Corruption status could not be determined for this file type")
    warnings += sus["indicators"] + sus["blockers"]
    warnings += [f["text"] for f in img["findings"] if f["level"] == "warn"]
    warnings += img["limitations"] if img["applicable"] else []
    seen, unique = set(), []
    for w in warnings:
        if w not in seen:
            seen.add(w)
            unique.append(w)
    return unique


def run_screening(filename, data, duplicate, vt_result="Not requested"):
    """Run the full analysis chain for one file. SHA-256 is always computed first."""
    sha = hashlib.sha256(data).hexdigest()
    ext = file_ext(filename)
    sniffed = sniff_type(data)
    stages = {}

    def stage(name, fallback, fn):
        try:
            stages[name] = fn()
        except Exception as exc:  # a broken analyser must never crash the scan or yield a clean result
            fallback["notes"] = list(fallback.get("notes", [])) + [f"Internal analyser error ({type(exc).__name__})"]
            stages[name] = fallback

    stage("corruption", {"status": "Unable to verify", "css": "warn", "problems": [], "notes": [], "validated_by": [], "limits": [], "info": {}, "format": None},
          lambda: validate_integrity(filename, data, sniffed))
    corruption = stages["corruption"]
    stage("suspicious", {"status": "Unable to determine", "css": "warn", "indicators": [], "blockers": ["Screening failed internally"], "checks": []},
          lambda: malware_screen(filename, data, sniffed, sha, corruption, vt_result))
    stage("image", {"applicable": False, "status": "Unable to determine", "css": "warn", "metadata": {}, "findings": [], "limitations": []},
          lambda: image_forensics(filename, data, corruption.get("format"), corruption.get("info", {})))
    image = stages["image"]
    if image.get("applicable") and corruption.get("status") == "Corrupted":
        image["limitations"].append("Image is damaged or incomplete, so metadata may be missing or unreliable")
        if image["status"] == "No inconsistencies noted":
            image.update(status="Unable to determine", css="warn")
    verdict = decide_verdict(corruption, stages["suspicious"], duplicate)
    report = {
        "filename": filename, "extension": ext, "sha256": sha, "size": len(data), "size_human": human_size(len(data)),
        "detected_type": TYPE_LABELS.get(sniffed, sniffed), "magika": identify_file_type(data) if data else "",
        "scanned_at": stamp(), "duplicate": duplicate, "corruption": corruption, "suspicious": stages["suspicious"],
        "image": stages["image"], "virustotal": vt_result, "verdict": verdict,
        "baseline": {"saved": False, "id": None, "note": "No baseline saved for this scan."},
        "notice": SCREENING_NOTICE,
    }
    report["warnings"] = collect_warnings(report)
    return report


def unreadable_report(filename, reason, duplicate):
    corruption = {"status": "Corrupted", "css": "bad", "problems": ["File could not be read: " + reason], "notes": [],
                  "validated_by": [], "limits": [], "info": {}, "format": None}
    suspicious = {"status": "Unable to determine", "css": "warn", "indicators": [], "blockers": ["File could not be read, so it was not screened"], "checks": []}
    image = {"applicable": False, "status": "Not applicable", "css": "neutral", "metadata": {}, "findings": [], "limitations": []}
    report = {
        "filename": filename, "extension": file_ext(filename), "sha256": "—", "size": 0, "size_human": "0 B",
        "detected_type": "Unavailable", "magika": "", "scanned_at": stamp(), "duplicate": duplicate, "corruption": corruption,
        "suspicious": suspicious, "image": image, "virustotal": "Not scanned",
        "verdict": {"code": "CORRUPTED", "label": "REJECTED: file is corrupted, incomplete or unreadable", "css": "bad",
                    "approved": False, "reasons": corruption["problems"]},
        "baseline": {"saved": False, "id": None, "note": "No baseline saved for this scan."}, "notice": SCREENING_NOTICE,
    }
    report["warnings"] = collect_warnings(report)
    return report


def summarize_report(report):
    """One-line summary stored in ScanEvent.details (full report is stored separately)."""
    parts = [
        "SHA-256 " + report["sha256"], "Type: " + report["detected_type"], "Size: " + report["size_human"],
        "Duplicate: " + report["duplicate"]["summary"], "Validation: " + report["corruption"]["status"],
        "Suspicious screening: " + report["suspicious"]["status"], "Image forensics: " + report["image"]["status"],
        "VirusTotal: " + report["virustotal"],
    ]
    if report["verdict"]["reasons"]:
        parts.append("Findings: " + " | ".join(report["verdict"]["reasons"])[:1500])
    return "; ".join(parts)


def virustotal_scan(filename, data):
    """Optional external scan. Called only after the user explicitly opts in."""
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return "Not configured (set VIRUSTOTAL_API_KEY)"
    if len(data) > 32 * 1024 * 1024:
        return "Not submitted (over 32 MB API upload limit for this workflow)"
    headers = {"x-apikey": api_key}
    try:
        response = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files={"file": (filename, data)},
            timeout=(5, 20),
        )
        if response.status_code == 429:
            return "Rate limited by VirusTotal; retry later"
        response.raise_for_status()
        analysis_id = response.json().get("data", {}).get("id")
        if not analysis_id:
            return "Submitted; analysis ID not returned"
        # Keep polling short for serverless request limits; pending is not a clean verdict.
        deadline = time.time() + 5
        while time.time() < deadline:
            check = requests.get(
                "https://www.virustotal.com/api/v3/analyses/" + analysis_id,
                headers=headers,
                timeout=(3, 5),
            )
            if check.ok:
                attributes = check.json().get("data", {}).get("attributes", {})
                if attributes.get("status") == "completed":
                    stats = attributes.get("stats", {})
                    return f"Completed: {stats.get('malicious', 0)} malicious, {stats.get('suspicious', 0)} suspicious, {stats.get('undetected', 0)} undetected"
            time.sleep(1)
        return "Submitted; analysis pending (not a clean verdict)"
    except requests.RequestException as exc:
        return "Unavailable: VirusTotal request failed (check API key/network/limits)"
    except (ValueError, KeyError, TypeError):
        return "Unavailable: unexpected VirusTotal response"


# ----- Database-backed parts of the scan workflow -----
def find_duplicates(uid, sha, filename, batch_seen, position):
    """Compare a SHA-256 against saved baselines, earlier scans and earlier files in this batch.
    Content (hash) decides, so a different file name or extension does not hide a duplicate."""
    refs = []
    n_base = Baseline.query.filter_by(user_id=uid).count()
    n_scans = ScanEvent.query.filter(ScanEvent.user_id == uid, ScanEvent.sha256 != "—").count()

    def add(kind, rid, other_name, when, lead):
        suffix = ""
        if file_ext(other_name) != file_ext(filename):
            suffix = " · same content under a different extension"
        elif other_name.lower() != filename.lower():
            suffix = " · same content under a different file name"
        refs.append({"kind": kind, "id": rid, "filename": other_name, "when": when,
                     "label": f"{lead} '{other_name}'" + (f" · {when}" if when else "") + suffix})

    for b in Baseline.query.filter_by(user_id=uid, sha256=sha).order_by(Baseline.id.asc()).limit(5).all():
        add("baseline", b.id, b.filename, "saved " + b.created, f"Baseline #{b.id}")
    for s in ScanEvent.query.filter_by(user_id=uid, sha256=sha).order_by(ScanEvent.id.asc()).limit(5).all():
        add("previous_scan", s.id, s.filename, "scanned " + s.scanned, f"Previous scan #{s.id}")
    for earlier_pos, earlier_name in batch_seen.get(sha, []):
        add("batch", earlier_pos, earlier_name, "", f"File #{earlier_pos} in this upload batch")
    batch_seen.setdefault(sha, []).append((position, filename))
    compared = {"baselines": n_base, "scans": n_scans, "batch_files": position - 1}
    if refs:
        summary = f"Exact duplicate: identical SHA-256 to {len(refs)} earlier record(s)."
    else:
        summary = (f"No duplicate detected. Compared against {n_base} saved baseline(s), {n_scans} previously scanned "
                   f"file(s) and {position - 1} earlier file(s) in this batch.")
    return {"is_duplicate": bool(refs), "references": refs, "summary": summary, "compared": compared}


def process_evidence(upload, position, batch_seen, request_vt, approve, case_id, evidence_id):
    """Workflow for one upload: hash -> duplicate/corruption/suspicious/image checks -> verdict
    -> (only if approved AND requested) baseline. Returns (report, stored_report_id)."""
    uid, username = session["uid"], session["username"]
    filename = clean_filename(upload.filename)
    data, error = None, None
    try:
        data = read_upload(upload)
    except ValueError as exc:
        error = str(exc)
    except Exception:
        error = "the upload stream could not be read"
    if error:
        duplicate = {"is_duplicate": False, "references": [], "compared": {}, "summary": "Not compared: the file could not be read."}
        report = unreadable_report(filename, error, duplicate)
    else:
        sha = hashlib.sha256(data).hexdigest()
        duplicate = find_duplicates(uid, sha, filename, batch_seen, position)
        vt_result = virustotal_scan(filename, data) if request_vt else "Not requested"
        report = run_screening(filename, data, duplicate, vt_result)
    verdict = report["verdict"]
    event = ScanEvent(user_id=uid, filename=filename, sha256=report["sha256"], size=report["size"], result=verdict["code"],
                      details=summarize_report(report), scanned=report["scanned_at"])
    db.session.add(event)
    db.session.flush()
    baseline_id = None
    if verdict["approved"] and approve:
        base = Baseline(user_id=uid, case_id=case_id[:100], evidence_id=evidence_id[:100], filename=filename,
                        size=report["size"], sha256=report["sha256"], created=report["scanned_at"])
        db.session.add(base)
        db.session.flush()
        baseline_id = base.id
        verdict["label"] = f"APPROVED: saved as baseline #{base.id}"
        report["baseline"] = {"saved": True, "id": base.id, "note": f"Saved to the baseline database as #{base.id} (SHA-256, size, timestamp and this scan report)."}
        db.session.add(Audit(username=username, event="BASELINE_CREATED", at=stamp()))
    elif verdict["approved"]:
        report["baseline"]["note"] = "Eligible for a baseline, but baseline creation was not requested for this scan."
    else:
        report["baseline"]["note"] = "No automatic approval and no baseline created: " + verdict["label"]
    record = ScanReport(user_id=uid, scan_event_id=event.id, baseline_id=baseline_id, filename=filename, sha256=report["sha256"],
                        verdict=verdict["code"], report_json=json.dumps(report, ensure_ascii=False), created=report["scanned_at"])
    db.session.add(record)
    db.session.flush()
    return report, record.id


REPORT_MACRO = r'''{% macro pill(css, text) %}<span class="pill {{ css }}">{{ text }}</span>{% endmacro %}
{% macro report_card(r, rid=None) %}
<section class="panel">
<div class="hero"><div><h2>{{ r.filename }}</h2><p>{{ pill(r.verdict.css, r.verdict.label) }}</p></div>{% if rid %}<a class="btn" href="{{ url_for('scan_report', rid=rid) }}">Open stored report</a>{% endif %}</div>
<table>
<tr><th style="width:170px">SHA-256</th><td class="hash">{{ r.sha256 }}</td></tr>
<tr><th>File type &amp; size</th><td>Extension: {{ r.extension or 'none' }} · Detected from content: <b>{{ r.detected_type }}</b>{% if r.magika %} · AI identification: {{ r.magika }}{% endif %}<br>Size: {{ r.size_human }} ({{ r.size }} bytes)</td></tr>
<tr><th>Duplicate status</th><td>{{ pill('warn' if r.duplicate.is_duplicate else 'neutral', 'DUPLICATE' if r.duplicate.is_duplicate else 'No duplicate detected') }}<div>{{ r.duplicate.summary }}</div>{% if r.duplicate.references %}<ul>{% for ref in r.duplicate.references %}<li>{{ ref.label }}</li>{% endfor %}</ul>{% endif %}</td></tr>
<tr><th>Corruption / validation</th><td>{{ pill(r.corruption.css, r.corruption.status) }}{% if r.corruption.problems %}<ul>{% for p in r.corruption.problems %}<li>{{ p }}</li>{% endfor %}</ul>{% endif %}{% if r.corruption.notes %}<ul class="muted small">{% for n in r.corruption.notes %}<li>{{ n }}</li>{% endfor %}</ul>{% endif %}<div class="muted small">Checks run: {{ r.corruption.validated_by|join(' · ') or 'none' }}</div></td></tr>
<tr><th>Suspicious-file screening</th><td>{{ pill(r.suspicious.css, r.suspicious.status) }}{% if r.suspicious.indicators %}<ul>{% for i in r.suspicious.indicators %}<li>{{ i }}</li>{% endfor %}</ul>{% endif %}{% if r.suspicious.blockers %}<ul class="muted small">{% for b in r.suspicious.blockers %}<li>{{ b }}</li>{% endfor %}</ul>{% endif %}{% if r.suspicious.status == 'Not detected' %}<div class="muted small">No indicators found by these local checks. This is not a guarantee that the file is safe.</div>{% endif %}<div class="muted small">Checks run: {{ r.suspicious.checks|join(' · ') or 'none' }}</div></td></tr>
<tr><th>Image forensics</th><td>{% if r.image.applicable %}{{ pill(r.image.css, r.image.status) }}{% if r.image.metadata %}<table class="small">{% for k, v in r.image.metadata.items() %}<tr><th style="width:210px">{{ k }}</th><td>{{ v }}</td></tr>{% endfor %}</table>{% endif %}{% if r.image.findings %}<ul>{% for f in r.image.findings %}<li>{{ pill('warn' if f.level == 'warn' else 'neutral', 'Indicator' if f.level == 'warn' else 'Info') }} {{ f.text }}</li>{% endfor %}</ul>{% endif %}{% if r.image.limitations %}<ul class="muted small">{% for l in r.image.limitations %}<li>{{ l }}</li>{% endfor %}</ul>{% endif %}{% else %}<span class="muted">Not applicable (not an image file)</span>{% endif %}</td></tr>
{% if r.virustotal != 'Not requested' %}<tr><th>VirusTotal (opt-in)</th><td>{{ r.virustotal }}</td></tr>{% endif %}
<tr><th>Final verdict</th><td>{{ pill(r.verdict.css, r.verdict.label) }}{% if r.verdict.reasons %}<ul>{% for x in r.verdict.reasons %}<li>{{ x }}</li>{% endfor %}</ul>{% endif %}<div>{{ r.baseline.note }}</div></td></tr>
{% if r.warnings %}<tr><th>Warnings</th><td><ul>{% for w in r.warnings %}<li>{{ w }}</li>{% endfor %}</ul></td></tr>{% endif %}
<tr><th>Scan timestamp</th><td>{{ r.scanned_at }}</td></tr>
</table>
<p class="muted small">{{ r.notice }}</p>
</section>
{% endmacro %}'''


# ----- Small responsive UI embedded in this file (no templates folder required) -----
BASE = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · IntegrityX</title><style>
:root{--bg:#101827;--surface:#172235;--surface-2:#1c2a3f;--line:#34445a;--text:#e7edf5;--muted:#a9b5c6;--blue:#5d91c9;--blue-hover:#76a7dc;--red:#e3a0a5;--green:#9ac7aa}
*{box-sizing:border-box}
html{min-height:100%;background:var(--bg)}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI",Arial, sans-serif;letter-spacing:0}
a{color:#a9c9ec;text-underline-offset:3px}
a:hover{color:#d7e7f8}
.nav{display:flex;gap:18px;align-items:center;justify-content:space-between;padding:13px 4%;border-bottom:1px solid var(--line);background:#121d2d;position:sticky;top:0;z-index:10}
.brand{font-size:18px;font-weight:650;white-space:nowrap;color:#f0f3f8;letter-spacing:.1px}
.brand span:not(.muted){color:#78a8d9}
.links{display:flex;gap:5px;align-items:center;flex-wrap:wrap}
.links a,.btn{display:inline-flex;align-items:center;justify-content:center;color:#e0e8f2;text-decoration:none;border:1px solid #40516a;padding:7px 11px;border-radius:4px;background:#1a2940;cursor:pointer;transition:background .12s,border-color .12s}
.links a:hover,.btn:hover{border-color:#6786aa;background:#233650;color:#fff}
main{max-width:1100px;margin:25px auto;padding:0 22px;min-height:calc(100vh - 165px)}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:5px;padding:20px;margin:14px 0}
.panel h1,.panel h2,.panel h3{margin-top:0;line-height:1.35;letter-spacing:0;font-weight:600;color:#f0f3f8}
h1{font-size:24px}h2{font-size:19px}h3{font-size:16px}
p{margin:9px 0}
.hero{display:flex;justify-content:space-between;gap:18px;align-items:center;flex-wrap:wrap}
.muted{color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(185px,1fr));gap:11px}
.metric{background:#142033;border:1px solid #304159;border-radius:4px;padding:14px}
.metric b{font-size:24px;display:block;color:#c2d8f0;font-weight:600;line-height:1.4}
label{display:block;margin:12px 0 5px;color:#d4deea;font-size:13px;font-weight:600}
input,select,textarea{width:100%;padding:9px 10px;border-radius:4px;background:#101a29;color:var(--text);border:1px solid #40516a;font:inherit;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--blue);box-shadow:0 0 0 2px rgba(93,145,201,.13)}
input[type=file]{padding:8px;background:#121e30}
button{font:inherit}
.btn.primary{background:#315b86;color:#fff;font-weight:600;border-color:#527eac}
.btn.primary:hover{background:#3b6b9c;border-color:#709ac5}
.btn.danger{border-color:#71444a;background:#2a2029;color:#f0c5c8}
.flash{padding:10px 12px;border:1px solid var(--line);border-radius:4px;margin:10px 0;background:#172235}
.flash.success{border-color:#426b50;color:#b9dfc5;background:#172b24}
.flash.error{border-color:#79464b;color:#f0bfc2;background:#302126}
table{width:100%;border-collapse:collapse;overflow-wrap:anywhere;background:transparent}
th,td{text-align:left;padding:10px 9px;border-bottom:1px solid #34445a;vertical-align:top}
th{color:#bdc9d8;background:#142033;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.3px}
tbody tr:hover{background:#1b2a3e}
.pill{display:inline-block;padding:2px 7px;border-radius:3px;background:#22344b;border:1px solid #3b506b;color:#d2deed;font-size:12px}
.small{font-size:12px}
.hash{font-family:Consolas,"Courier New",monospace;overflow-wrap:anywhere;font-size:12px;color:#c7d8e9}
.footer{text-align:center;color:#8e9db1;padding:21px 18px;border-top:1px solid #29384d;font-size:12px}
.two{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:13px}
ul{padding-left:22px}
hr{border:0;border-top:1px solid var(--line)}
@media(max-width:760px){.nav{align-items:flex-start;flex-direction:column;gap:10px}.links{gap:5px}.links a{padding:6px 8px;font-size:13px}main{padding:0 14px;margin:17px auto}.panel{padding:15px}h1{font-size:22px}.grid{grid-template-columns:repeat(auto-fit,minmax(140px,1fr))}table{font-size:12px}th,td{padding:8px 6px}}
.pill.ok{background:#172b24;border-color:#426b50;color:#b9dfc5}.pill.bad{background:#302126;border-color:#79464b;color:#f0bfc2}.pill.warn{background:#2f2a1b;border-color:#7a6a3a;color:#ecd9a0}.pill.neutral{background:#22344b}
td ul{margin:6px 0}td table{margin-top:8px}
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
        report, rid = process_evidence(f, 1, {}, False, True, request.form.get("case_id", "").strip(),
                                       request.form.get("evidence_id", "").strip())
        db.session.add(Audit(username=session["username"], event="BASELINE_SCAN", at=stamp()))
        db.session.commit()
        if report["baseline"]["saved"]:
            flash("Baseline saved after full evidence scan. SHA-256: " + report["sha256"], "success")
        else:
            flash("Baseline NOT created. " + report["verdict"]["label"], "error")
        return redirect(url_for("scan_report", rid=rid))
    body = '''<section class="panel"><h1>Create evidence baseline</h1><p class="muted">Every file goes through the full scan first: SHA-256, duplicate check, corruption validation, suspicious-file screening and image forensics. Only files that pass are saved as a baseline together with their hash, size, timestamp and scan report. Failed, suspicious or inconclusive files are never approved automatically.</p><form method="post" enctype="multipart/form-data"><div class="two"><div><label>Case ID (optional)</label><input name="case_id" maxlength="100" placeholder="e.g. CASE-2026-001"></div><div><label>Evidence ID (optional)</label><input name="evidence_id" maxlength="100" placeholder="e.g. EVD-001"></div></div><label>Select evidence file</label><input type="file" name="file" required><p><button class="btn primary" type="submit">Scan & create baseline</button></p></form></section><section class="panel"><b>Forensic note</b><p class="muted">The SHA-256 hash identifies the exact uploaded bytes. Keep the original evidence and acquisition notes separately; this web tool does not certify chain of custody or prove that a file is malware-free.</p></section>'''
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
        request_vt = request.form.get("use_virustotal") == "yes"
        approve = request.form.get("approve_baseline") == "yes"
        case_id = request.form.get("case_id", "").strip()
        evidence_id = request.form.get("evidence_id", "").strip() if len(files) == 1 else ""
        batch_seen = {}
        for position, f in enumerate(files, start=1):
            results.append(process_evidence(f, position, batch_seen, request_vt, approve, case_id, evidence_id))
        db.session.add(Audit(username=session["username"], event="EVIDENCE_SCAN", at=stamp()))
        db.session.commit()
        counts = defaultdict(int)
        for report, _rid in results:
            counts[report["verdict"]["code"]] += 1
        saved = sum(1 for report, _rid in results if report["baseline"]["saved"])
        flash(f"Scanned {len(results)} file(s): {counts['APPROVED']} approved, {counts['SUSPICIOUS']} suspicious, "
              f"{counts['CORRUPTED']} corrupted/unreadable, {counts['DUPLICATE']} duplicate of a baseline, "
              f"{counts['REVIEW']} need review; {saved} baseline(s) saved.",
              "success" if len(results) == counts["APPROVED"] else "error")
    body = REPORT_MACRO + '''<section class="panel"><h1>Evidence scan</h1><p class="muted">Workflow: upload → file type, size &amp; SHA-256 → duplicate + corruption + suspicious scan → image/document validation → verdict &amp; detailed report → approved evidence can be saved to the baseline database. Rejected or suspicious evidence is never approved automatically.</p><form method="post" enctype="multipart/form-data"><label>Choose one or more evidence files</label><input type="file" name="files" multiple required><div class="two"><div><label>Case ID (optional, used if baselines are saved)</label><input name="case_id" maxlength="100" placeholder="e.g. CASE-2026-001"></div><div><label>Evidence ID (optional, single file only)</label><input name="evidence_id" maxlength="100" placeholder="e.g. EVD-001"></div></div><label style="display:flex;gap:9px;align-items:flex-start;font-weight:500"><input style="width:auto;margin-top:4px" type="checkbox" name="approve_baseline" value="yes"><span>Save files that pass every check as approved baselines (hash, size, timestamp and scan report are stored). Failed, suspicious, duplicate or inconclusive files are never saved.</span></label><label style="display:flex;gap:9px;align-items:flex-start;font-weight:500"><input style="width:auto;margin-top:4px" type="checkbox" name="use_virustotal" value="yes"><span>Also submit these files to VirusTotal for online malware analysis. Only select this if you are authorised to share the evidence with an external service.</span></label><p><button class="btn primary" type="submit">Scan selected evidence</button></p></form><p class="muted small">VirusTotal requires the VIRUSTOTAL_API_KEY environment variable. Optional packages: Pillow (image decode &amp; EXIF), pypdf (deep PDF validation) and magika (AI file identification). Extra known-bad hashes can be supplied via KNOWN_BAD_SHA256="hash:label,hash:label".</p></section>
{% if results %}<section class="panel"><div class="hero"><h2>Scan summary</h2><a class="btn" href="{{ url_for('export_scan_csv') }}">Export scan history CSV</a></div><table><tr><th>File</th><th>Verdict</th><th>Duplicate</th><th>Validation</th><th>Suspicious</th><th>SHA-256</th></tr>{% for r, rid in results %}<tr><td>{{ r.filename }}</td><td>{{ pill(r.verdict.css, r.verdict.code) }}</td><td>{{ 'YES' if r.duplicate.is_duplicate else 'No' }}</td><td>{{ r.corruption.status }}</td><td>{{ r.suspicious.status }}</td><td class="hash small">{{ r.sha256 }}</td></tr>{% endfor %}</table></section>{% for r, rid in results %}{{ report_card(r, rid) }}{% endfor %}{% endif %}
<section class="panel"><h3>What these checks can and cannot say</h3><ul><li><b>Duplicate:</b> exact byte-for-byte match by SHA-256 against saved baselines, earlier scans and this batch. A renamed file or changed extension is still caught; an edited or re-encoded copy is not.</li><li><b>Corruption:</b> format-specific structure checks (JPEG, PNG, GIF, BMP, WebP, PDF, ZIP/Office, GZIP, OLE). Other formats are reported as "Unable to verify"; no universal corruption detector exists.</li><li><b>Suspicious:</b> known hashes, EICAR test signature, extension-vs-content mismatch, executable/script markers, PDF active content and Office macros. <i>Not detected</i> is not a clean bill of health, and unknown malware cannot be ruled out.</li><li><b>Image forensics:</b> EXIF, dimensions, decode validation and metadata inconsistencies are indicators only. They cannot confirm or exclude manipulation.</li></ul></section>'''
    return page("Evidence scan", body, results=results)


@app.route("/scan/report/<int:rid>")
@logged
def scan_report(rid):
    record = ScanReport.query.filter_by(id=rid, user_id=session["uid"]).first_or_404()
    report = json.loads(record.report_json)
    body = REPORT_MACRO + '''<section class="panel hero"><div><h1>Detailed scan report #{{ rid }}</h1><p class="muted">Stored report generated at scan time.</p></div><div><a class="btn" href="{{ url_for('scan_report_json', rid=rid) }}">Download JSON</a> <a class="btn" href="{{ url_for('reports') }}">Back to reports</a></div></section>{{ report_card(report) }}'''
    return page("Scan report", body, report=report, rid=rid)


@app.route("/scan/report/<int:rid>.json")
@logged
def scan_report_json(rid):
    record = ScanReport.query.filter_by(id=rid, user_id=session["uid"]).first_or_404()
    return send_file(io.BytesIO(record.report_json.encode("utf-8")), mimetype="application/json", as_attachment=True,
                     download_name=f"integrityx_scan_report_{rid}.json")


@app.route("/reports")
@logged
def reports():
    uid = session["uid"]
    baselines = Baseline.query.filter_by(user_id=uid).order_by(Baseline.id.desc()).all()
    checks = Check.query.filter_by(user_id=uid).order_by(Check.id.desc()).all()
    scans = ScanEvent.query.filter_by(user_id=uid).order_by(ScanEvent.id.desc()).limit(100).all()
    audits = Audit.query.filter_by(username=session["username"]).order_by(Audit.id.desc()).limit(50).all()
    report_ids = {r.scan_event_id: r.id for r in ScanReport.query.filter_by(user_id=uid).all()}
    body = '''<section class="panel hero"><div><h1>Forensic reports & activity</h1><p class="muted">Export saved baseline records, integrity comparisons, scan findings, and activity logs for this account.</p></div><div><a class="btn primary" href="{{ url_for('export_report', fmt='csv') }}">Download CSV</a> <a class="btn" href="{{ url_for('export_report', fmt='json') }}">Download JSON</a></div></section>
<section class="panel"><h2>Integrity checks</h2>{% if checks %}<table><tr><th>File</th><th>Baseline ID</th><th>Result</th><th>Candidate SHA-256</th><th>Time</th></tr>{% for c in checks %}<tr><td>{{ c.filename }}</td><td>{{ c.baseline_id }}</td><td><span class="pill">{{ c.result }}</span></td><td class="hash small">{{ c.sha256 }}</td><td>{{ c.checked }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">No integrity checks saved.</p>{% endif %}</section>
<section class="panel"><h2>Evidence scan history</h2>{% if scans %}<table><tr><th>File</th><th>Status</th><th>Size</th><th>SHA-256</th><th>Findings</th><th>Time</th><th>Report</th></tr>{% for s in scans %}<tr><td>{{ s.filename }}</td><td>{{ s.result }}</td><td>{{ s.size }} B</td><td class="hash small">{{ s.sha256 }}</td><td>{{ s.details }}</td><td>{{ s.scanned }}</td><td>{% if report_ids.get(s.id) %}<a href="{{ url_for('scan_report', rid=report_ids[s.id]) }}">View</a>{% else %}—{% endif %}</td></tr>{% endfor %}</table>{% else %}<p class="muted">No scan history saved.</p>{% endif %}</section>
<section class="panel"><h2>Recent account activity</h2>{% if audits %}<table><tr><th>Event</th><th>Username</th><th>Time</th></tr>{% for a in audits %}<tr><td>{{ a.event }}</td><td>{{ a.username }}</td><td>{{ a.at }}</td></tr>{% endfor %}</table>{% else %}<p class="muted">No activity logged.</p>{% endif %}</section>'''
    return page("Reports", body, baselines=baselines, checks=checks, scans=scans, audits=audits, report_ids=report_ids)


def report_payload(uid):
    baselines = Baseline.query.filter_by(user_id=uid).order_by(Baseline.id.asc()).all()
    checks = Check.query.filter_by(user_id=uid).order_by(Check.id.asc()).all()
    scans = ScanEvent.query.filter_by(user_id=uid).order_by(ScanEvent.id.asc()).all()
    stored = ScanReport.query.filter_by(user_id=uid).order_by(ScanReport.id.asc()).all()
    return {
        "application": "IntegrityX",
        "generated_at": stamp(),
        "notice": "SHA-256 verifies byte identity. Screening results are indicators only: they are not a full antivirus scan, proof of authenticity, or proof that an image is or is not manipulated.",
        "baselines": [{"id": b.id, "case_id": b.case_id, "evidence_id": b.evidence_id, "filename": b.filename, "size": b.size, "sha256": b.sha256, "created": b.created} for b in baselines],
        "integrity_checks": [{"id": c.id, "baseline_id": c.baseline_id, "filename": c.filename, "size": c.size, "sha256": c.sha256, "result": c.result, "checked": c.checked} for c in checks],
        "scan_reports": [{"id": r.id, "scan_event_id": r.scan_event_id, "baseline_id": r.baseline_id, "verdict": r.verdict, "report": json.loads(r.report_json)} for r in stored],
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
