import hashlib
import json
import os
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_TITLE = "Forensic File Baseline Checker"
MANIFEST_FORMAT = "Forensic File Integrity Baseline"
CHUNK_SIZE = 1024 * 1024
BG = "#eef2f7"
NAVY = "#101b2d"
INK = "#1c2a3a"
MUTED = "#617184"
TEAL = "#12b8a6"
BORDER = "#d9e1eb"


def utc_time(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def hash_evidence(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        before = os.fstat(stream.fileno())
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    stable = (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
    return {
        "path": str(Path(path).resolve()),
        "name": Path(path).name,
        "size": after.st_size,
        "modified_utc": utc_time(after.st_mtime),
        "hash": digest.hexdigest(),
        "stable": stable,
    }


class ForensicBaselineChecker(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1050x850")
        self.minsize(880, 760)
        self.configure(bg=BG)
        self.case_id = tk.StringVar()
        self.examiner = tk.StringVar()
        self.evidence_id = tk.StringVar()
        self.trusted_path = tk.StringVar()
        self.current_path = tk.StringVar()
        self.manifest_path = tk.StringVar()
        self.trusted_meta = None
        self.current_meta = None
        self.last_report = None
        self._style()
        self._build()

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TButton", font=("Segoe UI", 9, "bold"), padding=(11, 7))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(14, 9), background="#087f8c", foreground="white")
        style.map("Primary.TButton", background=[("active", "#066773"), ("disabled", "#a6b5c4")], foreground=[("disabled", "#f5f7fa")])
        style.configure("TEntry", padding=(7, 6), fieldbackground="white")

    def _build(self):
        header = tk.Frame(self, bg=NAVY, padx=26, pady=18)
        header.pack(fill="x")
        title_row = tk.Frame(header, bg=NAVY)
        title_row.pack(fill="x")
        tk.Label(title_row, text="FORENSIC FILE BASELINE CHECKER", bg=NAVY, fg="white", font=("Segoe UI", 18, "bold")).pack(side="left")
        tk.Label(title_row, text="EVIDENCE INTEGRITY  •  SHA-256", bg="#20334d", fg="#9fe7df", font=("Segoe UI", 8, "bold"), padx=11, pady=7).pack(side="right")
        tk.Label(header, text="Create a hash reference for a trusted file, then verify a later copy against that reference.", bg=NAVY, fg="#b8c6d8", font=("Segoe UI", 9)).pack(anchor="w", pady=(6, 0))

        body = tk.Frame(self, bg=BG, padx=22, pady=16)
        body.pack(fill="both", expand=True)
        self._section_label(body, "CASE CONTEXT", "These identifiers are recorded in the baseline and exported report.")
        context = tk.Frame(body, bg="white", padx=12, pady=10, highlightbackground=BORDER, highlightthickness=1)
        context.pack(fill="x", pady=(6, 12))
        self._context_entry(context, "CASE / REFERENCE ID", self.case_id, 0)
        self._context_entry(context, "EXAMINER / ANALYST", self.examiner, 1)
        self._context_entry(context, "EVIDENCE ITEM ID", self.evidence_id, 2)

        self._section_label(body, "01  CREATE TRUSTED BASELINE", "Select the known-good original and save its hash record as a JSON manifest.")
        self.trusted_card = self._file_card(body, "TRUSTED ORIGINAL", self.trusted_path, self.choose_trusted)
        self.save_button = ttk.Button(body, text="Calculate SHA-256 & Save Baseline…", style="Primary.TButton", command=self.save_baseline)
        self.save_button.pack(anchor="w", pady=(7, 12))

        self._section_label(body, "02  VERIFY FILE AGAINST BASELINE", "Select the current file and the saved JSON manifest, then compare hashes.")
        self.current_card = self._file_card(body, "CURRENT FILE TO VERIFY", self.current_path, self.choose_current)
        self._manifest_card(body)
        actions = tk.Frame(body, bg=BG)
        actions.pack(fill="x", pady=(7, 10))
        self.check_button = ttk.Button(actions, text="Verify Against Baseline", style="Primary.TButton", command=self.compare_baseline)
        self.check_button.pack(side="left")
        self.export_button = ttk.Button(actions, text="Export Verification Report…", command=self.export_report, state="disabled")
        self.export_button.pack(side="left", padx=(9, 0))
        self.status = tk.StringVar(value="READY  •  Start by choosing a trusted original file.")
        tk.Label(actions, textvariable=self.status, bg=BG, fg=MUTED, font=("Segoe UI", 8), anchor="e", wraplength=390, justify="right").pack(side="right", fill="x", expand=True, padx=(12, 0))

        result = tk.Frame(body, bg="white", padx=14, pady=12, highlightbackground=BORDER, highlightthickness=1)
        result.pack(fill="both", expand=True)
        tk.Label(result, text="VERIFICATION RESULT", bg="white", fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.verdict = tk.Label(result, text="AWAITING VERIFICATION", bg="white", fg="#546579", font=("Segoe UI", 16, "bold"), anchor="w")
        self.verdict.pack(fill="x", pady=(5, 8))
        self.result_text = tk.Text(result, height=7, wrap="word", bg="#f7f9fc", fg=INK, relief="flat", padx=10, pady=8, font=("Consolas", 8), state="disabled")
        self.result_text.pack(fill="both", expand=True)
        tk.Label(body, text="Local file hashing only. This tool does not acquire a forensic image, validate the source of a baseline, or create a signed chain-of-custody record.", bg=BG, fg=MUTED, font=("Segoe UI", 8), wraplength=980, justify="left").pack(anchor="w", pady=(8, 0))

    def _section_label(self, parent, title, subtitle):
        tk.Label(parent, text=title, bg=BG, fg=INK, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        tk.Label(parent, text=subtitle, bg=BG, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))

    def _context_entry(self, parent, label, variable, column):
        frame = tk.Frame(parent, bg="white")
        frame.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 10, 0))
        parent.columnconfigure(column, weight=1)
        tk.Label(frame, text=label, bg="white", fg=MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w")
        ttk.Entry(frame, textvariable=variable).pack(fill="x", pady=(4, 0))

    def _file_card(self, parent, title, variable, command):
        card = tk.Frame(parent, bg="white", padx=12, pady=9, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", pady=(6, 0))
        tk.Label(card, text=title, bg="white", fg="#087f8c", font=("Segoe UI", 8, "bold")).grid(row=0, column=0, sticky="w", columnspan=2)
        path_label = tk.Label(card, text="No file selected", bg="white", fg=INK, font=("Segoe UI", 9, "bold"), anchor="w", wraplength=700, justify="left")
        path_label.grid(row=1, column=0, sticky="ew", pady=(5, 0), padx=(0, 10))
        details_label = tk.Label(card, text="File size: —     Last modified (UTC): —", bg="white", fg=MUTED, font=("Segoe UI", 8), anchor="w")
        details_label.grid(row=2, column=0, sticky="ew", pady=(3, 0))
        button = ttk.Button(card, text="Browse…", command=command)
        button.grid(row=1, column=1, rowspan=2)
        card.columnconfigure(0, weight=1)
        variable.trace_add("write", lambda *_args, v=variable, p=path_label, d=details_label: self._show_file_meta(v.get(), p, d))
        return card

    def _manifest_card(self, parent):
        card = tk.Frame(parent, bg="white", padx=12, pady=9, highlightbackground=BORDER, highlightthickness=1)
        card.pack(fill="x", pady=(7, 0))
        tk.Label(card, text="SAVED BASELINE MANIFEST", bg="white", fg="#087f8c", font=("Segoe UI", 8, "bold")).grid(row=0, column=0, sticky="w", columnspan=2)
        ttk.Entry(card, textvariable=self.manifest_path, state="readonly").grid(row=1, column=0, sticky="ew", pady=(5, 0), padx=(0, 10))
        ttk.Button(card, text="Browse…", command=self.choose_manifest).grid(row=1, column=1, pady=(5, 0))
        card.columnconfigure(0, weight=1)

    def _show_file_meta(self, path, path_label, details_label):
        if not path:
            path_label.configure(text="No file selected")
            details_label.configure(text="File size: —     Last modified (UTC): —")
            return
        try:
            stat = Path(path).stat()
            path_label.configure(text=path)
            details_label.configure(text=f"{Path(path).name}  •  {stat.st_size:,} bytes  •  Modified {utc_time(stat.st_mtime)}")
        except OSError:
            path_label.configure(text=path)
            details_label.configure(text="File metadata is unavailable.")

    def choose_trusted(self):
        path = filedialog.askopenfilename(title="Select trusted original evidence file")
        if path:
            self.trusted_path.set(path)
            self.last_report = None
            self.export_button.configure(state="disabled")

    def choose_current(self):
        path = filedialog.askopenfilename(title="Select current file to verify")
        if path:
            self.current_path.set(path)
            self.last_report = None
            self.export_button.configure(state="disabled")

    def choose_manifest(self):
        path = filedialog.askopenfilename(title="Select saved baseline manifest", filetypes=[("Baseline JSON", "*.json"), ("All files", "*.*")])
        if path:
            self.manifest_path.set(path)
            self.last_report = None
            self.export_button.configure(state="disabled")

    def save_baseline(self):
        trusted = self.trusted_path.get()
        if not trusted:
            messagebox.showinfo("Evidence required", "Select the trusted original file first.")
            return
        if not self.case_id.get().strip() and not messagebox.askyesno("Case reference", "No case/reference ID was entered. Save the baseline without one?"):
            return
        target = filedialog.asksaveasfilename(title="Save baseline manifest", initialfile=Path(trusted).name + ".baseline.json", defaultextension=".json", filetypes=[("JSON baseline", "*.json")])
        if not target:
            return
        context = {
            "caseId": self.case_id.get().strip(),
            "examiner": self.examiner.get().strip(),
            "evidenceId": self.evidence_id.get().strip(),
        }
        self.last_report = None
        self._set_busy(True, "ACQUIRING HASH  •  Reading trusted original…")

        def work():
            try:
                evidence = hash_evidence(trusted)
                manifest = {
                    "format": MANIFEST_FORMAT,
                    "version": 1,
                    "algorithm": "SHA-256",
                    "caseId": context["caseId"],
                    "examiner": context["examiner"],
                    "evidenceId": context["evidenceId"],
                    "createdUtc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "evidence": {key: evidence[key] for key in ("path", "name", "size", "modified_utc", "hash")},
                    "fileStableDuringHash": evidence["stable"],
                }
                target_path = Path(target)
                temp_path = target_path.with_suffix(target_path.suffix + ".tmp")
                temp_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
                temp_path.replace(target_path)
                result = (manifest, None)
            except (OSError, TypeError) as exc:
                result = (None, str(exc))
            self.after(0, lambda: self._saved(target, result))

        threading.Thread(target=work, daemon=True).start()

    def _saved(self, target, result):
        manifest, error = result
        self._set_busy(False, "READY")
        if error:
            self.verdict.configure(text="BASELINE SAVE ERROR", fg="#b42318")
            self._set_result_text(error)
            return
        self.manifest_path.set(target)
        self.trusted_meta = manifest["evidence"]
        if not manifest["fileStableDuringHash"]:
            self.verdict.configure(text="BASELINE CREATED — FILE CHANGED DURING HASH", fg="#b54708")
        else:
            self.verdict.configure(text="BASELINE CREATED", fg="#087f5b")
        self.status.set("BASELINE RECORD SAVED  •  Keep the JSON manifest with the case records.")
        evidence = manifest["evidence"]
        self._set_result_text(self._format_baseline(manifest, evidence))

    def _format_baseline(self, manifest, evidence):
        return (f"CASE / REFERENCE: {manifest['caseId'] or 'Not provided'}\n"
                f"EXAMINER / ANALYST: {manifest['examiner'] or 'Not provided'}\n"
                f"EVIDENCE ITEM ID: {manifest['evidenceId'] or 'Not provided'}\n"
                f"BASELINE CREATED: {manifest['createdUtc']}\n\n"
                f"ORIGINAL: {evidence['name']}\nPATH: {evidence['path']}\nSIZE: {evidence['size']:,} bytes  |  MODIFIED: {evidence['modified_utc']}\n"
                f"SHA-256: {evidence['hash']}\n\nMANIFEST: {self.manifest_path.get()}")

    def compare_baseline(self):
        current, manifest_path = self.current_path.get(), self.manifest_path.get()
        if not current or not manifest_path:
            messagebox.showinfo("Evidence required", "Select the current file and a saved baseline manifest.")
            return
        self.last_report = None
        self._set_busy(True, "VERIFYING EVIDENCE  •  Calculating SHA-256…")

        def work():
            try:
                manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8-sig"))
                if not isinstance(manifest, dict) or manifest.get("format") != MANIFEST_FORMAT or manifest.get("version") != 1 or manifest.get("algorithm") != "SHA-256":
                    raise ValueError("This is not a supported forensic baseline manifest.")
                original = manifest.get("evidence")
                if not isinstance(original, dict):
                    raise ValueError("The baseline manifest has no evidence record.")
                baseline_hash = original.get("hash", "")
                if not isinstance(baseline_hash, str) or len(baseline_hash) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in baseline_hash):
                    raise ValueError("The baseline manifest contains an invalid SHA-256 hash.")
                current_info = hash_evidence(current)
                result = (manifest, current_info, baseline_hash.lower(), None)
            except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
                result = (None, None, None, str(exc))
            self.after(0, lambda: self._compared(result))

        threading.Thread(target=work, daemon=True).start()

    def _compared(self, result):
        manifest, current, baseline_hash, error = result
        self._set_busy(False, "READY")
        if error:
            self.verdict.configure(text="VERIFICATION ERROR", fg="#b42318")
            self._set_result_text(error)
            return
        original = manifest["evidence"]
        stable = manifest.get("fileStableDuringHash", True) and current["stable"]
        same = current["hash"] == baseline_hash
        if not stable:
            verdict, color = "INCONCLUSIVE — FILE CHANGED DURING HASH", "#b54708"
            detail = "At least one file changed while being read. Repeat verification after the file is stable."
        elif same:
            verdict, color = "MATCH — HASH VERIFIED", "#087f5b"
            detail = "The current file's SHA-256 matches the value in the selected baseline manifest."
        else:
            verdict, color = "MISMATCH — CONTENTS DIFFER", "#b42318"
            detail = "The current file's SHA-256 differs from the selected baseline manifest."
        self.verdict.configure(text=verdict, fg=color)
        self.status.set("VERIFICATION COMPLETE  •  SHA-256 comparison finished.")
        self.last_report = {"manifest": manifest, "current": current, "baseline_hash": baseline_hash, "verdict": verdict, "detail": detail, "verified_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
        self.export_button.configure(state="normal")
        self._set_result_text(self._format_verification(self.last_report))

    def _format_verification(self, report):
        manifest, current = report["manifest"], report["current"]
        original = manifest["evidence"]
        return (f"{report['detail']}\n\n"
                f"CASE / REFERENCE: {manifest.get('caseId') or 'Not provided'}\n"
                f"EXAMINER / ANALYST: {manifest.get('examiner') or 'Not provided'}\n"
                f"EVIDENCE ITEM ID: {manifest.get('evidenceId') or 'Not provided'}\n"
                f"BASELINE CREATED: {manifest.get('createdUtc', 'Unknown')}\nVERIFIED: {report['verified_utc']}\n\n"
                f"BASELINE FILE: {original.get('name', 'Unknown')}\nSIZE: {original.get('size', 'Unknown')} bytes  |  MODIFIED: {original.get('modified_utc', 'Unknown')}\nSHA-256: {report['baseline_hash']}\n\n"
                f"CURRENT FILE: {current['name']}\nPATH: {current['path']}\nSIZE: {current['size']:,} bytes  |  MODIFIED: {current['modified_utc']}\nSHA-256: {current['hash']}")

    def _set_result_text(self, text):
        self.result_text.configure(state="normal")
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", text)
        self.result_text.configure(state="disabled")

    def export_report(self):
        if not self.last_report:
            return
        target = filedialog.asksaveasfilename(title="Export verification report", defaultextension=".txt", initialfile="evidence_baseline_verification.txt", filetypes=[("Text report", "*.txt"), ("All files", "*.*")])
        if not target:
            return
        try:
            Path(target).write_text("DIGITAL EVIDENCE BASELINE VERIFICATION REPORT\n" + "=" * 48 + "\n\n" + self._format_verification(self.last_report), encoding="utf-8")
            messagebox.showinfo("Report exported", f"Report saved to:\n{target}")
        except OSError as exc:
            messagebox.showerror("Export error", str(exc))

    def _set_busy(self, busy, text):
        for child in self.winfo_children():
            self._set_controls(child, "disabled" if busy else "normal")
        self.export_button.configure(state="disabled" if busy or not self.last_report else "normal")
        self.status.set(text)

    def _set_controls(self, widget, state):
        if isinstance(widget, ttk.Button):
            if widget is not self.export_button:
                widget.configure(state=state)
        for child in widget.winfo_children():
            self._set_controls(child, state)


if __name__ == "__main__":
    ForensicBaselineChecker().mainloop()
