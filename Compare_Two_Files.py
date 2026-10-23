import hashlib
import os
import threading
import tkinter as tk
from datetime import datetime, timezone
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_TITLE = "Evidence Hash Comparator"
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
    info = {
        "path": str(Path(path).resolve()),
        "name": Path(path).name,
        "size": after.st_size,
        "modified_utc": utc_time(after.st_mtime),
        "hash": digest.hexdigest(),
        "stable": stable,
    }
    return info


class EvidenceHashComparator(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1160x790")
        self.minsize(950, 700)
        self.configure(bg=BG)
        self.case_id = tk.StringVar()
        self.examiner = tk.StringVar()
        self.evidence_ids = [tk.StringVar(), tk.StringVar()]
        self.paths = [tk.StringVar(), tk.StringVar()]
        self.metadata = [None, None]
        self.result_data = None
        self.busy = False
        self._style()
        self._build()

    def _style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TButton", font=("Segoe UI", 9, "bold"), padding=(12, 8))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(15, 10), background="#087f8c", foreground="white")
        style.map("Primary.TButton", background=[("active", "#066773"), ("disabled", "#a6b5c4")], foreground=[("disabled", "#f5f7fa")])
        style.configure("TEntry", padding=(8, 7), fieldbackground="white")

    def _build(self):
        header = tk.Frame(self, bg=NAVY, padx=28, pady=20)
        header.pack(fill="x")
        title_row = tk.Frame(header, bg=NAVY)
        title_row.pack(fill="x")
        tk.Label(title_row, text="EVIDENCE HASH COMPARATOR", bg=NAVY, fg="white", font=("Segoe UI", 19, "bold")).pack(side="left")
        tk.Label(title_row, text="LOCAL ANALYSIS  •  SHA-256", bg="#20334d", fg="#9fe7df", font=("Segoe UI", 9, "bold"), padx=12, pady=7).pack(side="right")
        tk.Label(header, text="Compare two evidence files by cryptographic hash. Files are read locally and are not modified.", bg=NAVY, fg="#b8c6d8", font=("Segoe UI", 10)).pack(anchor="w", pady=(7, 0))

        body = tk.Frame(self, bg=BG, padx=24, pady=18)
        body.pack(fill="both", expand=True)
        self._section_label(body, "CASE CONTEXT", "Optional identifiers are included in the exported comparison report.")
        context = tk.Frame(body, bg="white", padx=14, pady=12, highlightbackground=BORDER, highlightthickness=1)
        context.pack(fill="x", pady=(7, 15))
        self._entry_field(context, "CASE / REFERENCE ID", self.case_id, 0)
        self._entry_field(context, "EXAMINER / ANALYST", self.examiner, 1)
        self._entry_field(context, "EVIDENCE ITEM A ID", self.evidence_ids[0], 2)
        self._entry_field(context, "EVIDENCE ITEM B ID", self.evidence_ids[1], 3)

        self._section_label(body, "EVIDENCE ITEMS", "Select the two files to compare. SHA-256 is calculated from file contents.")
        evidence_row = tk.Frame(body, bg=BG)
        evidence_row.pack(fill="x", pady=(7, 14))
        evidence_row.columnconfigure(0, weight=1, uniform="ev")
        evidence_row.columnconfigure(1, weight=1, uniform="ev")
        self._evidence_card(evidence_row, 0, "EVIDENCE ITEM A", "Evidence A")
        self._evidence_card(evidence_row, 1, "EVIDENCE ITEM B", "Evidence B")

        actions = tk.Frame(body, bg=BG)
        actions.pack(fill="x", pady=(0, 13))
        self.compare_button = ttk.Button(actions, text="Calculate & Compare", style="Primary.TButton", command=self.compare)
        self.compare_button.pack(side="left")
        self.export_button = ttk.Button(actions, text="Export Report…", command=self.export_report, state="disabled")
        self.export_button.pack(side="left", padx=(9, 0))
        self.status = tk.StringVar(value="READY  •  Choose evidence items A and B to begin.")
        self.status_label = tk.Label(actions, textvariable=self.status, bg=BG, fg=MUTED, font=("Segoe UI", 9), anchor="e")
        self.status_label.pack(side="right", fill="x", expand=True, padx=(12, 0))

        result_card = tk.Frame(body, bg="white", padx=16, pady=14, highlightbackground=BORDER, highlightthickness=1)
        result_card.pack(fill="both", expand=True)
        tk.Label(result_card, text="COMPARISON RESULT", bg="white", fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w")
        self.verdict = tk.Label(result_card, text="AWAITING ANALYSIS", bg="white", fg="#546579", font=("Segoe UI", 18, "bold"), anchor="w")
        self.verdict.pack(fill="x", pady=(6, 12))
        self.hash_text = tk.Text(result_card, height=8, wrap="word", bg="#f7f9fc", fg=INK, relief="flat", padx=12, pady=10, font=("Consolas", 9), state="disabled")
        self.hash_text.pack(fill="both", expand=True)
        tk.Label(body, text="Method: SHA-256 over file bytes. A matching hash indicates matching contents at the time of analysis. This utility does not create a forensic image or a signed chain-of-custody record.", bg=BG, fg=MUTED, font=("Segoe UI", 8), wraplength=1080, justify="left").pack(anchor="w", pady=(10, 0))

    def _section_label(self, parent, title, subtitle):
        tk.Label(parent, text=title, bg=BG, fg=INK, font=("Segoe UI", 10, "bold")).pack(anchor="w")
        tk.Label(parent, text=subtitle, bg=BG, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w", pady=(2, 0))

    def _entry_field(self, parent, label, variable, column):
        field = tk.Frame(parent, bg="white")
        field.grid(row=0, column=column, sticky="ew", padx=(0 if column == 0 else 14, 0))
        parent.columnconfigure(column, weight=1)
        tk.Label(field, text=label, bg="white", fg=MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
        ttk.Entry(field, textvariable=variable).pack(fill="x", pady=(5, 0))

    def _evidence_card(self, parent, index, title, evidence_id):
        card = tk.Frame(parent, bg="white", padx=15, pady=13, highlightbackground=BORDER, highlightthickness=1)
        card.grid(row=0, column=index, sticky="nsew", padx=(0 if index == 0 else 8, 8 if index == 0 else 0))
        tk.Label(card, text=title, bg="white", fg="#087f8c", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        meta = tk.Frame(card, bg="white", pady=12)
        meta.pack(fill="both", expand=True)
        name = tk.Label(meta, text="No file selected", bg="white", fg=INK, font=("Segoe UI", 11, "bold"), anchor="w", wraplength=440, justify="left")
        name.pack(fill="x", anchor="w")
        path = tk.Label(meta, text="Select an evidence file to view its metadata.", bg="white", fg=MUTED, font=("Segoe UI", 8), anchor="w", wraplength=440, justify="left")
        path.pack(fill="x", anchor="w", pady=(5, 4))
        details = tk.Label(meta, text="File size: —     Last modified (UTC): —", bg="white", fg=MUTED, font=("Segoe UI", 8), anchor="w", wraplength=440, justify="left")
        details.pack(fill="x", anchor="w")
        button = ttk.Button(card, text="Select Evidence File…", command=lambda: self.choose_file(index))
        button.pack(anchor="w")
        self.paths[index].trace_add("write", lambda *_args, i=index, n=name, p=path, d=details: self._update_card(i, n, p, d))
        if index == 0:
            self.card_labels = []
        self.card_labels.append((name, path, details, button))

    def _update_card(self, index, name_label, path_label, details_label):
        path = self.paths[index].get()
        if not path:
            return
        try:
            stat = Path(path).stat()
            name_label.configure(text=Path(path).name)
            path_label.configure(text=path)
            details_label.configure(text=f"File size: {stat.st_size:,} bytes     Last modified (UTC): {utc_time(stat.st_mtime)}")
        except OSError:
            name_label.configure(text="File unavailable")
            path_label.configure(text=path)
            details_label.configure(text="Metadata could not be read.")

    def choose_file(self, index):
        path = filedialog.askopenfilename(title=f"Select Evidence Item {'A' if index == 0 else 'B'}")
        if path:
            self.paths[index].set(path)
            self.result_data = None
            self.export_button.configure(state="disabled")
            self.verdict.configure(text="READY TO ANALYZE", fg="#546579")
            self._set_hash_text("Evidence selection updated. Run Calculate & Compare to generate results.")

    def compare(self):
        first, second = (value.get() for value in self.paths)
        if not first or not second:
            messagebox.showinfo("Evidence required", "Select both evidence items before comparison.")
            return
        if not self.case_id.get().strip():
            if not messagebox.askyesno("Case reference", "No case/reference ID was entered. Continue without one?"):
                return
        context = {
            "case_id": self.case_id.get().strip(),
            "examiner": self.examiner.get().strip(),
            "evidence_ids": [item.get().strip() for item in self.evidence_ids],
        }
        self.result_data = None
        self._set_busy(True, "ANALYZING  •  Calculating SHA-256…")

        def work():
            try:
                result = (hash_evidence(first), hash_evidence(second), None)
            except OSError as exc:
                result = (None, None, str(exc))
            self.after(0, lambda: self._finish(result, context))

        threading.Thread(target=work, daemon=True).start()

    def _finish(self, result, context):
        first, second, error = result
        self._set_busy(False, "ANALYSIS COMPLETE")
        if error:
            self.verdict.configure(text="ANALYSIS ERROR", fg="#b42318")
            self._set_hash_text(f"A file could not be read.\n\n{error}")
            return
        if not first["stable"] or not second["stable"]:
            verdict, color = "UNSTABLE DURING HASH", "#b54708"
            detail = "File metadata changed while it was being read. Repeat the analysis after the file is stable."
        elif first["hash"] == second["hash"]:
            verdict, color = "HASH MATCH", "#087f5b"
            detail = "The SHA-256 values match. The file contents were identical at the time of analysis."
        else:
            verdict, color = "HASH MISMATCH", "#b42318"
            detail = "The SHA-256 values differ. The file contents are not identical."
        self.verdict.configure(text=verdict, fg=color)
        self.status.set("ANALYSIS COMPLETE  •  SHA-256 comparison finished.")
        self.result_data = {"first": first, "second": second, "verdict": verdict, "detail": detail, "context": context, "analyzed_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")}
        self.export_button.configure(state="normal")
        self._set_hash_text(self._format_result(self.result_data))

    def _format_result(self, data):
        a, b = data["first"], data["second"]
        context = data["context"]
        return (f"{data['detail']}\n\n"
                f"CASE / REFERENCE: {context['case_id'] or 'Not provided'}\n"
                f"EXAMINER / ANALYST: {context['examiner'] or 'Not provided'}\n"
                f"ANALYZED: {data['analyzed_utc']}\n\n"
                f"EVIDENCE ITEM A  |  ID: {context['evidence_ids'][0] or 'Not provided'}  |  {a['name']}\nPATH: {a['path']}\nSIZE: {a['size']:,} bytes  |  MODIFIED: {a['modified_utc']}\nSHA-256: {a['hash']}\n\n"
                f"EVIDENCE ITEM B  |  ID: {context['evidence_ids'][1] or 'Not provided'}  |  {b['name']}\nPATH: {b['path']}\nSIZE: {b['size']:,} bytes  |  MODIFIED: {b['modified_utc']}\nSHA-256: {b['hash']}\n")

    def _set_hash_text(self, text):
        self.hash_text.configure(state="normal")
        self.hash_text.delete("1.0", "end")
        self.hash_text.insert("1.0", text)
        self.hash_text.configure(state="disabled")

    def export_report(self):
        if not self.result_data:
            return
        target = filedialog.asksaveasfilename(title="Export comparison report", defaultextension=".txt", initialfile="evidence_hash_comparison.txt", filetypes=[("Text report", "*.txt"), ("All files", "*.*")])
        if not target:
            return
        try:
            Path(target).write_text("DIGITAL EVIDENCE HASH COMPARISON REPORT\n" + "=" * 42 + "\n\n" + self._format_result(self.result_data), encoding="utf-8")
            messagebox.showinfo("Report exported", f"Report saved to:\n{target}")
        except OSError as exc:
            messagebox.showerror("Export error", str(exc))

    def _set_busy(self, busy, text):
        self.busy = busy
        for *_, button in self.card_labels:
            button.configure(state="disabled" if busy else "normal")
        self.compare_button.configure(state="disabled" if busy else "normal")
        self.export_button.configure(state="disabled" if busy or not self.result_data else "normal")
        self.status.set(text)


if __name__ == "__main__":
    EvidenceHashComparator().mainloop()
