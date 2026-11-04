"""Point-and-click window for the scanner (Windows / macOS / Linux).

Double-click "iPhone Scanner.exe" (or run `python iPhoneScanner.pyw`).
It finds the newest iPhone backup, asks for the backup password, downloads
fresh spyware signatures, scans, and opens the report in the browser.
"""

from __future__ import annotations

import datetime as _dt
import queue
import threading
import tkinter as tk
import traceback
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__, indicators, report
from .backup import Backup, BackupError, find_backups
from .checks import run_all

VERDICT_COLORS = {
    "critical": "#c4141a", "high": "#d9480f", "medium": "#b7791f", "low": "#2b8a3e", None: "#2b8a3e",
}

BACKUP_HELP = (
    "How to back up your iPhone\n\n"
    "Windows:\n"
    "1. Install 'Apple Devices' from the Microsoft Store (or use iTunes).\n"
    "2. Plug in your iPhone, unlock it and tap 'Trust'.\n"
    "3. In Apple Devices click your iPhone > General.\n"
    "4. Choose 'Back up all of the data on your iPhone to this computer'.\n"
    "5. Tick 'Encrypt local backup' and choose a password. Write it down!\n"
    "6. Click 'Back Up Now' and wait until it finishes.\n\n"
    "Mac: same steps in Finder (click your iPhone in the sidebar).\n\n"
    "Then come back here and click 'Look again'."
)


def reports_dir() -> Path:
    docs = Path.home() / "Documents"
    d = (docs if docs.is_dir() else Path.home()) / "iPhone Scanner Reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _friendly_date(text: str) -> str:
    try:
        return _dt.datetime.fromisoformat(text).strftime("%d %b %Y, %H:%M")
    except ValueError:
        return text


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.backups: list[dict] = []
        self.custom: dict | None = None
        self.events: queue.Queue = queue.Queue()
        self.report_path: Path | None = None
        self.busy = False

        root.title("iPhone Scanner")
        root.geometry("600x740")
        root.minsize(520, 640)
        style = ttk.Style(root)
        for theme in ("vista", "aqua", "clam"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        style.configure("Big.TButton", font=("Segoe UI", 13, "bold"), padding=(18, 12))
        style.configure("H.TLabel", font=("Segoe UI", 20, "bold"))
        style.configure("Sub.TLabel", foreground="#566273")
        style.configure("Step.TLabelframe.Label", font=("Segoe UI", 11, "bold"))

        f = ttk.Frame(root, padding=22)
        f.pack(fill="both", expand=True)
        f.columnconfigure(0, weight=1)

        ttk.Label(f, text="iPhone Scanner", style="H.TLabel").grid(sticky="w")
        ttk.Label(f, text="Checks a backup of your iPhone for spyware, stalkerware, jailbreaks and tracking profiles. "
                         "Nothing leaves this computer.", style="Sub.TLabel", wraplength=540).grid(sticky="w", pady=(2, 14))

        # Step 1: backup
        s1 = ttk.Labelframe(f, text="1   Your iPhone backup", style="Step.TLabelframe", padding=12)
        s1.grid(sticky="ew")
        s1.columnconfigure(0, weight=1)
        self.backup_var = tk.StringVar()
        self.backup_box = ttk.Combobox(s1, textvariable=self.backup_var, state="readonly")
        self.backup_box.bind("<<ComboboxSelected>>", lambda e: self._on_backup_change())
        self.backup_msg = ttk.Label(s1, wraplength=520)
        self.backup_box.grid(row=0, column=0, columnspan=3, sticky="ew")
        self.backup_msg.grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 8))
        ttk.Button(s1, text="Look again", command=self.refresh).grid(row=2, column=0, sticky="w")
        ttk.Button(s1, text="Choose folder…", command=self.choose_folder).grid(row=2, column=1, padx=6)
        ttk.Button(s1, text="How do I back up?", command=lambda: messagebox.showinfo("Back up your iPhone", BACKUP_HELP)).grid(row=2, column=2)

        # Step 2: password
        s2 = ttk.Labelframe(f, text="2   Backup password", style="Step.TLabelframe", padding=12)
        s2.grid(sticky="ew", pady=12)
        s2.columnconfigure(0, weight=1)
        self.pw_var = tk.StringVar()
        self.pw = ttk.Entry(s2, textvariable=self.pw_var, show="•", font=("Segoe UI", 12))
        self.pw.grid(sticky="ew")
        self.pw.bind("<Return>", lambda e: self.start())
        self.pw_hint = ttk.Label(s2, style="Sub.TLabel", wraplength=520,
                                 text="The password you chose when you ticked 'Encrypt local backup'. "
                                      "It is not your iPhone passcode or Apple ID password.")
        self.pw_hint.grid(sticky="w", pady=(6, 0))

        # Step 3: scan
        self.scan_btn = ttk.Button(f, text="Scan my iPhone", style="Big.TButton", command=self.start)
        self.scan_btn.grid(sticky="ew", pady=(4, 10))
        self.progress = ttk.Progressbar(f, mode="indeterminate")
        self.progress.grid(sticky="ew")
        self.status = ttk.Label(f, text="", wraplength=540)
        self.status.grid(sticky="w", pady=(6, 10))

        # Result
        self.result = tk.Frame(f, bg="#2b8a3e", padx=14, pady=12)
        self.verdict = tk.Label(self.result, font=("Segoe UI", 16, "bold"), fg="white", bg="#2b8a3e", anchor="w")
        self.summary = tk.Label(self.result, font=("Segoe UI", 10), fg="white", bg="#2b8a3e",
                                anchor="w", justify="left", wraplength=520)
        self.verdict.pack(fill="x")
        self.summary.pack(fill="x")
        self.open_btn = ttk.Button(f, text="Open full report", command=self.open_report)

        root.after(100, self._poll)
        self.refresh()

    # -- backups ---------------------------------------------------------

    def refresh(self):
        self.backups = find_backups()
        if self.custom and self.custom["path"] not in {b["path"] for b in self.backups}:
            self.backups.insert(0, self.custom)
        labels = [f"{b['device_name']}  -  backed up {_friendly_date(b['last_backup'])}" for b in self.backups]
        self.backup_box["values"] = labels
        if labels:
            self.backup_box.current(0)
        else:
            self.backup_var.set("No iPhone backup found on this computer")
        self._on_backup_change()

    def choose_folder(self):
        d = filedialog.askdirectory(title="Choose the iPhone backup folder")
        if not d:
            return
        p = Path(d)
        is_backup = (p / "Manifest.plist").is_file()
        root = p.parent if is_backup else p
        cands = [b for b in find_backups([root]) if Path(b["path"]).parent == root]
        if is_backup:
            cands = [b for b in cands if Path(b["path"]) == p]
        if not cands:
            messagebox.showerror("Not a backup", "That folder doesn't contain an iPhone backup.")
            return
        self.custom = cands[0]
        self.refresh()
        idx = next(i for i, b in enumerate(self.backups) if b["path"] == self.custom["path"])
        self.backup_box.current(idx)
        self._on_backup_change()

    def selected(self) -> dict | None:
        i = self.backup_box.current()
        return self.backups[i] if 0 <= i < len(self.backups) else None

    def _on_backup_change(self):
        b = self.selected()
        if not b:
            self.backup_msg.configure(foreground="#c4141a",
                                      text="No backup found. Click 'How do I back up?', make a backup, then click 'Look again'.")
            self.pw.state(["disabled"])
            self.scan_btn.state(["disabled"])
            return
        self.scan_btn.state(["!disabled"])
        if b.get("encrypted"):
            self.backup_msg.configure(foreground="#2b8a3e", text=f"Encrypted backup of iOS {b.get('product_version', '?')} - ready to scan.")
            self.pw.state(["!disabled"])
            self.pw.focus_set()
        else:
            self.backup_msg.configure(foreground="#b7791f",
                                      text="This backup is NOT encrypted, so the scan will miss a lot. For a full scan, "
                                           "tick 'Encrypt local backup' in Apple Devices / Finder and back up again.")
            self.pw_var.set("")
            self.pw.state(["disabled"])

    # -- scanning --------------------------------------------------------

    def start(self):
        b = self.selected()
        if self.busy or not b:
            return
        if b.get("encrypted") and not self.pw_var.get():
            self._set_status("Type the backup password first.", "#c4141a")
            self.pw.focus_set()
            return
        self.busy = True
        self.scan_btn.state(["disabled"])
        self.result.grid_forget()
        self.open_btn.grid_forget()
        self.progress.start(12)
        threading.Thread(target=self._work, args=(b["path"], self.pw_var.get() or None), daemon=True).start()

    def _work(self, path: str, password: str | None):
        send = lambda kind, val: self.events.put((kind, val))  # noqa: E731
        try:
            age = indicators.age_days()
            if age is None or age > 7:
                send("status", "Downloading the latest spyware signatures…")
                try:
                    indicators.update(progress=lambda *_: None)
                except Exception:
                    if age is None:
                        send("status", "Couldn't download signatures (no internet?). Scanning settings only…")
            ind = indicators.Indicators.load()
            send("status", "Unlocking the backup… (this can take up to a minute)" if password else "Opening the backup…")
            with Backup(path, password) as bk:
                send("status", "Scanning… (large backups can take a few minutes)")
                res = run_all(bk, ind)
            out = reports_dir() / f"iPhone scan {_dt.datetime.now():%Y-%m-%d %H-%M}.html"
            out.write_text(report.to_html(res), "utf-8")
            send("done", (res, out))
        except BackupError as exc:
            msg = str(exc)
            if "Wrong backup password" in msg or "wrong password" in msg:
                msg = ("Wrong backup password. Use the password you chose when you ticked "
                       "'Encrypt local backup' (not your iPhone passcode).")
            send("error", msg)
        except Exception as exc:
            send("error", f"Something went wrong: {exc}\n\n{traceback.format_exc(limit=3)}")

    def _poll(self):
        try:
            while True:
                kind, val = self.events.get_nowait()
                if kind == "status":
                    self._set_status(val)
                elif kind == "error":
                    self._finish()
                    self._set_status(val, "#c4141a")
                elif kind == "done":
                    self._finish()
                    self._show_result(*val)
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _finish(self):
        self.busy = False
        self.progress.stop()
        self.scan_btn.state(["!disabled"])

    def _set_status(self, text, color=""):
        self.status.configure(text=text, foreground=color)

    def _show_result(self, res, path: Path):
        worst = res.worst()
        verdict, summary = report.VERDICTS[worst]
        color = VERDICT_COLORS[worst]
        top = [f"•  {f.title}" for f in res.findings if f.severity in ("critical", "high", "medium")][:4]
        for w in (self.result, self.verdict, self.summary):
            w.configure(bg=color)
        self.verdict.configure(text=verdict)
        self.summary.configure(text=summary + ("\n\n" + "\n".join(top) if top else ""))
        self.result.grid(sticky="ew")
        self.open_btn.grid(sticky="w", pady=(10, 0))
        self.report_path = path
        self._set_status(f"Report saved to {path}")
        self.open_report()

    def open_report(self):
        if self.report_path:
            webbrowser.open(self.report_path.resolve().as_uri())


def main() -> int:
    root = tk.Tk()
    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
