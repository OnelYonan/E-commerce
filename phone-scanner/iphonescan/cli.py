"""Command-line interface."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__, indicators, report
from .backup import Backup, BackupError, find_backups
from .checks import run_all

HOW_TO_BACKUP = """\
How to make a backup of your iPhone:
  Mac:      connect the iPhone > Finder > select the iPhone > tick
            "Encrypt local backup" (choose a password) > "Back Up Now".
  Windows:  install "Apple Devices" (or iTunes) > connect the iPhone >
            tick "Encrypt local backup" > "Back Up Now".
  Linux:    sudo apt install libimobiledevice-utils
            idevicebackup2 -i encryption on        # set a backup password
            idevicebackup2 backup --full ~/iphone-backup
Then run:  python3 scan_iphone.py scan            (finds the backup automatically)
      or:  python3 scan_iphone.py scan PATH/TO/BACKUP
"""


def _cmd_list(args) -> int:
    backups = find_backups([Path(p) for p in args.search or []])
    if not backups:
        print("No iPhone backups found in the default locations.\n")
        print(HOW_TO_BACKUP)
        return 2
    for b in backups:
        print(f"{b['path']}\n    {b['device_name']}  iOS {b['product_version']}  last backup {b['last_backup']}")
    return 0


def _cmd_update(args) -> int:
    n = indicators.update()
    print(f"\n{n} indicator file(s) saved to {indicators.cache_dir()}")
    return 0 if n else 2


def _resolve_backup(args) -> str | None:
    if args.backup:
        p = Path(args.backup).expanduser()
        # allow pointing at the parent "Backup" folder or a nested UDID folder
        if not (p / "Manifest.plist").is_file():
            subs = [d for d in p.iterdir() if (d / "Manifest.plist").is_file()] if p.is_dir() else []
            if len(subs) == 1:
                return str(subs[0])
        return str(p)
    found = find_backups()
    if not found:
        return None
    if len(found) > 1:
        print("Several backups found; scanning the most recent one (pass a path to choose):")
        for b in found:
            print(f"  {b['path']}  ({b['device_name']}, {b['last_backup']})")
        found.sort(key=lambda b: b["last_backup"], reverse=True)
    return found[0]["path"]


def _cmd_scan(args) -> int:
    path = _resolve_backup(args)
    if not path:
        print("No iPhone backup found.\n")
        print(HOW_TO_BACKUP)
        return 2

    ind_paths = [Path(p) for p in args.indicators] if args.indicators else None
    if ind_paths is None and not any(indicators.cache_dir().glob("*.stix2")) and not args.offline:
        print("Downloading spyware signatures (first run)...")
        try:
            indicators.update(progress=lambda *_: None)
        except Exception as exc:
            print(f"  could not download signatures: {exc}\n  continuing with configuration checks only.")
    ind = indicators.Indicators.load(ind_paths)

    password = args.password or os.environ.get("IPHONE_BACKUP_PASSWORD")
    try:
        try:
            backup = Backup(path, password)
        except BackupError as exc:
            if "encrypted" in str(exc) and password is None and sys.stdin.isatty():
                password = getpass.getpass("Backup password: ")
                print("Unlocking backup (this can take ~10 seconds)...")
                backup = Backup(path, password)
            else:
                raise
        with backup:
            print(f"Scanning {path} ...")
            result = run_all(backup, ind)
    except BackupError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    print(report.to_text(result))
    if args.html:
        Path(args.html).write_text(report.to_html(result), "utf-8")
        print(f"HTML report saved to {args.html}")
    if args.json:
        Path(args.json).write_text(report.to_json(result), "utf-8")
        print(f"JSON report saved to {args.json}")
    worst = result.worst()
    return 1 if worst in ("critical", "high") else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="scan_iphone.py",
        description="Scan an iPhone backup for spyware, stalkerware, jailbreaks and tracking profiles.",
        epilog=HOW_TO_BACKUP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan a backup (default)")
    s.add_argument("backup", nargs="?", help="backup folder (default: newest backup on this computer)")
    s.add_argument("-p", "--password", help="password of an encrypted backup (or set IPHONE_BACKUP_PASSWORD)")
    s.add_argument("--html", metavar="FILE", help="also write an HTML report")
    s.add_argument("--json", metavar="FILE", help="also write a JSON report")
    s.add_argument("--indicators", nargs="+", metavar="STIX2", help="use these STIX2 indicator files instead of the cache")
    s.add_argument("--offline", action="store_true", help="don't download signatures")
    s.set_defaults(func=_cmd_scan)

    u = sub.add_parser("update", help="download the latest spyware signatures")
    u.set_defaults(func=_cmd_update)

    l = sub.add_parser("list", help="list iPhone backups on this computer")
    l.add_argument("search", nargs="*", help="extra folders to search")
    l.set_defaults(func=_cmd_list)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in ("scan", "update", "list", "-h", "--help", "--version"):
        argv = ["scan"] + argv
    args = build_parser().parse_args(argv)
    return args.func(args)
