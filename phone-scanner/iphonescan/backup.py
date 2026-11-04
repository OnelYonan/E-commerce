"""Read iPhone backups made by Finder, iTunes, Apple Devices or idevicebackup2.

Backup layout:
    <backup>/Info.plist       device info and installed apps
    <backup>/Manifest.plist   encryption keybag, app list
    <backup>/Manifest.db      SQLite index: Files(fileID, domain, relativePath, flags, file)
    <backup>/<id[:2]>/<id>    file contents; id = sha1(domain + "-" + relativePath)

Encrypted backups are decrypted in memory and in a private temp directory with
the backup password. This needs the optional `cryptography` package.
Nothing in the backup folder is ever modified.
"""

from __future__ import annotations

import hashlib
import os
import plistlib
import shutil
import sqlite3
import struct
import sys
import tempfile
from pathlib import Path


class BackupError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Backup discovery
# ---------------------------------------------------------------------------

def default_backup_roots() -> list[Path]:
    home = Path.home()
    roots = [Path(p) for p in os.environ.get("IPHONESCAN_BACKUP_DIR", "").split(os.pathsep) if p]
    roots.append(home / "Library/Application Support/MobileSync/Backup")  # macOS
    if sys.platform.startswith("win"):
        appdata = os.environ.get("APPDATA")
        if appdata:
            roots.append(Path(appdata) / "Apple Computer/MobileSync/Backup")
        roots.append(home / "Apple/MobileSync/Backup")  # Microsoft Store iTunes / Apple Devices
    return [r for r in roots if r.is_dir()]


def find_backups(extra_roots: list[Path] | None = None) -> list[dict]:
    found, seen = [], set()
    for root in (extra_roots or []) + default_backup_roots():
        try:
            subdirs = sorted(root.iterdir()) if root.is_dir() else []
        except OSError:  # e.g. macOS blocks the folder without Full Disk Access
            continue
        for d in subdirs:
            if str(d) in seen:
                continue
            seen.add(str(d))
            try:
                if not (d / "Manifest.plist").is_file():
                    continue
            except OSError:
                continue
            info = _load_plist(d / "Info.plist") or {}
            manifest = _load_plist(d / "Manifest.plist") or {}
            found.append({
                "path": str(d),
                "device_name": info.get("Device Name", "?"),
                "product_version": info.get("Product Version", "?"),
                "last_backup": str(info.get("Last Backup Date", "?")),
                "encrypted": bool(manifest.get("IsEncrypted")),
            })
    found.sort(key=lambda b: b["last_backup"], reverse=True)
    return found


def _load_plist(path: Path):
    try:
        with open(path, "rb") as f:
            return plistlib.load(f)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Keybag / decryption (Apple iOS backup data protection)
# ---------------------------------------------------------------------------

WRAP_PASSCODE = 2
_CLASSKEY_TAGS = {"CLAS", "WRAP", "WPKY", "KTYP", "PBKY"}


def _tlv(data: bytes):
    i = 0
    while i + 8 <= len(data):
        tag = data[i:i + 4].decode("ascii", "replace")
        length = struct.unpack(">L", data[i + 4:i + 8])[0]
        yield tag, data[i + 8:i + 8 + length]
        i += 8 + length


class Keybag:
    def __init__(self, data: bytes):
        self.uuid = None
        self.wrap = None
        self.attrs: dict[str, object] = {}
        self.class_keys: dict[int, dict] = {}
        current = None
        for tag, value in _tlv(data):
            v = struct.unpack(">L", value)[0] if len(value) == 4 else value
            if tag == "UUID" and self.uuid is None:
                self.uuid = v
            elif tag == "WRAP" and self.wrap is None:
                self.wrap = v
            elif tag == "UUID":
                if current is not None:
                    self.class_keys[current["CLAS"]] = current
                current = {"UUID": v}
            elif tag in _CLASSKEY_TAGS and current is not None:
                current[tag] = v
            else:
                self.attrs[tag] = v
        if current is not None:
            self.class_keys[current["CLAS"]] = current

    def unlock(self, password: str) -> None:
        _require_crypto()
        from cryptography.hazmat.primitives.keywrap import InvalidUnwrap, aes_key_unwrap

        pw = password.encode("utf-8")
        if "DPSL" in self.attrs:  # iOS 10.2+: extra PBKDF2-SHA256 round
            pw = hashlib.pbkdf2_hmac("sha256", pw, self.attrs["DPSL"], self.attrs["DPIC"], 32)
        key = hashlib.pbkdf2_hmac("sha1", pw, self.attrs["SALT"], self.attrs["ITER"], 32)
        unlocked = 0
        for ck in self.class_keys.values():
            if "WPKY" in ck and ck.get("WRAP", 0) & WRAP_PASSCODE:
                try:
                    ck["KEY"] = aes_key_unwrap(key, ck["WPKY"])
                    unlocked += 1
                except InvalidUnwrap:
                    raise BackupError("Wrong backup password.") from None
        if not unlocked:
            raise BackupError("Could not unlock any keys in the backup keybag.")

    def unwrap_for_class(self, protection_class: int, wrapped: bytes) -> bytes:
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

        ck = self.class_keys.get(protection_class)
        if not ck or "KEY" not in ck:
            raise BackupError(f"No key for protection class {protection_class}.")
        return aes_key_unwrap(ck["KEY"], wrapped)


def _require_crypto():
    try:
        import cryptography  # noqa: F401
    except ImportError:
        raise BackupError(
            "This backup is encrypted. Install the decryption library first:\n"
            "    pip install cryptography"
        ) from None


def aes_cbc_decrypt(key: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    data = data[: len(data) - len(data) % 16]
    d = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).decryptor()
    return d.update(data) + d.finalize()


def _strip_pkcs7(data: bytes) -> bytes:
    if data and 1 <= data[-1] <= 16 and data.endswith(bytes([data[-1]]) * data[-1]):
        return data[: -data[-1]]
    return data


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------

class Backup:
    def __init__(self, path: str | Path, password: str | None = None):
        self.path = Path(path).expanduser()
        if not (self.path / "Manifest.plist").is_file():
            raise BackupError(
                f"{self.path} is not an iPhone backup folder (Manifest.plist not found)."
            )
        self.manifest = _load_plist(self.path / "Manifest.plist") or {}
        self.info = _load_plist(self.path / "Info.plist") or {}
        self.encrypted = bool(self.manifest.get("IsEncrypted"))
        self.keybag = None
        self._tmp = tempfile.mkdtemp(prefix="iphonescan-")
        db_path = self.path / "Manifest.db"
        if not db_path.is_file():
            raise BackupError("Manifest.db is missing - the backup is incomplete or very old.")
        if self.encrypted:
            if password is None:
                raise BackupError("This backup is encrypted; supply its password with --password.")
            _require_crypto()
            self.keybag = Keybag(self.manifest["BackupKeyBag"])
            self.keybag.unlock(password)
            mk = self.manifest["ManifestKey"]
            cls = struct.unpack("<l", mk[:4])[0]
            key = self.keybag.unwrap_for_class(cls, mk[4:])
            plain = _strip_pkcs7(aes_cbc_decrypt(key, db_path.read_bytes()))
            if not plain.startswith(b"SQLite format 3"):
                raise BackupError("Could not decrypt Manifest.db (wrong password?).")
            db_path = Path(self._tmp) / "Manifest.db"
            db_path.write_bytes(plain)
        self.db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

    def close(self):
        try:
            self.db.close()
        finally:
            shutil.rmtree(self._tmp, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- index -------------------------------------------------------------

    def files(self, domain_like: str = "%", path_like: str = "%"):
        """Yield (fileID, domain, relativePath, flags) rows."""
        yield from self.db.execute(
            "SELECT fileID, domain, relativePath, flags FROM Files "
            "WHERE domain LIKE ? AND relativePath LIKE ?",
            (domain_like, path_like),
        )

    def all_paths(self):
        yield from self.db.execute("SELECT domain, relativePath FROM Files")

    def domains(self) -> set[str]:
        return {r[0] for r in self.db.execute("SELECT DISTINCT domain FROM Files")}

    # -- contents ----------------------------------------------------------

    def read(self, domain: str, relative_path: str) -> bytes | None:
        row = self.db.execute(
            "SELECT fileID, file FROM Files WHERE domain = ? AND relativePath = ? AND flags = 1",
            (domain, relative_path),
        ).fetchone()
        return self._read_row(row) if row else None

    def read_id(self, file_id: str) -> bytes | None:
        row = self.db.execute("SELECT fileID, file FROM Files WHERE fileID = ?", (file_id,)).fetchone()
        return self._read_row(row) if row else None

    def _read_row(self, row) -> bytes | None:
        file_id, blob = row
        on_disk = self.path / file_id[:2] / file_id
        if not on_disk.is_file():
            on_disk = self.path / file_id  # very old flat layout
            if not on_disk.is_file():
                return None
        data = on_disk.read_bytes()
        if not self.encrypted:
            return data
        meta = _mbfile(blob)
        wrapped = meta.get("EncryptionKey")
        if not wrapped:
            return data
        cls = meta.get("ProtectionClass") or struct.unpack("<l", wrapped[:4])[0]
        key = self.keybag.unwrap_for_class(cls, wrapped[4:])
        plain = aes_cbc_decrypt(key, data)
        size = meta.get("Size")
        return plain[:size] if isinstance(size, int) and size <= len(plain) else _strip_pkcs7(plain)

    def sqlite(self, domain: str, relative_path: str) -> sqlite3.Connection | None:
        """Extract an SQLite database (plus its -wal) and open it read-only."""
        data = self.read(domain, relative_path)
        if not data or not data.startswith(b"SQLite format 3"):
            return None
        name = hashlib.sha1(f"{domain}-{relative_path}".encode()).hexdigest()
        target = Path(self._tmp) / f"{name}.db"
        target.write_bytes(data)
        wal = self.read(domain, relative_path + "-wal")
        if wal:
            Path(str(target) + "-wal").write_bytes(wal)
        conn = sqlite3.connect(str(target))
        return conn

    def plist(self, domain: str, relative_path: str):
        data = self.read(domain, relative_path)
        if not data:
            return None
        try:
            return plistlib.loads(data)
        except Exception:
            return None


def _mbfile(blob: bytes) -> dict:
    """Decode the NSKeyedArchiver MBFile blob stored in Manifest.db."""
    try:
        archive = plistlib.loads(blob)
        objects = archive["$objects"]
        root_ref = archive["$top"]["root"]
        root = objects[root_ref.data if hasattr(root_ref, "data") else int(root_ref)]
        out = dict(root)
        ek = root.get("EncryptionKey")
        if ek is not None:
            ref = objects[ek.data if hasattr(ek, "data") else int(ek)]
            out["EncryptionKey"] = ref["NS.data"] if isinstance(ref, dict) else ref
        return out
    except Exception:
        return {}
