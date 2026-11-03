"""Build synthetic iPhone backups (plain or encrypted) for tests and demos."""

from __future__ import annotations

import hashlib
import os
import plistlib
import sqlite3
import struct
import tempfile
from pathlib import Path


def _pad(data: bytes) -> bytes:
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def _aes_cbc(key, data):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    e = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16)).encryptor()
    return e.update(_pad(data)) + e.finalize()


def _tlv(tag: str, value) -> bytes:
    if isinstance(value, int):
        value = struct.pack(">L", value)
    return tag.encode() + struct.pack(">L", len(value)) + value


def _mbfile(size: int, wrapped_key: bytes | None, pclass: int) -> bytes:
    root = {"$class": plistlib.UID(3), "Size": size, "ProtectionClass": pclass, "Mode": 33188}
    objs = ["$null", root]
    if wrapped_key is not None:
        root["EncryptionKey"] = plistlib.UID(2)
        objs.append({"NS.data": wrapped_key, "$class": plistlib.UID(4)})
    else:
        objs.append("$null")
    objs.append({"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]})
    objs.append({"$classname": "NSMutableData", "$classes": ["NSMutableData", "NSData", "NSObject"]})
    return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$version": 100000,
                           "$top": {"root": plistlib.UID(1)}, "$objects": objs}, fmt=plistlib.FMT_BINARY)


def sqlite_bytes(schema_and_rows: list[tuple[str, list[tuple]]]) -> bytes:
    """[(create_sql, rows)] -> bytes of an SQLite file. Insert SQL derived from the table."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "x.db")
        c = sqlite3.connect(p)
        for create, rows in schema_and_rows:
            c.execute(create)
            table = create.split()[2].split("(")[0]
            for r in rows:
                c.execute(f"INSERT INTO {table} VALUES ({','.join('?' * len(r))})", r)
        c.commit()
        c.close()
        return Path(p).read_bytes()


def make_backup(root: str | Path, files: dict[tuple[str, str], bytes], info: dict | None = None,
                password: str | None = None, apps: list[str] | None = None) -> Path:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    info = {"Device Name": "Test iPhone", "Product Type": "iPhone15,2", "Product Version": "26.1",
            "Build Version": "23B85", "Last Backup Date": "2026-11-01 10:00:00",
            "Installed Applications": apps or [], **(info or {})}
    (root / "Info.plist").write_bytes(plistlib.dumps(info))
    manifest = {"IsEncrypted": bool(password), "Applications": {a: {} for a in apps or []}, "Version": "10.0"}

    class_keys = {}
    if password:
        from cryptography.hazmat.primitives.keywrap import aes_key_wrap
        salt, dpsl = os.urandom(20), os.urandom(20)
        it, dpic = 10, 10
        pk = hashlib.pbkdf2_hmac("sha1", hashlib.pbkdf2_hmac("sha256", password.encode(), dpsl, dpic, 32),
                                 salt, it, 32)
        kb = (_tlv("VERS", 4) + _tlv("TYPE", 1) + _tlv("UUID", os.urandom(16)) + _tlv("HMCK", os.urandom(40))
              + _tlv("WRAP", 1) + _tlv("SALT", salt) + _tlv("ITER", it)
              + _tlv("DPWT", 1) + _tlv("DPIC", dpic) + _tlv("DPSL", dpsl))
        for clas in (1, 2, 3, 4):
            k = os.urandom(32)
            class_keys[clas] = k
            kb += (_tlv("UUID", os.urandom(16)) + _tlv("CLAS", clas) + _tlv("WRAP", 3)
                   + _tlv("KTYP", 0) + _tlv("WPKY", aes_key_wrap(pk, k)))
        manifest["BackupKeyBag"] = kb
        mkey = os.urandom(32)
        manifest["ManifestKey"] = struct.pack("<l", 3) + aes_key_wrap(class_keys[3], mkey)

    dbfile = root / "Manifest.db.tmp"
    db = sqlite3.connect(dbfile)
    db.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    dirs = set()
    for (domain, rel), data in files.items():
        parts = rel.split("/")
        for i in range(1, len(parts)):
            dirs.add((domain, "/".join(parts[:i])))
    for domain, rel in dirs:
        fid = hashlib.sha1(f"{domain}-{rel}".encode()).hexdigest()
        db.execute("INSERT OR IGNORE INTO Files VALUES (?,?,?,2,?)", (fid, domain, rel, _mbfile(0, None, 0)))
    for (domain, rel), data in files.items():
        fid = hashlib.sha1(f"{domain}-{rel}".encode()).hexdigest()
        out = data
        wrapped = None
        if password:
            from cryptography.hazmat.primitives.keywrap import aes_key_wrap
            fk = os.urandom(32)
            out = _aes_cbc(fk, data)
            wrapped = struct.pack("<l", 3) + aes_key_wrap(class_keys[3], fk)
        (root / fid[:2]).mkdir(exist_ok=True)
        (root / fid[:2] / fid).write_bytes(out)
        db.execute("INSERT INTO Files VALUES (?,?,?,1,?)", (fid, domain, rel, _mbfile(len(data), wrapped, 3)))
    db.commit()
    db.close()
    raw = dbfile.read_bytes()
    dbfile.unlink()
    (root / "Manifest.db").write_bytes(_aes_cbc(mkey, raw) if password else raw)
    (root / "Manifest.plist").write_bytes(plistlib.dumps(manifest))
    return root


# ---------------------------------------------------------------------------
# A ready-made "infected" scenario
# ---------------------------------------------------------------------------

FAKE_STIX = {
    "type": "bundle", "id": "bundle--1",
    "objects": [
        {"type": "malware", "id": "malware--p", "name": "Pegasus"},
        {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value='evil-spy.example']"},
        {"type": "indicator", "id": "indicator--2", "pattern": "[process:name='bh']"},
        {"type": "indicator", "id": "indicator--3", "pattern": "[email-addr:value='attacker@icloud.example']"},
        {"type": "indicator", "id": "indicator--4",
         "pattern": "[file:path='/private/var/mobile/library/preferences/com.evil.agent.plist']"},
        {"type": "indicator", "id": "indicator--5", "pattern": "[configuration-profile:id='AAAA-1111']"},
        {"type": "relationship", "id": "relationship--1", "relationship_type": "indicates",
         "source_ref": "indicator--1", "target_ref": "malware--p"},
        {"type": "relationship", "id": "relationship--2", "relationship_type": "indicates",
         "source_ref": "indicator--2", "target_ref": "malware--p"},
        {"type": "relationship", "id": "relationship--3", "relationship_type": "indicates",
         "source_ref": "indicator--3", "target_ref": "malware--p"},
    ],
}

PROFILE_DOMAIN = "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles"


def infected_files() -> dict:
    profile = plistlib.dumps({
        "PayloadType": "Configuration", "PayloadIdentifier": "com.spyco.profile",
        "PayloadDisplayName": "System Update", "PayloadOrganization": "SpyCo",
        "PayloadContent": [
            {"PayloadType": "com.apple.mdm", "PayloadIdentifier": "com.spyco.profile.mdm"},
            {"PayloadType": "com.apple.security.root", "PayloadIdentifier": "com.spyco.profile.ca"},
        ],
    })
    return {
        ("HomeDomain", "Library/Safari/History.db"): sqlite_bytes([
            ("CREATE TABLE history_items (id INTEGER, url TEXT)",
             [(1, "https://www.apple.com/"), (2, "https://cdn.evil-spy.example/x?y=1")]),
            ("CREATE TABLE history_visits (id INTEGER, history_item INTEGER, visit_time REAL)",
             [(1, 1, 700000000.0), (2, 2, 750000000.0)]),
        ]),
        ("HomeDomain", "Library/SMS/sms.db"): sqlite_bytes([
            ("CREATE TABLE handle (ROWID INTEGER, id TEXT)", [(1, "attacker@icloud.example"), (2, "+15550100")]),
            ("CREATE TABLE message (ROWID INTEGER, text TEXT, date INTEGER, handle_id INTEGER)",
             [(1, "hi, see https://evil-spy.example/a", 750000000000000000, 1), (2, "lunch?", 1, 2)]),
        ]),
        ("WirelessDomain", "Library/Databases/DataUsage.sqlite"): sqlite_bytes([
            ("CREATE TABLE ZPROCESS (Z_PK INTEGER, ZPROCNAME TEXT, ZBUNDLENAME TEXT, ZFIRSTTIMESTAMP REAL)",
             [(1, "bh", None, 750000000.0), (2, "MobileSafari", "com.apple.mobilesafari", 1.0)]),
        ]),
        ("HomeDomain", "Library/TCC/TCC.db"): sqlite_bytes([
            ("CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER)",
             [("kTCCServiceMicrophone", "com.example.flashlight", 0, 2),
              ("kTCCServiceCamera", "com.example.flashlight", 0, 2),
              ("kTCCServiceAddressBook", "com.example.flashlight", 0, 2),
              ("kTCCServiceCamera", "com.apple.camera", 0, 2)]),
        ]),
        (PROFILE_DOMAIN, "Library/ConfigurationProfiles/profile-abc.stub"): profile,
        (PROFILE_DOMAIN, "Library/ConfigurationProfiles/CloudConfigurationDetails.plist"):
            plistlib.dumps({"IsSupervised": True, "OrganizationName": "SpyCo"}),
        ("HomeDomain", "Library/Preferences/com.evil.agent.plist"): plistlib.dumps({}),
        (PROFILE_DOMAIN, "Library/ConfigurationProfiles/profile-def.stub"): plistlib.dumps({
            "PayloadType": "Configuration", "PayloadIdentifier": "com.other", "PayloadUUID": "aaaa-1111",
            "PayloadDisplayName": "Free VPN"}),
        ("AppDomain-com.saurik.Cydia", "Library/Preferences/com.saurik.Cydia.plist"): plistlib.dumps({}),
    }


INFECTED_APPS = ["com.saurik.Cydia", "com.example.flashlight", "net.whatsapp.WhatsApp"]


def clean_files() -> dict:
    return {
        ("HomeDomain", "Library/Safari/History.db"): sqlite_bytes([
            ("CREATE TABLE history_items (id INTEGER, url TEXT)", [(1, "https://www.apple.com/")]),
            ("CREATE TABLE history_visits (id INTEGER, history_item INTEGER, visit_time REAL)", [(1, 1, 7e8)]),
        ]),
    }
