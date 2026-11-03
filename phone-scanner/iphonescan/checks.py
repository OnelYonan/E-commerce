"""The individual security checks run against an iPhone backup."""

from __future__ import annotations

import datetime as _dt
import plistlib
import re
from dataclasses import dataclass, field

from .backup import Backup
from .indicators import URL_RE, Indicators

SEVERITIES = ["critical", "high", "medium", "low", "info"]

PROFILE_DOMAIN = "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles"


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str = ""
    advice: str = ""
    evidence: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    device: dict
    apps: list[str]
    findings: list[Finding]
    coverage: dict[str, str]
    indicator_count: int

    def worst(self) -> str | None:
        for s in SEVERITIES[:-1]:
            if any(f.severity == s for f in self.findings):
                return s
        return None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _apple_ts(value) -> str:
    """Convert Apple 'Mac absolute time' (seconds or ns since 2001) to ISO."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return str(value)
    if v > 1e12:  # nanoseconds
        v /= 1e9
    try:
        return (_dt.datetime(2001, 1, 1, tzinfo=_dt.timezone.utc) + _dt.timedelta(seconds=v)).strftime("%Y-%m-%d %H:%M")
    except OverflowError:
        return str(value)


def _columns(conn, table) -> set[str]:
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    except Exception:
        return set()


def _limit(items: list[str], n: int = 25) -> list[str]:
    return items[:n] + ([f"... and {len(items) - n} more"] if len(items) > n else [])


# ---------------------------------------------------------------------------
# device / apps
# ---------------------------------------------------------------------------

def device_info(b: Backup) -> dict:
    i = b.info
    return {
        "name": i.get("Device Name") or i.get("Display Name") or "?",
        "model": i.get("Product Type", "?"),
        "ios_version": i.get("Product Version", "?"),
        "build": i.get("Build Version", "?"),
        "serial": i.get("Serial Number", "?"),
        "last_backup": str(i.get("Last Backup Date", "?")),
        "encrypted_backup": b.encrypted,
    }


def installed_apps(b: Backup) -> list[str]:
    apps = set(b.info.get("Installed Applications") or [])
    apps |= set((b.manifest.get("Applications") or {}).keys())
    for d in b.domains():
        if d.startswith("AppDomain-"):
            apps.add(d[len("AppDomain-"):])
    return sorted(a for a in apps if a)


def check_ios_version(b: Backup, out: list[Finding]):
    ver = str(b.info.get("Product Version", ""))
    m = re.match(r"(\d+)", ver)
    if not m:
        return
    major = int(m.group(1))
    # Apple jumped from iOS 18 to iOS 26 (year-based numbering) in 2025.
    if major < 18:
        out.append(Finding(
            "high", "System", f"iOS {ver} is out of date",
            "This iOS version no longer receives all security fixes. Most iPhone "
            "spyware relies on vulnerabilities that updates have already fixed.",
            "Settings > General > Software Update. If the phone can't update, consider replacing it.",
        ))
    else:
        out.append(Finding(
            "info", "System", f"iOS {ver}",
            "Make sure this is the latest version available for your iPhone.",
            "Settings > General > Software Update; turn on Automatic Updates.",
        ))


# ---------------------------------------------------------------------------
# Jailbreak
# ---------------------------------------------------------------------------

JAILBREAK_APPS = {
    "com.saurik.cydia": "Cydia",
    "org.coolstar.sileostore": "Sileo",
    "org.coolstar.sileo": "Sileo",
    "xyz.willy.zebra": "Zebra",
    "com.opa334.trollstore": "TrollStore",
    "com.opa334.dopamine": "Dopamine jailbreak",
    "com.opa334.dopamine.roothide": "Dopamine jailbreak",
    "science.xnu.undecimus": "unc0ver jailbreak",
    "org.coolstar.electra1141": "Electra jailbreak",
    "com.electrateam.chimera": "Chimera jailbreak",
    "com.tigisoftware.filza": "Filza file manager (jailbreak tool)",
    "kr.h4ck.jailbreak": "jailbreak loader",
}
JAILBREAK_PATHS = re.compile(
    r"(^|/)(var/jb|Library/MobileSubstrate|Library/Cydia|Applications/Cydia\.app|"
    r"\.installed_dopamine|\.bootstrapped|private/preboot/[^/]+/jb-)",
    re.I,
)


def check_jailbreak(b: Backup, apps: list[str], out: list[Finding]):
    hits = [f"{a} ({JAILBREAK_APPS[a.lower()]})" for a in apps if a.lower() in JAILBREAK_APPS]
    paths = []
    for domain, rel in b.all_paths():
        if rel and JAILBREAK_PATHS.search(rel):
            paths.append(f"{domain}: {rel}")
    if hits or paths:
        out.append(Finding(
            "critical", "Jailbreak",
            "Signs that this iPhone is (or was) jailbroken",
            "A jailbreak removes iOS security protections. Full-featured iPhone "
            "stalkerware (that reads messages, records calls, etc.) needs a "
            "jailbreak to install. If YOU did not jailbreak this phone, assume "
            "someone with physical access did.",
            "Back up photos/contacts, then erase the phone and update iOS: "
            "Settings > General > Transfer or Reset iPhone > Erase All Content and Settings. "
            "Don't restore from a backup made after the jailbreak.",
            evidence=_limit(hits + paths),
        ))


# ---------------------------------------------------------------------------
# Configuration profiles / MDM
# ---------------------------------------------------------------------------

PAYLOAD_RISK = {
    "com.apple.mdm": ("high", "Mobile Device Management (MDM) - a remote server can manage this phone, see installed apps, push settings and apps"),
    "com.apple.security.root": ("high", "Installs a root certificate - can let someone intercept and read encrypted web traffic"),
    "com.apple.security.pem": ("high", "Installs a certificate - may allow traffic interception"),
    "com.apple.security.pkcs1": ("medium", "Installs a certificate"),
    "com.apple.proxy.http.global": ("high", "Forces all web traffic through a proxy server"),
    "com.apple.vpn.managed": ("medium", "Configures a VPN - all traffic may be routed through someone else's server"),
    "com.apple.vpn.managed.applayer": ("medium", "Per-app VPN"),
    "com.apple.dnsSettings.managed": ("medium", "Forces DNS through a specific server - can log every site you visit"),
    "com.apple.webcontent-filter": ("medium", "Web content filter - can monitor or block browsing"),
    "com.apple.applicationaccess": ("low", "Restrictions on what the phone can do"),
    "com.apple.app.lock": ("medium", "Locks the phone into one app (kiosk mode)"),
    "com.apple.supervision": ("high", "Supervision - allows much deeper remote control"),
}


def _walk_payloads(obj, found: list[dict]):
    if isinstance(obj, dict):
        if "PayloadType" in obj:
            found.append(obj)
        for v in obj.values():
            _walk_payloads(v, found)
    elif isinstance(obj, list):
        for v in obj:
            _walk_payloads(v, found)
    elif isinstance(obj, bytes) and obj[:6] in (b"bplist", b"<?xml "):
        try:
            _walk_payloads(plistlib.loads(obj), found)
        except Exception:
            pass


def check_profiles(b: Backup, out: list[Finding], coverage: dict, ind: Indicators | None = None):
    payloads: list[dict] = []
    events: list[str] = []
    supervised = None
    n_files = 0
    for fid, domain, rel, flags in b.files(PROFILE_DOMAIN, "Library/ConfigurationProfiles/%"):
        if flags != 1:
            continue
        n_files += 1
        data = b.read_id(fid)
        if not data:
            continue
        try:
            pl = plistlib.loads(data)
        except Exception:
            continue
        name = rel.rsplit("/", 1)[-1]
        if name == "MCProfileEvents.plist":
            for ev in pl.get("ProfileEvents", []) if isinstance(pl, dict) else []:
                for pid, e in (ev.items() if isinstance(ev, dict) else []):
                    if isinstance(e, dict):
                        events.append(f"{e.get('timestamp', '?')}  {e.get('operation', '?')}  {pid}  (by {e.get('process', '?')})")
            continue
        if name == "CloudConfigurationDetails.plist" and isinstance(pl, dict):
            if pl.get("IsSupervised") or pl.get("ConfigurationURL"):
                supervised = pl
            continue
        _walk_payloads(pl, payloads)
    coverage["Configuration profiles"] = f"{n_files} file(s) checked" if n_files else "none found"

    # group by top-level profile
    profiles: dict[str, dict] = {}
    for p in payloads:
        ident = p.get("PayloadIdentifier") or p.get("PayloadUUID") or repr(sorted(p.keys()))
        if p.get("PayloadType") == "Configuration" or ident not in profiles:
            profiles.setdefault(ident, {"meta": p, "types": set()})
        profiles[ident]["types"].add(p.get("PayloadType"))
    # collapse sub-payloads into their parent profile when identifiers nest
    tops = {k: v for k, v in profiles.items() if v["meta"].get("PayloadType") == "Configuration"} or profiles
    for ident, prof in tops.items():
        types = set()
        for k, v in profiles.items():
            if k == ident or k.startswith(ident + "."):
                types |= v["types"]
        types.discard("Configuration")
        m = prof["meta"]
        sev, reasons = "low", []
        for t in sorted(types):
            if t in PAYLOAD_RISK:
                s, why = PAYLOAD_RISK[t]
                reasons.append(f"{t}: {why}")
                if SEVERITIES.index(s) < SEVERITIES.index(sev):
                    sev = s
            else:
                reasons.append(t)
        ioc = None
        if ind is not None:
            for k, v in profiles.items():
                if k == ident or k.startswith(ident + "."):
                    uuid = str(v["meta"].get("PayloadUUID", ""))
                    ioc = ioc or ind.match("configuration-profile:id", uuid) or ind.match("configuration-profile:id", k)
        if ioc:
            sev = "critical"
            reasons.insert(0, f"matches known spyware profile -> {ioc}")
        title = m.get("PayloadDisplayName") or ident
        org = m.get("PayloadOrganization")
        out.append(Finding(
            sev, "Profiles",
            f"Configuration profile installed: {title}" + (f" ({org})" if org else ""),
            "Configuration profiles can change deep system settings. They are normal on "
            "work/school phones, but a profile you don't recognise is a classic way to "
            "monitor an iPhone without installing an app.",
            "Settings > General > VPN & Device Management. Remove any profile you don't "
            "recognise (on a work phone, ask your IT department first).",
            evidence=[f"identifier: {ident}"] + reasons,
        ))
    if supervised:
        out.append(Finding(
            "high", "Profiles", "This iPhone is supervised / enrolled in remote management",
            "Supervised iPhones can be monitored and controlled much more deeply. "
            "Expected for company or school phones; suspicious on a personal phone.",
            "If this is your personal phone, erase it and set it up again as new.",
            evidence=[f"{k}: {supervised.get(k)}" for k in ("IsSupervised", "OrganizationName", "ConfigurationURL") if k in supervised],
        ))
    if events:
        out.append(Finding("info", "Profiles", "Profile install/remove history", evidence=_limit(events)))


# ---------------------------------------------------------------------------
# Spyware indicator matching
# ---------------------------------------------------------------------------

def _ioc_finding(category, title, hits, advice=None):
    malware = sorted({h[1] for h in hits})
    return Finding(
        "critical", category, title,
        "Matched public indicators of compromise for: " + ", ".join(malware),
        advice or (
            "This is a strong warning sign. If you may be targeted by government-grade "
            "spyware (Pegasus, Predator...), contact Amnesty Tech's Security Lab or "
            "Access Now's Digital Security Helpline (accessnow.org/help) BEFORE erasing "
            "the phone, so the evidence can be verified. Turn on Lockdown Mode: "
            "Settings > Privacy & Security > Lockdown Mode."
        ),
        evidence=_limit([f"{h[0]}  ->  {h[1]}" for h in hits]),
    )


def _stalkerware_advice():
    return ("A stalkerware website/account appears in this phone's data. Someone may "
            "have tried to set up monitoring. Change your Apple ID password, check the "
            "devices signed into your Apple ID, and run Safety Check (Settings > "
            "Privacy & Security > Safety Check). If you're in an abusive situation, "
            "make a safety plan before removing anything; the abuser may notice.")


def check_installed_app_iocs(apps, ind: Indicators, out):
    hits = [(a, m) for a in apps if (m := ind.match("app:id", a))]
    if hits:
        out.append(_ioc_finding("Spyware", "Installed app matches known spyware/stalkerware", hits,
                                "Delete the app (press and hold the icon > Remove App), then follow the "
                                "steps in the 'Account security' checklist."))


def check_urls(b: Backup, ind: Indicators, out, coverage):
    sources = []  # (label, list of (url, when))

    # Safari history (encrypted backups only)
    conn = b.sqlite("HomeDomain", "Library/Safari/History.db")
    if conn:
        try:
            rows = conn.execute(
                "SELECT i.url, v.visit_time FROM history_items i "
                "LEFT JOIN history_visits v ON v.history_item = i.id").fetchall()
            sources.append(("Safari history", rows))
        except Exception:
            pass
        conn.close()
    coverage["Safari history"] = f"{len(sources[-1][1])} visits" if conn and sources else (
        "not in backup (needs an encrypted backup)" if not b.encrypted else "not found")

    # Chrome history
    chrome = None
    for fid, domain, rel, flags in b.files("AppDomain-com.google.chrome.ios", "%/History"):
        chrome = (domain, rel)
    if chrome:
        conn = b.sqlite(*chrome)
        if conn:
            try:
                rows = conn.execute("SELECT url, last_visit_time FROM urls").fetchall()
                sources.append(("Chrome history", [(u, None) for u, _ in rows]))
                coverage["Chrome history"] = f"{len(rows)} URLs"
            except Exception:
                pass
            conn.close()

    # Messages / iMessage
    conn = b.sqlite("HomeDomain", "Library/SMS/sms.db")
    sms_rows = []
    if conn:
        try:
            for text, date, handle in conn.execute(
                    "SELECT m.text, m.date, h.id FROM message m LEFT JOIN handle h ON m.handle_id = h.ROWID"):
                for u in URL_RE.findall(text or ""):
                    sms_rows.append((u, date))
                if handle and ind.match("email-addr:value", handle):
                    out.append(_ioc_finding("Spyware", "Message from an account used by spyware operators",
                                            [(handle, ind.match("email-addr:value", handle))]))
            sources.append(("Messages", sms_rows))
            coverage["Messages (SMS/iMessage)"] = f"{len(sms_rows)} links checked"
        except Exception:
            coverage["Messages (SMS/iMessage)"] = "could not read"
        conn.close()
    else:
        coverage["Messages (SMS/iMessage)"] = "not found"

    # WebKit resource load statistics: domains loaded by Safari and in-app browsers
    wk = 0
    for fid, domain, rel, flags in b.files("%", "%ResourceLoadStatistics/observations.db"):
        conn = b.sqlite(domain, rel)
        if not conn:
            continue
        try:
            rows = conn.execute("SELECT registrableDomain, mostRecentUserInteractionTime FROM ObservedDomains").fetchall()
            wk += len(rows)
            sources.append((f"Web data ({domain})", rows))
        except Exception:
            pass
        conn.close()
    coverage["Websites loaded in apps (WebKit)"] = f"{wk} domains" if wk else "not found"

    for label, rows in sources:
        hits, seen = [], set()
        for url, when in rows:
            m = ind.match_url(url)
            if m and url not in seen:
                seen.add(url)
                hits.append((f"{url}" + (f"  [{_apple_ts(when)}]" if when else ""), m[1]))
        if hits:
            stalker = all(ind.is_stalkerware(name) for _, name in hits)
            out.append(_ioc_finding("Spyware", f"{label}: link/domain linked to spyware or stalkerware", hits,
                                    _stalkerware_advice() if stalker else None))


def check_processes(b: Backup, ind: Indicators, out, coverage):
    conn = b.sqlite("WirelessDomain", "Library/Databases/DataUsage.sqlite")
    if not conn:
        coverage["Network usage by process"] = "not found"
        return
    hits = []
    try:
        cols = _columns(conn, "ZPROCESS")
        ts = "ZFIRSTTIMESTAMP" if "ZFIRSTTIMESTAMP" in cols else "NULL"
        rows = conn.execute(f"SELECT ZPROCNAME, ZBUNDLENAME, {ts} FROM ZPROCESS").fetchall()
        coverage["Network usage by process"] = f"{len(rows)} processes"
        for proc, bundle, first in rows:
            for v in (proc, bundle):
                if v and (m := ind.match("process:name", v.split("/")[0])):
                    hits.append((f"{v}  [first seen {_apple_ts(first)}]", m))
    except Exception:
        coverage["Network usage by process"] = "could not read"
    conn.close()
    if hits:
        out.append(_ioc_finding("Spyware", "Process name matches known spyware", hits))


DOMAIN_ROOTS = {"HomeDomain": "/private/var/mobile/", "RootDomain": "/private/var/root/",
                "MediaDomain": "/private/var/mobile/", "WirelessDomain": "/private/var/wireless/",
                "SystemPreferencesDomain": "/private/var/preferences/"}


def check_file_iocs(b: Backup, ind: Indicators, out):
    names = ind.by_type.get("file:name", {})
    paths = ind.by_type.get("file:path", {})
    if not names and not paths:
        return
    dir_iocs = [(k, v) for k, v in paths.items() if k.endswith("/")]
    hits = []
    for domain, rel in b.all_paths():
        if not rel:
            continue
        base = rel.rsplit("/", 1)[-1].lower()
        full = (DOMAIN_ROOTS.get(domain, "") + rel).lower() if domain in DOMAIN_ROOTS else None
        if base in names:
            hits.append((f"{domain}: {rel}", names[base]))
        elif full and full in paths:
            hits.append((f"{domain}: {rel}", paths[full]))
        elif full:
            for d, mal in dir_iocs:
                if full.startswith(d) or full + "/" == d:
                    hits.append((f"{domain}: {rel}", mal))
                    break
    if hits:
        out.append(_ioc_finding("Spyware", "File matches known spyware artifact", hits))


# ---------------------------------------------------------------------------
# Privacy permissions (TCC)
# ---------------------------------------------------------------------------

TCC_SERVICES = {
    "kTCCServiceMicrophone": "Microphone",
    "kTCCServiceCamera": "Camera",
    "kTCCServiceAddressBook": "Contacts",
    "kTCCServicePhotos": "Photos",
    "kTCCServiceCalendar": "Calendar",
    "kTCCServiceReminders": "Reminders",
    "kTCCServiceMediaLibrary": "Media library",
    "kTCCServiceMotion": "Motion & fitness",
    "kTCCServiceBluetoothAlways": "Bluetooth",
    "kTCCServiceSpeechRecognition": "Speech recognition",
}
SENSITIVE = {"kTCCServiceMicrophone", "kTCCServiceCamera", "kTCCServiceAddressBook", "kTCCServicePhotos"}


def check_permissions(b: Backup, out, coverage):
    conn = b.sqlite("HomeDomain", "Library/TCC/TCC.db")
    if not conn:
        coverage["App permissions"] = "not in backup (needs an encrypted backup)" if not b.encrypted else "not found"
        return
    try:
        cols = _columns(conn, "access")
        allowed = "auth_value = 2" if "auth_value" in cols else "allowed = 1"
        rows = conn.execute(f"SELECT service, client FROM access WHERE {allowed}").fetchall()
    except Exception:
        coverage["App permissions"] = "could not read"
        conn.close()
        return
    conn.close()
    coverage["App permissions"] = f"{len(rows)} grants"
    per_app: dict[str, set] = {}
    for service, client in rows:
        if client and not client.startswith("com.apple.") and service in TCC_SERVICES:
            per_app.setdefault(client, set()).add(service)
    heavy = sorted((a, s) for a, s in per_app.items() if len(s & SENSITIVE) >= 3)
    if heavy:
        out.append(Finding(
            "low", "Permissions", "Apps with access to microphone, camera, contacts and/or photos",
            "Usually harmless (messaging and social apps need these), but review any app you don't recognise.",
            "Settings > Privacy & Security - open each category and switch off apps that don't need it.",
            evidence=[f"{a}: {', '.join(sorted(TCC_SERVICES[x] for x in s))}" for a, s in heavy],
        ))


# ---------------------------------------------------------------------------

ACCOUNT_CHECKLIST = [
    "Apple ID devices: Settings > [your name] - scroll down. Remove any device you don't own.",
    "Safety Check: Settings > Privacy & Security > Safety Check - review who you share location, photos and data with, and reset access.",
    "Find My: open Find My > People - stop sharing location with anyone unexpected.",
    "Family Sharing: Settings > [your name] > Family - check who is in your family group and whether location sharing is on.",
    "Change your Apple ID password and make sure two-factor authentication uses only YOUR phone numbers (Settings > [your name] > Sign-In & Security).",
    "Change the phone's passcode if anyone else might know it. Spyware and iCloud-based monitoring usually begin with someone knowing it.",
    "Unknown AirTag / tracker alerts: Find My > Items > Identify Found Item, or check for 'Item Detected Near You' notifications.",
    "iCloud backup monitoring: commercial 'no-jailbreak' iPhone spy services work by logging into your iCloud. Changing your Apple ID password and removing unknown devices cuts them off.",
    "High risk (journalist, activist, etc.)? Turn on Lockdown Mode: Settings > Privacy & Security > Lockdown Mode.",
]


def run_all(b: Backup, ind: Indicators) -> ScanResult:
    out: list[Finding] = []
    coverage: dict[str, str] = {}
    apps = installed_apps(b)
    coverage["Installed apps"] = f"{len(apps)} apps"
    check_ios_version(b, out)
    check_jailbreak(b, apps, out)
    check_profiles(b, out, coverage, ind)
    if len(ind):
        check_installed_app_iocs(apps, ind, out)
        check_urls(b, ind, out, coverage)
        check_processes(b, ind, out, coverage)
        check_file_iocs(b, ind, out)
    else:
        out.append(Finding(
            "medium", "Scanner", "No spyware indicators loaded - spyware signature checks were skipped",
            advice="Run:  python3 scan_iphone.py update   (needs internet), then scan again.",
        ))
    check_permissions(b, out, coverage)
    if not b.encrypted:
        out.append(Finding(
            "medium", "Scanner", "Backup is not encrypted - many checks had limited data",
            "Unencrypted iPhone backups leave out browsing history, app permissions and "
            "other data the scanner needs.",
            "Turn on 'Encrypt local backup' in Finder / iTunes / Apple Devices (or "
            "`idevicebackup2 -i encryption on`), make a new backup, and scan it with --password.",
        ))
    out.sort(key=lambda f: SEVERITIES.index(f.severity))
    return ScanResult(device_info(b), apps, out, coverage, len(ind))
