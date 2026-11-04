# iPhone Spyware & Tracking Scanner

Checks an iPhone for **spyware** (Pegasus, Predator, Operation Triangulation and others),
**stalkerware**, **jailbreaks**, and **tracking/monitoring configuration profiles (MDM)**.
It also gives you a checklist for the account-level tracking that the most common
iPhone spying relies on.

iOS doesn't let any app or USB tool look inside other apps, so this scanner works the
way professional tools such as Amnesty's MVT do: it analyzes a **backup of your iPhone**
on your computer. Nothing is uploaded anywhere. The only network access is downloading
public spyware signatures.

## Easiest way: the Windows app (no Python needed)

1. Back up your iPhone with **Apple Devices** or iTunes, with **Encrypt local backup** ticked (see step 2 below).
2. Download **iPhoneScanner.exe** from this repository's **Releases** page
   (release "iPhone Scanner for Windows (latest build)").
3. Double-click it. If Windows says *"Windows protected your PC"*, click **More info → Run anyway**
   (the app isn't code-signed).
4. Type your backup password and click **Scan my iPhone**. The report opens in your browser and is
   saved in *Documents\iPhone Scanner Reports*.

The `.exe` is built automatically by GitHub Actions (`.github/workflows/build-iphone-scanner.yml`).
With Python installed you can open the same window with `python iPhoneScanner.pyw`.

## Command-line version

## 1. Install

You need Python 3.9+.

```bash
cd phone-scanner
pip install -r requirements.txt   # needed for encrypted backups (recommended)
```

## 2. Make an encrypted backup of the iPhone

An **encrypted** backup includes browsing history, app permissions and other
data the scanner needs. An unencrypted backup gives much less coverage.

| Computer | Steps |
|---|---|
| **Mac** | Connect the iPhone → Finder → select the iPhone → tick **Encrypt local backup** (pick a password you'll remember) → **Back Up Now** |
| **Windows** | Install **Apple Devices** (or iTunes) → connect the iPhone → tick **Encrypt local backup** → **Back Up Now** |
| **Linux** | `sudo apt install libimobiledevice-utils` → `idevicebackup2 -i encryption on` → `idevicebackup2 backup --full ~/iphone-backup` |

## 3. Scan

```bash
python3 scan_iphone.py update            # download the latest spyware signatures
python3 scan_iphone.py scan --html report.html
```

On Mac and Windows the scanner finds the newest backup automatically. Otherwise pass its
folder: `python3 scan_iphone.py scan ~/iphone-backup`. You'll be asked for the backup
password (or use `--password` / the `IPHONE_BACKUP_PASSWORD` environment variable).

Other commands:

```bash
python3 scan_iphone.py list              # show backups found on this computer
python3 scan_iphone.py scan --json out.json
```

Exit code: `0` = nothing serious, `1` = critical/high findings, `2` = error.

## What it checks

| Check | Looks at |
|---|---|
| **Known spyware signatures** | ~11,000 public indicators (domains, process names, files, attacker accounts, profile IDs) from the [MVT indicators index](https://github.com/mvt-project/mvt-indicators): NSO Pegasus, Intellexa Predator, Operation Triangulation, QuaDream, Candiru, Cellebrite, ECHAP stalkerware database, and more |
| Links you visited | Safari & Chrome history, links in SMS/iMessage, websites loaded inside apps |
| Suspicious processes | Per-process network usage records (where Pegasus' `bh` and similar were found) |
| Spyware files | File names and paths left behind by known spyware |
| **Jailbreak** | Cydia, Sileo, Zebra, TrollStore, Dopamine, unc0ver, etc. and jailbreak file paths. Full-featured iPhone stalkerware needs a jailbreak |
| **Configuration profiles / MDM** | Remote management, root certificates (traffic interception), global proxies, VPN/DNS/web filters, supervision |
| App permissions | Third-party apps with microphone + camera + contacts + photos access |
| iOS version | Outdated iOS versions |

## What a backup can't show: check these yourself

Most real-world iPhone spying doesn't install anything. It uses **your Apple ID / iCloud** or
**location sharing**. The report includes this checklist:

- Settings → [your name]: remove devices you don't own; change your Apple ID password.
- Settings → Privacy & Security → **Safety Check**: review and reset who has access.
- Find My → People: stop unexpected location sharing. Check Family Sharing.
- Watch for "AirTag / Item Detected Near You" alerts.
- High-risk? Turn on **Lockdown Mode**.

## Important

- A clean result **lowers the risk but can't prove** a phone is clean. Brand-new spyware
  may not have public indicators yet.
- If you find government-grade spyware, **don't erase the phone first**. Contact
  [Access Now's Digital Security Helpline](https://www.accessnow.org/help/) or
  Amnesty Tech so the evidence can be verified.
- If you're in an abusive relationship, removing stalkerware or changing passwords can alert
  the abuser. Make a safety plan first (e.g. with [stopstalkerware.org](https://stopstalkerware.org/)).

## Development

```bash
python3 -m unittest discover -s tests -v
```

The tests build synthetic plain and encrypted iPhone backups (`tests/fakebackup.py`).
