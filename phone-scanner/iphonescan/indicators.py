"""Download and query public spyware / stalkerware indicators of compromise.

Sources come from the index the Mobile Verification Toolkit project maintains
(https://github.com/mvt-project/mvt-indicators). It covers NSO Pegasus,
Predator, Operation Triangulation, Candiru, Cellebrite, the ECHAP stalkerware
database and more. Files are STIX2 JSON and are cached locally.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit

INDEX_URL = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/indicators.yaml"
RAW = "https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"


def cache_dir() -> Path:
    base = os.environ.get("IPHONESCAN_CACHE") or os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    d = Path(base) / "iphonescan" / "indicators"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "iphonescan"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def parse_index(text: str) -> list[dict]:
    """Minimal parser for mvt-indicators' indicators.yaml (github-type entries)."""
    entries = []
    for block in re.split(r"\n\s*-\s*\n", "\n" + text):
        fields = dict(re.findall(r"^\s*(name|owner|repo|branch|path):\s*(.+?)\s*$", block, re.M))
        if {"owner", "repo", "branch", "path"} <= fields.keys():
            entries.append(fields)
    return entries


def update(progress=print) -> int:
    """Download all indicator files. Returns the number of files fetched."""
    d = cache_dir()
    progress(f"Downloading indicator index from {INDEX_URL}")
    entries = parse_index(_fetch(INDEX_URL).decode("utf-8"))
    ok = 0
    for e in entries:
        url = RAW.format(**e)
        fname = re.sub(r"[^\w.-]", "_", f"{e['owner']}_{e['repo']}_{e['path']}")
        try:
            data = _fetch(url)
            json.loads(data)  # validate
            (d / fname).write_bytes(data)
            ok += 1
            progress(f"  ok   {e.get('name', e['path'])}")
        except Exception as exc:
            progress(f"  FAIL {e.get('name', e['path'])}: {exc}")
    return ok


def age_days() -> float | None:
    """Days since signatures were last downloaded (None if never)."""
    files = list(cache_dir().glob("*.stix2"))
    if not files:
        return None
    import time
    return (time.time() - max(f.stat().st_mtime for f in files)) / 86400


_PATTERN = re.compile(r"([\w-]+:[\w.\-]+)\s*=\s*'((?:[^'\\]|\\.)*)'")


class Indicators:
    """In-memory index: type -> {value(lowercase): malware name}."""

    def __init__(self):
        self.by_type: dict[str, dict[str, str]] = defaultdict(dict)
        self.sources: list[str] = []
        self.source_of: dict[str, str] = {}

    @classmethod
    def load(cls, paths: list[Path] | None = None) -> "Indicators":
        ind = cls()
        if paths is None:
            paths = sorted(cache_dir().glob("*.stix2"))
        for p in paths:
            ind.add_stix(json.loads(Path(p).read_text("utf-8")), Path(p).name)
        return ind

    def add_stix(self, bundle: dict, source: str = "?") -> None:
        objs = bundle.get("objects", [])
        malware = {o["id"]: o.get("name", "?") for o in objs if o.get("type") == "malware"}
        ind_to_mal = {}
        for o in objs:
            if o.get("type") == "relationship" and o.get("target_ref") in malware:
                ind_to_mal[o.get("source_ref")] = malware[o["target_ref"]]
        default = next(iter(malware.values()), source)
        for o in objs:
            if o.get("type") != "indicator":
                continue
            name = ind_to_mal.get(o["id"], default)
            self.source_of.setdefault(name, source)
            for typ, val in _PATTERN.findall(o.get("pattern", "")):
                self.by_type[typ][val.replace("\\'", "'").lower()] = name
        self.sources.append(source)

    def __len__(self):
        return sum(len(v) for v in self.by_type.values())

    # -- matching -------------------------------------------------------------

    def match_domain(self, host: str) -> tuple[str, str] | None:
        """Match a hostname (or any subdomain of it) against domain IOCs."""
        host = (host or "").lower().strip(".")
        domains = self.by_type.get("domain-name:value", {})
        parts = host.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in domains:
                return cand, domains[cand]
        return None

    def match_url(self, url: str) -> tuple[str, str] | None:
        u = (url or "").strip()
        exact = self.by_type.get("url:value", {}).get(u.lower())
        if exact:
            return u, exact
        try:
            host = urlsplit(u if "//" in u else "//" + u).hostname
        except ValueError:
            return None
        if not host:
            return None
        ip = self.by_type.get("ipv4-addr:value", {}).get(host)
        return (host, ip) if ip else self.match_domain(host)

    def is_stalkerware(self, name: str) -> bool:
        return "stalkerware" in self.source_of.get(name, "").lower()

    def match(self, typ: str, value: str) -> str | None:
        return self.by_type.get(typ, {}).get((value or "").lower())


URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)
