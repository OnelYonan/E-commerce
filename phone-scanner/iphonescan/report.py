"""Render scan results as terminal text, JSON or a standalone HTML page."""

from __future__ import annotations

import dataclasses
import html
import json
import os
import sys

from .checks import ACCOUNT_CHECKLIST, ScanResult

VERDICTS = {
    "critical": ("DANGER", "Strong signs of spyware, stalkerware or a jailbreak were found."),
    "high": ("WARNING", "Settings that allow monitoring were found. Review them carefully."),
    "medium": ("CHECK", "Nothing malicious was found, but some items need your attention."),
    "low": ("LOOKS OK", "No spyware found. A few minor things to review."),
    None: ("LOOKS OK", "No spyware, stalkerware or tracking settings were found in this backup."),
}

_COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m",
           "low": "\033[36m", "info": "\033[2m", "ok": "\033[1;32m", "bold": "\033[1m", "end": "\033[0m"}


def _c(name: str, text: str, enabled: bool) -> str:
    return f"{_COLORS[name]}{text}{_COLORS['end']}" if enabled else text


def to_text(r: ScanResult, color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    d = r.device
    worst = r.worst()
    verdict, summary = VERDICTS[worst]
    lines = [
        "",
        _c("bold", "iPhone security scan", color),
        f"  Device:  {d['name']}  ({d['model']}, iOS {d['ios_version']})",
        f"  Backup:  {d['last_backup']}  ({'encrypted' if d['encrypted_backup'] else 'NOT encrypted'})",
        f"  Signatures loaded: {r.indicator_count}",
        "",
        "Checked:",
    ]
    lines += [f"  - {k}: {v}" for k, v in r.coverage.items()]
    lines += ["", _c(worst or "ok", f" RESULT: {verdict} ", color) + "  " + summary, ""]
    for f in r.findings:
        tag = _c(f.severity, f"[{f.severity.upper()}]", color)
        lines.append(f"{tag} {f.category}: {f.title}")
        if f.detail:
            lines.append(f"    {f.detail}")
        for e in f.evidence:
            lines.append(f"      * {e}")
        if f.advice:
            lines.append(f"    What to do: {f.advice}")
        lines.append("")
    lines.append(_c("bold", "Also check these yourself (a backup can't show them):", color))
    lines += [f"  [ ] {item}" for item in ACCOUNT_CHECKLIST]
    lines.append("")
    return "\n".join(lines)


def to_json(r: ScanResult) -> str:
    return json.dumps(dataclasses.asdict(r) | {"verdict": VERDICTS[r.worst()][0]}, indent=2, default=str)


def to_html(r: ScanResult) -> str:
    e = html.escape
    worst = r.worst()
    verdict, summary = VERDICTS[worst]
    d = r.device
    cards = []
    for f in r.findings:
        ev = "".join(f"<li><code>{e(x)}</code></li>" for x in f.evidence)
        cards.append(
            f'<section class="f {f.severity}"><div class="h"><span class="sev">{f.severity}</span>'
            f"<span class=cat>{e(f.category)}</span><h3>{e(f.title)}</h3></div>"
            + (f"<p>{e(f.detail)}</p>" if f.detail else "")
            + (f"<ul class=ev>{ev}</ul>" if ev else "")
            + (f'<p class="adv"><b>What to do:</b> {e(f.advice)}</p>' if f.advice else "")
            + "</section>"
        )
    cov = "".join(f"<tr><td>{e(k)}</td><td>{e(v)}</td></tr>" for k, v in r.coverage.items())
    todo = "".join(f"<li><label><input type=checkbox> {e(x)}</label></li>" for x in ACCOUNT_CHECKLIST)
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>iPhone Security Scan</title><style>
:root{{--bg:#f7f7f8;--card:#fff;--fg:#1d1d1f;--mut:#6e6e73;--bd:#e3e3e8;
--critical:#c4141a;--high:#d9480f;--medium:#b7791f;--low:#1c7ed6;--info:#868e96;--ok:#2b8a3e}}
@media (prefers-color-scheme:dark){{:root{{--bg:#111113;--card:#1c1c1f;--fg:#f2f2f5;--mut:#a1a1a8;--bd:#2e2e33}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif}}
main{{max-width:860px;margin:0 auto;padding:24px 16px 64px}}h1{{margin:0 0 4px;font-size:26px}}
.mut{{color:var(--mut)}}.verdict{{margin:20px 0;padding:18px 20px;border-radius:12px;color:#fff;
background:var(--{worst or 'ok'})}}.verdict b{{font-size:20px;display:block}}
.f{{background:var(--card);border:1px solid var(--bd);border-left:5px solid var(--info);border-radius:10px;
padding:14px 16px;margin:12px 0}}.f.critical{{border-left-color:var(--critical)}}.f.high{{border-left-color:var(--high)}}
.f.medium{{border-left-color:var(--medium)}}.f.low{{border-left-color:var(--low)}}
.h{{display:flex;flex-wrap:wrap;gap:8px;align-items:baseline}}.h h3{{margin:0;font-size:16px;flex-basis:100%}}
.sev{{text-transform:uppercase;font-size:11px;font-weight:700;letter-spacing:.05em}}
.critical .sev{{color:var(--critical)}}.high .sev{{color:var(--high)}}.medium .sev{{color:var(--medium)}}
.low .sev{{color:var(--low)}}.info .sev{{color:var(--info)}}.cat{{font-size:12px;color:var(--mut)}}
.ev{{margin:8px 0;padding-left:18px;font-size:13px}}code{{word-break:break-all}}.adv{{margin:8px 0 0}}
table{{border-collapse:collapse;width:100%;background:var(--card);border-radius:10px;overflow:hidden}}
td{{padding:6px 12px;border-bottom:1px solid var(--bd);vertical-align:top}}ul.todo{{padding-left:0;list-style:none}}
ul.todo li{{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:8px 12px;margin:6px 0}}
</style></head><body><main>
<h1>iPhone security scan</h1>
<div class=mut>{e(str(d['name']))} &middot; {e(str(d['model']))} &middot; iOS {e(str(d['ios_version']))}
&middot; backup {e(str(d['last_backup']))} &middot; {'encrypted' if d['encrypted_backup'] else 'not encrypted'}</div>
<div class=verdict><b>{verdict}</b>{e(summary)}</div>
<h2>Findings</h2>{''.join(cards) or '<p>No findings.</p>'}
<h2>Also check these yourself</h2><p class=mut>Most iPhone tracking works through your Apple ID or shared
location rather than an installed app, and a backup can't show that.</p><ul class=todo>{todo}</ul>
<h2>What was checked</h2><table>{cov}<tr><td>Spyware signatures</td><td>{r.indicator_count}</td></tr></table>
<p class=mut>This scan looks for known indicators and risky settings. A clean result lowers the risk but
can't prove a phone is clean: brand-new spyware may have no public indicators yet.</p>
</main></body></html>"""
