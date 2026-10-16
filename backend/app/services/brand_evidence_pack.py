"""Evidence pack for one look-alike (plan step 8.2): a self-contained record of what we observed, when, and from where, that someone else
(a registrar, a host, a lawyer) can read without access to ZoneProof.

Pure functions. `build` assembles a JSON-able dict and stamps it with a SHA-256 of its own canonical content, so a copy can be checked
for tampering later; `render_html` lays the same dict out for the PDF, hash on every page. The hash proves the copy is unchanged since
we produced it. It does NOT prove the observations are true, and the pack says so.

What the pack never contains: the brand owner's contact details, other tenants' data, or anything we did not observe. Things we did not
check (page content, screenshots, WHOIS contact data) are listed under `not_checked` rather than left out silently."""
from __future__ import annotations

import hashlib
import html as _html
import json
from datetime import datetime

PACK_VERSION = 1

NOT_CHECKED = [
    "What the website serves (page content, login forms, screenshots): ZoneProof does not fetch or render the page yet.",
    "Who registered the domain: registrant contact data is usually redacted and is not recorded here.",
    "Whether any person received a message from this domain: only public infrastructure is observed.",
]
LIMITS = (
    "Every observation below is from public sources (DNS, certificate transparency, public blocklists, registration data) at the time shown. "
    "The integrity hash shows this document is unchanged since it was generated; it does not prove the observations are correct. "
    "The verdict and the weights behind it are ZoneProof's assessment, and some weights are assumptions, marked as such."
)


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def content_hash(body: dict) -> str:
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


def build(*, brand: dict, candidate: dict, evidence: list[dict], timeline: list[dict], threat: dict, campaign: dict | None, generated_at: datetime, generated_by: str,
          issuer: dict | None = None) -> dict:
    body = {
        "pack_version": PACK_VERSION,
        "generated_at": generated_at.isoformat(),
        "generated_by": generated_by,
        "issuer": issuer,                    # white label: who is presenting this pack (an MSP, for a client's brand); None = no issuer line
        "brand": brand,                      # {"name", "official_domains"}
        "subject": candidate,                # domain, verdict, decision, scores, lifecycle stage, first/last seen, sources
        "evidence": evidence,                # every line: signal, summary, weight, observed_at, raw data
        "timeline": timeline,                # when each change was noticed (never an exact time of change)
        "threat": threat,                    # abuse type, impact, attack steps with observed/suspected/not-observed
        "campaign": campaign,                # other look-alikes that share infrastructure, if any
        "not_checked": NOT_CHECKED,
        "limits": LIMITS,
    }
    return {**body, "integrity": {"algorithm": "sha256", "over": "all fields except integrity, canonical JSON (sorted keys, no spaces)", "hash": content_hash(body)}}


def verify(pack: dict) -> bool:
    body = {k: v for k, v in pack.items() if k != "integrity"}
    return pack.get("integrity", {}).get("hash") == content_hash(body)


def _e(v) -> str:
    return _html.escape("" if v is None else str(v))


def render_html(pack: dict) -> str:
    s, b = pack["subject"], pack["brand"]
    rows = "".join(
        f"<tr><td>{_e(x.get('observed_at', '')[:19].replace('T', ' '))}</td><td>{_e(x.get('summary'))}</td><td class='w'>{_e(x.get('weight'))}</td><td class='raw'>{_e(canonical(x.get('data') or {}))}</td></tr>"
        for x in pack["evidence"]
    ) or "<tr><td colspan='4'>No evidence lines recorded.</td></tr>"
    tl = "".join(f"<li><b>{_e(t.get('at', '')[:19].replace('T', ' '))}</b> {_e(t.get('summary'))}</li>" for t in pack["timeline"]) or "<li>No changes recorded.</li>"
    nar = (pack["threat"] or {}).get("narrative", {})
    steps = "".join(f"<li>{_e(st.get('text'))} <b>({_e(str(st.get('status', '')).replace('_', ' '))})</b> {_e(st.get('note'))}</li>" for st in nar.get("steps", []))
    camp = ""
    if pack.get("campaign"):
        c = pack["campaign"]
        camp = f"<h2>Related look-alikes</h2><p>{_e(c.get('summary'))}</p><p class='mono'>{_e(', '.join(c.get('members', [])))}</p>"
    nc = "".join(f"<li>{_e(x)}</li>" for x in pack["not_checked"])
    h = pack["integrity"]["hash"]
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
body{{font:12px/1.5 Helvetica,Arial,sans-serif;color:#1b1f33;margin:0}} h1{{font-size:20px;margin:0 0 4px}} h2{{font-size:14px;margin:18px 0 6px;border-bottom:1px solid #d5d9ea;padding-bottom:3px}}
.mono,.raw{{font-family:Consolas,monospace;font-size:10px;word-break:break-all}} table{{width:100%;border-collapse:collapse}} td,th{{border-bottom:1px solid #e6e9f5;padding:4px 6px;vertical-align:top;text-align:left}}
.w{{text-align:right;width:40px}} .hash{{font-family:Consolas,monospace;font-size:10px;background:#f1f3fb;padding:6px;word-break:break-all}} .lim{{color:#555;font-size:11px}} .issuer{{font-size:11px;color:#555;margin:0 0 6px}}
footer{{position:fixed;bottom:0;font-size:9px;color:#777;font-family:Consolas,monospace}}
</style></head><body>
{f"<p class='issuer'>Prepared by <b>{_e(pack['issuer'].get('name'))}</b></p>" if pack.get('issuer') else ""}
<h1>Evidence pack: {_e(s.get('domain_unicode') or s.get('domain'))}</h1>
<p>Look-alike of <b>{_e(b.get('name'))}</b> ({_e(', '.join(b.get('official_domains', [])))}). Generated {_e(pack['generated_at'][:19].replace('T', ' '))} UTC by {_e(pack['generated_by'])}.</p>
<h2>Assessment</h2>
<p><b>{_e(s.get('verdict'))}</b>. {_e(s.get('why'))}</p>
<p>Decision by a person: {_e(s.get('decision') or 'none yet')}. Lifecycle stage: {_e(s.get('stage'))}. First seen {_e(s.get('first_seen_at', '')[:10])}, last seen {_e(s.get('last_seen_at', '')[:10])}. Found via: {_e(', '.join(s.get('sources', [])))}.</p>
<h2>What we observed</h2><table><tr><th>When</th><th>Observation</th><th class='w'>Weight</th><th>Raw data</th></tr>{rows}</table>
<h2>Timeline</h2><ul>{tl}</ul>
<h2>What it could do</h2><p>{_e(((pack['threat'] or {}).get('impact') or {}).get('text', ''))}</p><ol>{steps}</ol><p class='lim'>{_e(nar.get('summary', ''))} {_e(nar.get('caveat', ''))}</p>
{camp}
<h2>What was not checked</h2><ul>{nc}</ul>
<p class='lim'>{_e(pack['limits'])}</p>
<h2>Integrity</h2><div class='hash'>SHA-256 {_e(h)}</div>
<footer>Evidence pack v{_e(pack['pack_version'])} &middot; {_e(h[:16])}</footer>
</body></html>"""
