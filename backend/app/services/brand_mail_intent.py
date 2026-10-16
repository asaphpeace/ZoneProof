"""
Brand Guard — email intent of a look-alike domain (plan step 2.3; pure functions, no network).

A look-alike with a web page is a lure; a look-alike set up to SEND MAIL is an attack in preparation. Spoofers who
want their mail to land in an inbox publish the same records a legitimate sender does — SPF, a DKIM key, DMARC — and
often hand sending to a bulk-mail service. Those records are public DNS, free to read, and show intent long before
any phishing mail is seen. This module turns the records into evidence:

  spf_published / dkim_published / dmarc_published   authentication set up on a name that is not yours (+5 each)
  esp_sender                                          SPF authorises a bulk-mail service (+10)
  copied_dkim_key                                     publishes the SAME DKIM key as your domain — cloned DNS (+10)
  forwarding_mx                                       mail received through a forwarding relay, not a mailbox host (+5)
  mirrors_mail_provider                               same mail provider as you (0: informative, common to both sides)
  defensive_mail_posture                              "v=spf1 -all" and no mail host: how a careful owner parks a
                                                      look-alike so nobody can send as it (-10, a benign explainer)

The total of the positive intent signals is capped at +25 so mail setup can raise suspicion, never decide it alone.
Weights are hand-set heuristics: abuse scoring cannot be measured offline, so Stage 3 calibrates them. The lists of
bulk-mail services and forwarding relays are hand-curated, not exhaustive.
"""
from __future__ import annotations

import asyncio
import hashlib
import re

from app.services.brand_reasoning import points_for

# DKIM selectors worth probing: the defaults of the big providers (Microsoft 365, Google, Mailchimp/Mandrill, SendGrid,
# generic). A selector can be any string, so absence proves nothing; presence is real evidence.
DKIM_SELECTORS = ("selector1", "selector2", "google", "default", "k1", "s1", "s2", "mail", "dkim", "smtp")

# SPF include/redirect domain fragments -> bulk or transactional mail service.
ESP_INCLUDES = (
    ("sendgrid.net", "SendGrid"), ("mailgun.org", "Mailgun"), ("amazonses.com", "Amazon SES"), ("mcsv.net", "Mailchimp"),
    ("mandrillapp.com", "Mandrill"), ("sparkpostmail.com", "SparkPost"), ("sendinblue.com", "Brevo"), ("brevo.com", "Brevo"),
    ("mailjet.com", "Mailjet"), ("mtasv.net", "Postmark"), ("postmarkapp.com", "Postmark"), ("elasticemail.com", "Elastic Email"),
    ("smtp2go.com", "SMTP2GO"), ("sendpulse.com", "SendPulse"), ("mailerlite.com", "MailerLite"), ("pepipost.com", "Netcore"),
    ("socketlabs.com", "SocketLabs"), ("zeptomail.com", "ZeptoMail"), ("resend.com", "Resend"), ("mailchannels.net", "MailChannels"),
)

# MX host fragments of services that RELAY mail onward rather than host a mailbox — the cheapest way to receive
# replies for a throwaway domain.
FORWARDING_MX = (
    ("improvmx.com", "ImprovMX"), ("forwardemail.net", "Forward Email"), ("registrar-servers.com", "registrar email forwarding"),
    ("mailinator.com", "Mailinator"), ("simplelogin.co", "SimpleLogin"), ("anonaddy.me", "AnonAddy"),
    ("mxrouting.net", "MXRoute"), ("cloudflare.net", "Cloudflare Email Routing"), ("mx.cloudflare.net", "Cloudflare Email Routing"),
    ("guerrillamail.com", "Guerrilla Mail"), ("yopmail.com", "Yopmail"), ("emailforward.com", "email forwarding"),
)

INTENT_SIGNALS = frozenset({
    "spf_published", "dkim_published", "dmarc_published", "esp_sender", "copied_dkim_key", "forwarding_mx",
    "mirrors_mail_provider", "defensive_mail_posture",
})
POSITIVE_CAP = 25.0


def txt_text(rdata: str) -> str:
    """The text of one TXT record from dnspython's string form: '"v=spf1 " "include:x"' -> 'v=spf1 include:x'
    (a TXT record is split into 255-byte chunks that must be rejoined with nothing between them)."""
    chunks = re.findall(r'"((?:[^"\\]|\\.)*)"', rdata or "")
    return "".join(chunks) if chunks else (rdata or "").strip()


def parse_spf(txts: list[str]) -> dict | None:
    """None when no SPF record; else {"record", "includes", "all", "senders"} where `all` is the qualifier on the final
    "all" ("-", "~", "?", "+", or None) and `senders` counts ip4/ip6/a/mx mechanisms."""
    for raw in txts or []:
        text = txt_text(raw)
        if text.lower().startswith("v=spf1"):
            terms = text.split()[1:]
            includes: list[str] = []
            for term in terms:
                low = term.lower()
                if low.startswith("include:"):
                    includes.append(low[8:])
                elif low.startswith("redirect="):
                    includes.append(low[9:])
            all_q = next((t[0] if t[0] in "+-~?" else "+" for t in terms if t.lower().lstrip("+-~?") == "all"), None)
            senders = sum(1 for t in terms if re.match(r"[+\-~?]?(ip4|ip6|a|mx)\b", t.lower()))
            return {"record": text[:300], "includes": includes[:20], "all": all_q, "senders": senders}
    return None


def parse_dmarc(txts: list[str]) -> dict | None:
    for raw in txts or []:
        text = txt_text(raw)
        if text.lower().startswith("v=dmarc1"):
            tags = {k.strip().lower(): v.strip() for k, _, v in (p.partition("=") for p in text.split(";")) if k.strip()}
            return {"policy": (tags.get("p") or "none").lower(), "reports": bool(tags.get("rua") or tags.get("ruf"))}
    return None


def dkim_key_hash(raw: str) -> str | None:
    """SHA-256 of the public key in a DKIM record (None if it holds no key). Equal hashes = the same key."""
    text = txt_text(raw)
    m = re.search(r"(?:^|;)\s*p=([A-Za-z0-9+/=\s]+)", text)
    key = re.sub(r"\s+", "", m.group(1)) if m else ""
    return hashlib.sha256(key.encode()).hexdigest() if key else None


def esp_names(includes: list[str]) -> list[str]:
    found: list[str] = []
    for inc in includes or []:
        for fragment, name in ESP_INCLUDES:
            if (inc == fragment or inc.endswith("." + fragment)) and name not in found:     # a domain boundary, not a substring
                found.append(name)
    return found


def forwarding_mx(mx_hosts: list[str]) -> str | None:
    for host in mx_hosts or []:
        h = host.lower().rstrip(".")
        for fragment, name in FORWARDING_MX:
            if h == fragment or h.endswith("." + fragment):
                return name
    return None


def build_mail_profile(*, spf_txts: list[str], dmarc_txts: list[str], dkim: dict[str, str], mx_hosts: list[str], mail_provider: str | None) -> dict:
    """The mail facts about one domain, in the shape stored on a candidate and on the customer's baseline.
    `dkim` maps a selector that exists to the raw TXT text of its record."""
    spf = parse_spf(spf_txts)
    return {
        "spf": spf, "dmarc": parse_dmarc(dmarc_txts),
        "dkim_selectors": sorted(dkim), "dkim_keys": {sel: h for sel, rec in sorted(dkim.items()) if (h := dkim_key_hash(rec))},
        "esp": esp_names((spf or {}).get("includes", [])), "mx": sorted(h.lower().rstrip(".") for h in mx_hosts or [] if h.strip(".")),    # a null MX ("0 .") is no mail host
        "mail_provider": mail_provider, "forwarding_mx": forwarding_mx(mx_hosts or []),
    }


async def probe_mail(domain: str, query, *, mx_hosts: list[str], mail_provider: str | None, always_dkim: bool = False) -> dict:
    """Read a domain's mail-authentication records through `query(name, rtype) -> (outcome, values)` (the throttled
    resolver the scans use; injected so this stays testable). SPF and DMARC are one lookup each. The ten DKIM selectors
    are probed only when the domain looks mail-capable (it has an MX or an SPF record) — or always for the customer's own
    baseline — so a dormant name costs two queries, not twelve."""
    (spf_state, spf_txts), (dm_state, dm_txts) = await asyncio.gather(query(domain, "TXT"), query(f"_dmarc.{domain}", "TXT"))
    spf_values = spf_txts if spf_state == "answer" else []
    dkim: dict[str, str] = {}
    if always_dkim or mx_hosts or parse_spf(spf_values):
        results = await asyncio.gather(*[query(f"{sel}._domainkey.{domain}", "TXT") for sel in DKIM_SELECTORS])
        for sel, (state, values) in zip(DKIM_SELECTORS, results):
            if state != "answer":
                continue
            record = next((t for t in (txt_text(v) for v in values) if "p=" in t or t.lower().startswith("v=dkim1")), None)
            if record:
                dkim[sel] = record
    return build_mail_profile(spf_txts=spf_values, dmarc_txts=dm_txts if dm_state == "answer" else [], dkim=dkim,
                              mx_hosts=mx_hosts, mail_provider=mail_provider)


def intent_findings(mail: dict | None, baseline_mail: dict | None = None, baseline_provider: str | None = None) -> list[dict]:
    """Evidence about mail intent: [{"signal", "weight", "summary", "data"}]. Positive weights are capped in total."""
    if not mail:
        return []
    out: list[dict] = []
    spf, dmarc = mail.get("spf"), mail.get("dmarc")
    has_mx = bool(mail.get("mx"))
    no_mail_spf = bool(spf) and spf["all"] == "-" and not spf["includes"] and not spf["senders"]

    if no_mail_spf and not has_mx:
        out.append({"signal": "defensive_mail_posture", "weight": -10.0, "data": {"dmarc": (dmarc or {}).get("policy")},
                    "summary": "Publishes a “no mail is sent from here” SPF record and has no mail host — how a careful owner parks a look-alike so nobody can send as it."})
        return out        # a parked-and-locked domain is not preparing to send; nothing else about its mail is evidence of intent

    if spf:
        out.append({"signal": "spf_published", "weight": 5.0, "data": {"all": spf["all"]},
                    "summary": "Publishes an SPF record — set up to send mail as this domain."})
    if mail.get("dkim_selectors"):
        out.append({"signal": "dkim_published", "weight": 5.0, "data": {"selectors": mail["dkim_selectors"]},
                    "summary": f"Publishes DKIM signing keys ({', '.join(mail['dkim_selectors'][:3])}) — set up to sign outgoing mail."})
    if dmarc:
        out.append({"signal": "dmarc_published", "weight": 5.0, "data": {"policy": dmarc["policy"]},
                    "summary": f"Publishes a DMARC policy (p={dmarc['policy']}) — someone configured mail authentication on a name that is not yours."})
    if mail.get("esp"):
        out.append({"signal": "esp_sender", "weight": points_for("esp_sender", 10.0), "data": {"services": mail["esp"]},
                    "summary": f"Its SPF record authorises a bulk-mail service ({', '.join(mail['esp'])}) — set up to send mail in volume."})
    mine = (baseline_mail or {}).get("dkim_keys") or {}
    copied = sorted(sel for sel, h in (mail.get("dkim_keys") or {}).items() if h and h in set(mine.values()))
    if copied:
        out.append({"signal": "copied_dkim_key", "weight": 10.0, "data": {"selectors": copied},
                    "summary": "Publishes the same DKIM public key as your own domain — your mail DNS was copied. (If this is your own domain, add it to your official domains.)"})
    if mail.get("forwarding_mx"):
        out.append({"signal": "forwarding_mx", "weight": 5.0, "data": {"service": mail["forwarding_mx"]},
                    "summary": f"Receives mail through a forwarding relay ({mail['forwarding_mx']}) rather than a mailbox host — the cheapest way to receive replies for a throwaway domain."})
    if baseline_provider and mail.get("mail_provider") == baseline_provider:
        out.append({"signal": "mirrors_mail_provider", "weight": 0.0, "data": {"provider": baseline_provider},
                    "summary": f"Uses the same mail provider as you ({baseline_provider}). Common to legitimate and spoofing domains alike, so this alone means little."})

    positive = [f for f in out if f["weight"] > 0]
    total = sum(f["weight"] for f in positive)
    if total > POSITIVE_CAP:                                  # mail setup can raise suspicion, never decide it alone
        scale = POSITIVE_CAP / total
        for f in positive:
            f["weight"] = round(f["weight"] * scale, 1)
    return out
