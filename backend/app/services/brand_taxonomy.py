"""
Brand Guard — what kind of threat this is, what it could do, and the story of how it was set up (plan step 3.4). Pure; no I/O.

Three things, kept apart from "how much does it resemble your brand" (the identity score):

  abuse type     benign / trademark / impersonation / fraud / phishing / malware, each with its BASIS. Only a public abuse feed or a
                 confirmed reported email can say a thing IS phishing or malware ("reported"); everything else is "suspected" from
                 the name and how the domain is set up, and says so. Nothing here reads a web page (Brand Guard does not yet).
  impact         what the domain could do to people today, in plain words, from what was observed (resolves, mail-ready, HTTPS
                 certificate) plus the reach evidence the customer's own data gives (employee reports, spoofed-mail volume).
                 How many people have actually SEEN it cannot be measured from public data, and the card says that.
  narrative      the attack as ordered steps in the shape PathProof's kill chains use, each marked observed / suspected / not
                 observed / not checked, with a curated ATT&CK technique tag. A step is never shown as happening unless something
                 stored supports it.

The word lists are hand-set heuristics (flagged as such); the ATT&CK tags are a curated best-effort mapping, like
attack_technique_mapping.py: confirm before quoting them as evidence.
"""
from __future__ import annotations

TYPES = {
    "malware": "Malware distribution",
    "phishing": "Phishing",
    "fraud": "Payment fraud",
    "impersonation": "Impersonation",
    "trademark": "Trademark / look-alike squatting",
    "benign": "Probably benign",
    "unclassified": "Not enough to classify",
}
# Hand-set lure vocabularies (heuristics, not measured). Credential lures ask for a login; payment lures ask for money.
CREDENTIAL_WORDS = ("login", "signin", "sign-in", "logon", "verify", "verification", "secure", "security", "account", "auth", "password", "sso", "portal", "update")
PAYMENT_WORDS = ("pay", "payment", "invoice", "refund", "billing", "wallet", "bank", "tax", "fee", "claim", "reward", "prize", "parcel", "delivery", "customs")

_TECHNIQUES = {
    "acquire_domain": ("T1583.001", "Acquire Infrastructure: Domains", "Resource Development"),
    "certificate": ("T1588.004", "Obtain Capabilities: Digital Certificates", "Resource Development"),
    "impersonate": ("T1656", "Impersonation", "Defense Evasion"),
    "deliver": ("T1566.002", "Phishing: Spearphishing Link", "Initial Access"),
    "harvest": ("T1598.003", "Phishing for Information: Spearphishing Link", "Reconnaissance"),
}


def _by_signal(evidence) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for e in evidence:
        d = e if isinstance(e, dict) else {"signal": e.signal, "weight": e.weight, "data": e.data or {}, "summary": e.summary}
        out[d["signal"]] = d
    return out


def _label_words(domain: str, words) -> list[str]:
    label = domain.lower().split(".")[0]
    return [w for w in words if w in label]


def classify_abuse_type(*, domain: str, evidence, enrichment: dict | None, verdict_key: str, identity: float, stage: str | None) -> dict:
    """{"type", "label", "basis": "reported" | "suspected" | "assumed", "reasons": [...], "not_used": [...]}"""
    e = enrichment or {}
    sig = _by_signal(evidence)
    feeds = {f.get("feed") for f in (e.get("feeds") or [])}
    confirmed_report = any(r.get("disposition") == "confirmed_malicious" for r in (e.get("reported_emails") or []))
    cred, pay = _label_words(domain, CREDENTIAL_WORDS), _label_words(domain, PAYMENT_WORDS)
    mail_ready = bool(e.get("has_mx")) or any(s in sig for s in ("spf_published", "esp_sender", "dkim_published"))
    live = bool(e.get("has_a") or e.get("has_mx"))
    reasons: list[str] = []
    not_used = ["Web page content (Brand Guard does not read pages yet), so nothing below says what the page actually shows."]

    def out(kind: str, basis: str) -> dict:
        return {"type": kind, "label": TYPES[kind], "basis": basis, "reasons": reasons, "not_used": not_used}

    if "urlhaus" in feeds:
        reasons.append("abuse.ch URLhaus lists this host as distributing malware.")
        return out("malware", "reported")
    if "phishunt" in feeds or confirmed_report:
        reasons.append("A public phishing feed lists it." if "phishunt" in feeds else "Your team confirmed a reported email from it as malicious.")
        return out("phishing", "reported")
    if verdict_key == "likely_harmless":
        reasons.append("A strong benign explanation applies (a well-known site, or your own infrastructure).")
        return out("benign", "suspected")
    if identity < 40 and not live:
        reasons.append("It does not resemble your brand strongly and shows no setup.")
        return out("unclassified", "assumed")
    if cred and live:
        reasons.append(f"The name carries credential words ({', '.join(cred)}) and the domain is live.")
        if "class_prior" in sig:
            reasons.append("It is visually identical to your brand (an assumed, not measured, prior).")
        return out("phishing", "suspected")
    if pay and live:
        reasons.append(f"The name carries payment or delivery words ({', '.join(pay)}) and the domain is live.")
        return out("fraud", "suspected")
    if mail_ready and identity >= 55:
        reasons.append("It reads like your brand and has mail set up, so it could send email as you.")
        return out("impersonation", "suspected")
    if identity >= 40:
        why = "dormant (registered, nothing live)" if not live else "live with no sign of deception beyond the name"
        reasons.append(f"It resembles your brand but is {why}: the pattern of look-alike squatting.")
        if "parked" in sig:
            reasons.append("Its nameservers belong to a parking service.")
        return out("trademark", "suspected")
    reasons.append("Not enough evidence to say what it is for.")
    return out("unclassified", "assumed")


def impact_card(*, enrichment: dict | None, evidence, stage: str | None) -> dict:
    """What it could do to people today, from observed facts, and the reach evidence we do have."""
    e = enrichment or {}
    sig = _by_signal(evidence)
    can: list[str] = []
    if e.get("has_mx") or "esp_sender" in sig:
        can.append("send and receive email that appears to come from this name")
    if e.get("has_a") or e.get("has_aaaa"):
        can.append("serve a website on this name" + (" over HTTPS" if e.get("ct_hit") or e.get("ct_cert_issued_at") else ""))
    level = "high" if (e.get("has_mx") and (e.get("has_a") or e.get("ct_hit"))) else "medium" if can else "low"
    reports = e.get("reported_emails") or []
    spoof = (sig.get("same_network_as_spoofer") or {}).get("data") or {}
    reach = {
        "employee_reports": len(reports),
        "spoofed_messages": int(spoof.get("messages", 0)) if spoof.get("match") == "address" else 0,
        "known": [],
        "cannot_measure": "How many people have seen this domain, or been fooled by it, cannot be measured from public data.",
    }
    if reports:
        reach["known"].append(f"{len(reports)} email(s) from it were reported by your own team.")
    if reach["spoofed_messages"]:
        reach["known"].append(f"{reach['spoofed_messages']} message(s) pretending to be your domain came from the same server address.")
    return {"level": level, "can": can, "reach": reach,
            "text": ("It could " + " and ".join(can) + ".") if can else "It is registered but shows no live website or mail yet, so it cannot do anything today."}


def _step(key: str, text: str, status: str, refs: list[str], note: str = "") -> dict:
    tid, name, tactic = _TECHNIQUES[key]
    return {"key": key, "text": text, "status": status, "evidence": refs, "note": note, "technique": {"id": tid, "name": name, "tactic": tactic}}


def attack_narrative(*, domain: str, enrichment: dict | None, evidence, abuse_type: dict) -> dict:
    """The story as ordered steps. Status: observed (stored facts show it), suspected (the name and setup point at it), not_observed
    (we looked and it is not there), not_checked (we cannot look)."""
    e = enrichment or {}
    sig = _by_signal(evidence)
    steps: list[dict] = []
    reg = e.get("registered_at")
    registrar = (e.get("registration") or {}).get("registrar")
    steps.append(_step("acquire_domain", f"Registered the look-alike name {domain}" + (f" on {str(reg)[:10]}" if reg else "") + (f" through {registrar}" if registrar else "") + ".",
                       "observed" if (reg or e.get("registered")) else "suspected", ["new_registration"] if "new_registration" in sig else []))
    live = bool(e.get("has_a") or e.get("has_mx"))
    steps.append(_step("impersonate", "Pointed it at infrastructure so the name works" + (": " + ", ".join(x for x in ("a website" if e.get("has_a") else "", "mail servers" if e.get("has_mx") else "") if x) if live else "") + ".",
                       "observed" if live else "not_observed", [s for s in ("dns_live", "mx_live") if s in sig],
                       "" if live else "It does not resolve and has no mail servers today."))
    cert = e.get("ct_cert_issued_at")
    steps.append(_step("certificate", "Obtained a TLS certificate so a site on it shows the padlock" + (f" (logged {str(cert)[:10]})" if cert else "") + ".",
                       "observed" if cert else "not_observed", [s for s in ("recent_certificate", "cert_after_registration", "ct_certificate") if s in sig]))
    mail_setup = [s for s in ("spf_published", "dkim_published", "dmarc_published", "esp_sender") if s in sig]
    reported = bool(e.get("reported_emails")) or "phishunt" in {f.get("feed") for f in (e.get("feeds") or [])}
    delivered_status = "observed" if reported else "suspected" if (mail_setup or e.get("has_mx")) and abuse_type["type"] in ("phishing", "fraud", "impersonation") else "not_observed"
    steps.append(_step("deliver", "Sent the lure to people (email or a link).", delivered_status, [s for s in ("reported_by_employee", "on_phishing_feed", *mail_setup) if s in sig],
                       "A reported email or a blocklist entry shows this happened." if delivered_status == "observed" else "Mail is set up, but no delivery has been seen." if delivered_status == "suspected" else "No delivery seen."))
    probe = e.get("probe") or {}
    if probe.get("reachable") and probe.get("password_form"):
        steps.append(_step("harvest", "Sent people to a page that collects what they type (logins, card details).", "observed", ["page_password_form"],
                           "Its page asks for a password" + (" and sends it to a different site." if probe.get("offsite_password_form") else ".") + " It may show something different to real visitors."))
    elif probe.get("reachable"):
        steps.append(_step("harvest", "Sent people to a page that collects what they type (logins, card details).", "not_observed", [],
                           "We loaded its page and found no login form. A page can show scanners something different from real visitors, so this does not clear it."))
    else:
        steps.append(_step("harvest", "Sent people to a cloned page that collects what they type (logins, card details).", "not_checked", [],
                           "Its web page has not been analysed, so this step can neither be confirmed nor ruled out."))
    observed = [s for s in steps if s["status"] == "observed"]
    suspected = [s for s in steps if s["status"] == "suspected"]
    unknown = [s for s in steps if s["status"] == "not_checked"]
    summary = (f"Seen: {len(observed)} of {len(steps)} steps. " + (f"Suspected: {len(suspected)}. " if suspected else "") + (f"Cannot check: {len(unknown)}." if unknown else "")).strip()
    return {"steps": steps, "summary": summary, "caveat": "The ATT&CK tags are a curated best-effort mapping; confirm before quoting them as evidence."}


def assess(*, domain: str, evidence, enrichment: dict | None, verdict_key: str, identity: float, stage: str | None) -> dict:
    """Everything 3.4 adds to a candidate, in one call."""
    abuse_type = classify_abuse_type(domain=domain, evidence=evidence, enrichment=enrichment, verdict_key=verdict_key, identity=identity, stage=stage)
    return {"abuse_type": abuse_type, "impact": impact_card(enrichment=enrichment, evidence=evidence, stage=stage),
            "narrative": attack_narrative(domain=domain, enrichment=enrichment, evidence=evidence, abuse_type=abuse_type)}
