"""
Brand Guard — the proof behind a verdict (plan step 3.3). Pure; no database, no network.

A verdict is a conclusion; the analyst should be able to open it and see WHY, step by step, down to the raw facts:

    verdict            <- the rule that fired (brand_verdict.decide; the rule text is the logic, not a description of it)
      resemblance      <- identity signals           <- facts (the label compared with your brand name, ...)
      abuse evidence   <- families (name / how it is set up / campaign / blocklist / your own reports), each damped
                            <- signals (with their measured-or-assumed basis and weight)
                                 <- raw facts (a DNS record, a registry date, a certificate id, a blocklist entry ...) with source and time
      checked, nothing found / not checked
      the decision a person took, if any

Every node is derived from data already stored on the candidate; nothing is invented to make the tree look complete. A signal whose raw
fact is not stored (older candidates) shows its summary and says so, instead of fabricating a fact.
"""
from __future__ import annotations

from app.services.brand_verdict import FAMILY, FAMILY_LABEL, SOURCE_LABEL, VERDICT_RULES, VERDICTS

MAX_FACTS_PER_SIGNAL = 6
_FAMILY_ORDER = ("name", "infrastructure", "campaign", "blocklist", "your_reports", "popularity", "other")


def _fact(text: str, source: str, at: str | None = None, raw: dict | None = None) -> dict:
    return {"kind": "fact", "text": text, "source": source, "at": at, "raw": raw or {}, "children": []}


def _join(values, limit: int = 4) -> str:
    vals = [str(v) for v in (values or []) if v not in (None, "")]
    return ", ".join(vals[:limit]) + (f" and {len(vals) - limit} more" if len(vals) > limit else "")


def facts_for(signal: str, data: dict | None, enrichment: dict | None, at: str | None) -> list[dict]:
    """The raw facts behind one signal, taken from the candidate's stored enrichment and the signal's own data."""
    data, e = data or {}, enrichment or {}
    mail = e.get("mail") or {}
    out: list[dict] = []
    src = SOURCE_LABEL.get(signal, "Analysis")
    if signal in ("new_registration", "established_domain"):
        if e.get("registered_at"):
            out.append(_fact(f"The registry records this name as created on {str(e['registered_at'])[:10]}.", "Registration data (RDAP)", at, {"registered_at": e["registered_at"]}))
    elif signal == "reregistered":
        d = (e.get("registration") or {}).get("reregistered_at") or data.get("reregistered_at")
        if d:
            out.append(_fact(f"The registry shows the name was registered again on {str(d)[:10]}.", "Registration data (RDAP)", at, {"reregistered_at": d}))
    elif signal == "registrar":
        if data.get("registrar"):
            out.append(_fact(f"Registrar: {data['registrar']}.", "Registration data (RDAP)", at, {"registrar": data["registrar"]}))
    elif signal == "high_abuse_suffix":
        out.append(_fact(f"The suffix is .{data.get('suffix', '?')}.", "Registration data", at, {"suffix": data.get("suffix")}))
    elif signal == "dns_live":
        out.append(_fact("A record(s): " + (_join(e.get("a")) or "present"), "DNS", at, {"a": e.get("a") or []}))
    elif signal == "mx_live":
        out.append(_fact("Mail server(s): " + (_join(e.get("mx")) or "present"), "DNS", at, {"mx": e.get("mx") or []}))
    elif signal in ("spf_published", "dkim_published", "dmarc_published", "esp_sender", "copied_dkim_key", "forwarding_mx", "mirrors_mail_provider", "defensive_mail_posture"):
        if signal == "spf_published" and mail.get("spf"):
            out.append(_fact(f"SPF ends in '{(mail['spf'] or {}).get('all', '?')}' and includes {_join((mail['spf'] or {}).get('includes'))}.", "Mail records (DNS TXT)", at, {"spf": mail["spf"]}))
        elif signal == "dkim_published":
            out.append(_fact("DKIM key(s) published at selector(s): " + _join(mail.get("dkim_selectors") or data.get("selectors")), "Mail records (DNS TXT)", at, {"selectors": mail.get("dkim_selectors") or []}))
        elif signal == "dmarc_published" and mail.get("dmarc"):
            out.append(_fact(f"DMARC policy p={(mail['dmarc'] or {}).get('policy', '?')}.", "Mail records (DNS TXT)", at, {"dmarc": mail["dmarc"]}))
        elif signal == "esp_sender":
            out.append(_fact("SPF authorises bulk-mail service(s): " + _join(mail.get("esp") or (data.get("services"))), "Mail records (DNS TXT)", at, {"esp": mail.get("esp") or []}))
        elif signal == "copied_dkim_key":
            out.append(_fact("The DKIM key at selector(s) " + _join(data.get("selectors")) + " is identical to yours.", "Mail records (DNS TXT)", at, {"selectors": data.get("selectors") or []}))
        elif signal == "forwarding_mx":
            out.append(_fact(f"Mail goes to a forwarding service ({data.get('service') or mail.get('forwarding_mx')}).", "DNS", at, {"service": data.get("service")}))
        elif signal == "defensive_mail_posture":
            out.append(_fact(f"DMARC policy {data.get('dmarc')} with no mail servers or a locked-down SPF.", "Mail records (DNS TXT)", at, {"dmarc": data.get("dmarc")}))
    elif signal in ("ct_certificate", "recent_certificate", "cert_after_registration"):
        if e.get("ct_cert_issued_at"):
            out.append(_fact(f"A certificate was logged on {str(e['ct_cert_issued_at'])[:19].replace('T', ' ')}" + (f" by {e['cert_issuer']}" if e.get("cert_issuer") else "") + ".",
                             "Certificate transparency log", e.get("ct_cert_issued_at"), {"cert_ids": (e.get("cert_ids") or [])[:3], "issuer": e.get("cert_issuer")}))
    elif signal in ("free_platform_cname", "platform_hosted", "cloud_platform_hosted"):
        h = e.get("hosting") or {}
        out.append(_fact(f"Hosted on {h.get('platform') or e.get('platform_suffix') or 'a platform'}" + (f" (www points at {h['cname']})" if h.get("cname") else "") + ".", "DNS", at, {"hosting": h}))
    elif signal in ("batch_registered", "shared_certificate", "shared_nameservers_cluster", "shared_server_cluster"):
        sib = data.get("siblings") or []
        value = data.get("value")
        what = {"batch_registered": "registered within 30 minutes of", "shared_certificate": "covered by the same certificate as", "shared_nameservers_cluster": "using the same nameservers as",
                "shared_server_cluster": "served from the same address as"}[signal]
        out.append(_fact(f"{what} {_join(sib)}" + (f" ({_join(value) if isinstance(value, list) else value})" if value else "") + ".", "Campaign analysis", at, {"siblings": sib, "value": value}))
    elif signal == "on_phishing_feed":
        for f in (e.get("feeds") or [])[:MAX_FACTS_PER_SIGNAL]:
            out.append(_fact(f"Listed by {f.get('label') or f.get('feed')}" + (f", first seen {str(f['first_seen'])[:10]}" if f.get("first_seen") else "") + ("" if not f.get("same_site") else " (another host on the same registered domain)") + ".",
                             f.get("label") or "Public blocklist", at, {"feed": f.get("feed"), "same_site": bool(f.get("same_site"))}))
    elif signal in ("reported_by_employee", "reported_brand_mention"):
        for r in (e.get("reported_emails") or [])[:MAX_FACTS_PER_SIGNAL]:
            out.append(_fact(f"Reported email {r.get('email_id')} ({r.get('disposition', 'new')}) received {str(r.get('received_at'))[:10]}.", "Your reported emails", at,
                             {"email_id": r.get("email_id"), "disposition": r.get("disposition")}))
    elif signal == "same_network_as_spoofer":
        out.append(_fact(f"Matches a sender that failed authentication for your domain ({data.get('match')}: {_join(data.get('ips') or [data.get('asn')])}).", "Your DMARC reports", at, data))
    elif signal == "parked":
        out.append(_fact("Nameservers: " + _join(e.get("ns")) + f" ({data.get('service')}).", "DNS", at, {"ns": e.get("ns") or []}))
    elif signal == "popular_site":
        out.append(_fact(f"Ranked about #{data.get('rank'):,} in a list of the most visited sites." if isinstance(data.get("rank"), int) else "Appears in a list of the most visited sites.", "Popularity list (Majestic)", at, data))
    elif signal in ("same_nameservers", "same_hosting_ip"):
        out.append(_fact("Shared with your own infrastructure: " + _join(data.get("values")), "DNS", at, data))
    elif signal == "class_prior":
        out.append(_fact("No measurement exists for this. It is an assumed starting point for visually identical names.", "Assumption", at, data))
    elif data:
        out.append(_fact("; ".join(f"{k}: {v}" for k, v in list(data.items())[:4] if not isinstance(v, (dict, list))) or "see the evidence line", src, at, {}))
    return out[:MAX_FACTS_PER_SIGNAL]


def _signal_node(ev: dict, basis: str, enrichment: dict, counter) -> dict:
    w = float(ev["weight"])
    facts = facts_for(ev["signal"], ev.get("data"), enrichment, ev.get("observed_at"))
    for f in facts:
        f["id"] = counter()
    node = {"id": counter(), "kind": "signal", "signal": ev["signal"], "text": ev["summary"], "weight": w,
            "direction": "for" if w > 0 else "against" if w < 0 else "neutral", "basis": basis, "children": facts,
            "note": "" if facts else "The raw fact behind this line was not stored for this candidate; the summary is what was recorded."}
    return node


def build(*, domain: str, identity: float, abuse: float, evidence: list[dict], enrichment: dict | None, reasoning: dict, verdict_key: str, rule_id: str,
          decision: dict | None = None, not_found: list[dict] | None = None) -> dict:
    """The proof tree. `evidence`: [{"signal","dimension","weight","summary","data","observed_at"}]."""
    n = [0]

    def counter() -> str:
        n[0] += 1
        return f"n{n[0]}"

    enrichment = enrichment or {}
    basis_of = {c["signal"]: c["basis"] for c in (reasoning or {}).get("components", [])}
    ident = [e for e in evidence if e["dimension"] == "identity"]
    abuse_rows = [e for e in evidence if e["dimension"] == "abuse"]

    identity_node = {"id": counter(), "kind": "resemblance", "text": f"Resemblance to your brand: {identity:.0f} out of 100", "children":
                     [_signal_node(e, "name rules", enrichment, counter) for e in sorted(ident, key=lambda x: -abs(x["weight"]))]}

    by_family: dict[str, list[dict]] = {}
    for e in abuse_rows:
        by_family.setdefault(FAMILY.get(e["signal"], "other"), []).append(e)
    fam_nodes = []
    fams = (reasoning or {}).get("families", {})
    for fam in sorted(by_family, key=lambda f: _FAMILY_ORDER.index(f) if f in _FAMILY_ORDER else 99):
        rows = sorted(by_family[fam], key=lambda x: -abs(x["weight"]))
        log10 = (fams.get(fam) or {}).get("log10", 0.0)
        fam_nodes.append({"id": counter(), "kind": "family", "family": fam, "log10": round(log10, 2),
                          "text": f"{FAMILY_LABEL.get(fam, fam).capitalize()}: " + (f"about ×{10 ** log10:.1f} more typical of known-bad new domains" if log10 > 0.05 else f"about ×{10 ** abs(log10):.1f} more typical of ordinary ones" if log10 < -0.05 else "no measurable effect"),
                          "children": [_signal_node(e, basis_of.get(e["signal"], "no weight"), enrichment, counter) for e in rows]})
    ratio = (reasoning or {}).get("ratio", 1.0)
    abuse_node = {"id": counter(), "kind": "abuse", "children": fam_nodes,
                  "text": f"Abuse-side evidence: score {abuse:.0f}; overall about ×{ratio} against ordinary new registrations ({(reasoning or {}).get('label', 'not enough evidence').lower()})"}

    children = [identity_node, abuse_node]
    if not_found:
        children.append({"id": counter(), "kind": "unknown", "text": "Checked and found nothing, or not checked (this is not evidence either way)",
                         "children": [{"id": counter(), "kind": "fact", "text": x["text"], "source": x["source"], "at": None, "raw": {"kind": x["kind"]}, "children": []} for x in not_found]})
    if decision and decision.get("key") != "open":
        label = decision["label"] + (f": {decision['reason_label']}" if decision.get("reason_label") else "")
        children.append({"id": counter(), "kind": "decision", "text": f"A person decided: {label}. This does not change the verdict above; it is recorded separately.", "children": []})

    return {"id": counter(), "kind": "verdict", "verdict": verdict_key, "label": VERDICTS[verdict_key]["label"], "tone": VERDICTS[verdict_key]["tone"],
            "text": f"{domain}: {VERDICTS[verdict_key]['label']}", "rule": {"id": rule_id, "text": VERDICT_RULES[rule_id]}, "children": children}


def walk(node: dict):
    yield node
    for c in node.get("children", []):
        yield from walk(c)


def leaf_facts(node: dict) -> list[dict]:
    return [n for n in walk(node) if n["kind"] == "fact"]
