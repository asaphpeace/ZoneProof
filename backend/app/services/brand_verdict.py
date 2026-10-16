"""
Brand Guard — what the analyst sees for a candidate: a verdict, a confidence, the decision taken, and the evidence laid
out for and against (plan step 3.1 in spirit; the numbers behind it are still the hand-set weights, so nothing here
claims to be a calibrated probability).

Four things that are deliberately kept SEPARATE:

  verdict      what the system thinks, from the evidence                          (likely impersonation / watch / not
                                                                                    enough evidence / probably harmless)
  confidence   how well-corroborated that is: the number of INDEPENDENT kinds of evidence (name, infrastructure, campaign,
               public blocklist, the customer's own reports) that point the same way. It is a count, not a probability.
  decision     what a PERSON did (watching, confirmed, takedown requested, not a threat + why: yours / partner / unrelated).
               A rescan never overwrites it.
  evidence     for / against / checked-and-found-nothing. Absence of evidence is NOT shown as evidence against: "not on a
               blocklist" or "no mail seen" prove little and go in the third group.

Pure functions; no database, no network.
"""
from __future__ import annotations


# ── Which kind of evidence is each signal? ──────────────────────────────────

_NAME = ("class_prior", "homoglyph", "idn_homograph", "bit_flip", "cctld_mimic", "domain_similarity", "keyword_combo", "sound_alike", "subdomain_brand",
         "tld_swap", "word_order", "mixed_script", "credential_lure_word")
_INFRA = ("new_registration", "reregistered", "registrar", "high_abuse_suffix", "established_domain", "dns_live", "mx_live",
          "dormant", "dormant_activated", "fast_progression", "active_homoglyph", "free_platform_cname", "platform_hosted",
          "cloud_platform_hosted", "no_infrastructure", "spf_published", "dkim_published", "dmarc_published", "esp_sender",
          "copied_dkim_key", "forwarding_mx", "mirrors_mail_provider", "defensive_mail_posture", "ct_certificate", "recent_certificate",
          "cert_after_registration", "same_nameservers", "same_hosting_ip", "parked")
_CAMPAIGN = ("batch_registered", "shared_certificate", "shared_nameservers_cluster", "shared_server_cluster", "linked_to_known_bad")
_BLOCKLIST = ("on_phishing_feed",)
_OWN = ("reported_by_employee", "reported_brand_mention", "same_network_as_spoofer")
_POPULAR = ("popular_site",)
_PAGE = ("page_password_form", "page_brand_favicon", "page_certificate_odd", "page_redirects_to_brand", "page_may_differ", "page_form_after_scripts", "page_icon_lookalike", "page_copies_wording", "page_looks_like_brand")

FAMILY: dict[str, str] = {
    **{s: "name" for s in _NAME}, **{s: "infrastructure" for s in _INFRA}, **{s: "campaign" for s in _CAMPAIGN},
    **{s: "blocklist" for s in _BLOCKLIST}, **{s: "your_reports" for s in _OWN}, **{s: "popularity" for s in _POPULAR}, **{s: "page" for s in _PAGE},
}
FAMILY_LABEL = {
    "name": "its name", "infrastructure": "how it is set up", "campaign": "a campaign pattern",
    "blocklist": "a public blocklist", "your_reports": "your own reports", "popularity": "popularity data", "page": "what its web page shows",
}

SOURCE_LABEL: dict[str, str] = {
    **{s: "Name analysis" for s in _NAME},
    "new_registration": "Registration data", "reregistered": "Registration data", "registrar": "Registration data",
    "high_abuse_suffix": "Registration data", "established_domain": "Registration data",
    "dns_live": "DNS", "mx_live": "DNS", "dormant": "DNS", "dormant_activated": "DNS", "fast_progression": "DNS",
    "active_homoglyph": "DNS", "free_platform_cname": "DNS", "platform_hosted": "DNS", "cloud_platform_hosted": "DNS",
    "no_infrastructure": "DNS", "same_nameservers": "DNS", "same_hosting_ip": "DNS", "parked": "DNS",
    "spf_published": "Mail records", "dkim_published": "Mail records", "dmarc_published": "Mail records", "esp_sender": "Mail records",
    "copied_dkim_key": "Mail records", "forwarding_mx": "Mail records", "mirrors_mail_provider": "Mail records",
    "defensive_mail_posture": "Mail records",
    "ct_certificate": "Certificate log", "recent_certificate": "Certificate log", "cert_after_registration": "Certificate log",
    **{s: "Campaign analysis" for s in _CAMPAIGN},
    "linked_to_known_bad": "Evidence graph",
    "on_phishing_feed": "Public blocklist",
    "reported_by_employee": "Your reported emails", "reported_brand_mention": "Your reported emails",
    "same_network_as_spoofer": "Your DMARC reports",
    "popular_site": "Popularity list",
    **{s: "Page probe" for s in _PAGE},
}

# Signals that, when strongly negative, explain a look-alike away (it is a well-known site, or it is the customer's own).
_HARMLESS_EXPLAINERS = ("popular_site", "same_nameservers", "same_hosting_ip")
_HARMLESS_WEIGHT = -15.0

VERDICTS = {
    "likely_impersonation": {"label": "Likely impersonation", "tone": "red"},
    "watch": {"label": "Watch", "tone": "amber"},
    "insufficient": {"label": "Not enough evidence", "tone": "slate"},
    "likely_harmless": {"label": "Probably harmless", "tone": "green"},
    # the abstain state (plan 3.1): strong evidence on BOTH sides, so no verdict is offered
    "uncertain": {"label": "Uncertain: evidence conflicts", "tone": "slate"},
}
# Same cut-offs the scorer already uses to call a candidate suspicious / triaging (brand_scoring_service).
_LIKELY = (55.0, 60.0)
_WATCH = (40.0, 35.0)


def _sig(e) -> str:
    return e["signal"] if isinstance(e, dict) else e.signal


def _w(e) -> float:
    return float(e["weight"] if isinstance(e, dict) else e.weight)


# The rules, by id, in the order they are tried. The text is what the "how we got here" proof shows, so it lives next to the logic.
VERDICT_RULES = {
    "R-harmless": "A strong benign explanation (a well-known site, or your own infrastructure) and little abuse evidence, so it leans harmless.",
    "R-likely": f"It reads like your brand (identity {_LIKELY[0]:g} or more) AND the abuse evidence is strong (score {_LIKELY[1]:g} or more).",
    "R-watch-both": f"It reads like your brand (identity {_WATCH[0]:g} or more) and there is some abuse evidence (score {_WATCH[1]:g} or more).",
    "R-watch-identity": f"It reads very strongly like your brand (identity {_LIKELY[0]:g} or more), which is worth watching even without abuse evidence.",
    "R-insufficient": "Neither the resemblance nor the abuse evidence reaches a threshold, so there is not enough to say.",
    "R-abstain": "Strong evidence points both ways at once, so no verdict is offered rather than letting the larger side win.",
}


def decide(identity: float, abuse: float, evidence, reasoning: dict | None = None) -> tuple[str, str]:
    """(verdict key, rule id). Pure; `verdict` and the derivation proof both use it, so the proof is the logic, not a description of it."""
    explained = any(_sig(e) in _HARMLESS_EXPLAINERS and _w(e) <= _HARMLESS_WEIGHT for e in evidence)
    if explained and abuse < _WATCH[1] + 5:
        key, rule = "likely_harmless", "R-harmless"
    elif identity >= _LIKELY[0] and abuse >= _LIKELY[1]:
        key, rule = "likely_impersonation", "R-likely"
    elif identity >= _WATCH[0] and abuse >= _WATCH[1]:
        key, rule = "watch", "R-watch-both"
    elif identity >= _LIKELY[0]:
        key, rule = "watch", "R-watch-identity"
    else:
        key, rule = "insufficient", "R-insufficient"
    if reasoning and reasoning.get("state") == "conflicting" and key in ("likely_impersonation", "watch", "likely_harmless"):
        key, rule = "uncertain", "R-abstain"
    return key, rule


def verdict(identity: float, abuse: float, evidence, reasoning: dict | None = None) -> dict:
    """{"key", "label", "tone"} from the scores and evidence. When the evidence-ratio combiner (brand_reasoning) reports that strong
    evidence points both ways, the verdict abstains rather than letting the larger side win."""
    key, _ = decide(identity, abuse, evidence, reasoning)
    return {"key": key, **VERDICTS[key]}


def confidence(evidence) -> dict:
    """High / Medium / Low by the number of independent KINDS of evidence for the candidate (not a probability).
    A strong benign explanation caps it at Medium: something real points the other way."""
    families = sorted({FAMILY[_sig(e)] for e in evidence if _w(e) > 0 and _sig(e) in FAMILY and FAMILY[_sig(e)] != "popularity"})
    n = len(families)
    level = "high" if n >= 3 else "medium" if n == 2 else "low"
    capped = any(_sig(e) in _HARMLESS_EXPLAINERS and _w(e) <= _HARMLESS_WEIGHT for e in evidence)
    if capped and level == "high":
        level = "medium"
    names = [FAMILY_LABEL[f] for f in families]
    if not names:
        reason = "No evidence of abuse beyond the name."
    elif n == 1:
        reason = f"Only one kind of evidence so far: {names[0]}."
    else:
        reason = f"{n} independent kinds of evidence agree: {', '.join(names)}."
    return {"level": level, "label": level.capitalize(), "families": families, "reason": reason + (" A strong benign explanation caps this." if capped and n >= 3 else "")}


# ── The decision a person made ──────────────────────────────────────────────

_DECISION = {
    "new": ("open", "Not reviewed", None), "triaging": ("open", "Not reviewed", None), "suspicious": ("open", "Not reviewed", None),
    "monitoring": ("open", "Not reviewed", None),
    "confirmed": ("confirmed", "Confirmed impersonation", None), "takedown": ("takedown", "Takedown requested", None),
    "removed": ("removed", "Taken down", None),
    "customer_owned": ("not_a_threat", "Not a threat", "yours"), "partner": ("not_a_threat", "Not a threat", "partner"),
    "false_positive": ("not_a_threat", "Not a threat", "unrelated"), "benign": ("not_a_threat", "Not a threat", "unrelated"),
    "ignored": ("ignored", "Ignored", None),
}
REASON_LABEL = {"yours": "It is yours", "partner": "A partner", "unrelated": "Unrelated to your brand"}


def decision(status: str, reviewed: bool) -> dict:
    key, label, reason = _DECISION.get(status, ("open", "Not reviewed", None))
    if status == "monitoring" and reviewed:
        key, label = "watching", "Watching"
    return {"key": key, "label": label, "reason": reason, "reason_label": REASON_LABEL.get(reason) if reason else None, "by_person": reviewed}


# ── Evidence laid out for the drawer ────────────────────────────────────────

def _first_sentence(text: str, limit: int = 170) -> str:
    cut = text.split(". ")[0].strip()
    cut = cut if cut.endswith(".") else cut + "."
    return cut if len(cut) <= limit else cut[: limit - 1].rstrip() + "…"


def _source_of(row) -> str:
    sig = _sig(row)
    if sig == "on_phishing_feed":
        feed = (row["data"] if isinstance(row, dict) else row.data or {}).get("feed")
        return {"phishunt": "phishunt.io", "urlhaus": "abuse.ch URLhaus"}.get(feed, "Public blocklist")
    return SOURCE_LABEL.get(sig, "Analysis")


def why_line(evidence, verdict_key: str) -> str:
    """One plain sentence: the strongest reason for the verdict."""
    if verdict_key == "likely_harmless":
        pool = sorted((e for e in evidence if _w(e) < 0), key=_w)
    else:
        pool = sorted((e for e in evidence if _w(e) > 0), key=lambda e: -_w(e))
    if pool:
        row = pool[0]
        return _first_sentence(row["summary"] if isinstance(row, dict) else row.summary)
    return "Registered, nothing else observed yet. It is re-checked on every scan."


def evidence_view(evidence, enrichment: dict | None) -> dict:
    """{"for": [...], "against": [...], "context": [...], "not_found": [...], "narrative": [...]}
    Each evidence item: {n, id, signal, summary, weight, source, observed_at}. n numbers for then against, from 1."""
    enrichment = enrichment or {}
    rows = list(evidence)
    positive = sorted((e for e in rows if _w(e) > 0), key=lambda e: -_w(e))
    negative = sorted((e for e in rows if _w(e) < 0), key=_w)
    neutral = [e for e in rows if _w(e) == 0]

    def item(n: int | None, e) -> dict:
        get = (lambda k: e[k]) if isinstance(e, dict) else (lambda k: getattr(e, k))
        return {"n": n, "id": str(get("id")), "signal": get("signal"), "summary": get("summary"), "weight": _w(e),
                "source": _source_of(e), "observed_at": get("observed_at") if isinstance(e, dict) else (get("observed_at").isoformat() if get("observed_at") else None)}

    for_items = [item(i, e) for i, e in enumerate(positive, start=1)]
    against_items = [item(len(positive) + i, e) for i, e in enumerate(negative, start=1)]
    context = [item(None, e) for e in neutral]

    # Checked, found nothing / not checked — kept apart from "against" because absence proves little.
    present = {_sig(e) for e in rows}
    not_found: list[dict] = []
    if "on_phishing_feed" not in present:
        not_found.append({"kind": "not_found", "text": "Not on the phishunt.io or abuse.ch URLhaus lists at the last scan. Those are recent-activity lists, so this proves little.", "source": "Public blocklists"})
    if "reported_by_employee" not in present:
        not_found.append({"kind": "not_found", "text": "No email reported by your team involves it.", "source": "Your reported emails"})
    checked = enrichment.get("spoofer_ips_checked")
    if "same_network_as_spoofer" not in present and checked is not None:
        text = (f"It is not on the same address or network as the {checked} failing sender(s) in your DMARC reports."
                if checked else "Your DMARC reports show no failing senders to compare it with.")
        not_found.append({"kind": "not_found", "text": text, "source": "Your DMARC reports"})
    probe = enrichment.get("probe")
    if not probe:
        not_found.append({"kind": "not_checked", "text": "Its web page has not been analysed.", "source": "Page probe"})
    elif not probe.get("reachable"):
        not_found.append({"kind": "not_found", "text": "We tried to load its web page and could not reach it, so there is nothing on the page to judge.", "source": "Page probe"})

    narrative = _narrative(for_items, against_items)
    return {"for": for_items, "against": against_items, "context": context, "not_found": not_found, "narrative": narrative}


def _narrative(for_items: list[dict], against_items: list[dict]) -> list[dict]:
    """A short summary assembled from the evidence lines themselves (no model involved): each sentence is one fact and
    carries the number of the evidence line it came from."""
    out: list[dict] = []
    for it in for_items[:4]:
        out.append({"text": _first_sentence(it["summary"]), "refs": [it["n"]]})
    for it in against_items[:2]:
        out.append({"text": "On the other side: " + _first_sentence(it["summary"])[0].lower() + _first_sentence(it["summary"])[1:], "refs": [it["n"]]})
    return out
