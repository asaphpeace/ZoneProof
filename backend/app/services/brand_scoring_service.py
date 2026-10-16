"""
Brand Guard — deterministic candidate scoring (pure functions, no network).

Two independent scores, never one blended "threat score":

  identity_score  0-100  how likely this domain is actually ABOUT the protected
                         brand (resemblance: skeleton match, edit distance,
                         brand-keyword combos).
  abuse_score     0-100  how likely it is being used to deceive (registration
                         age, live mail/web infrastructure, certificates,
                         credential-lure words).

Every point comes from a named signal that's returned as evidence, so the UI can
answer "why am I seeing this?" without an LLM. Hard rules (customer-owned
domains) short-circuit before any scoring.

Phase 1 has no page-content signals (logo, forms, screenshots); when a renderer
lands it adds signals to this same function rather than changing its shape.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.services import brand_background
from app.services.brand_baseline import shares_infrastructure
from app.services.brand_corroboration import feed_findings, parking_finding, popularity_finding
from app.services.brand_firstparty import reported_findings
from app.services.brand_reasoning import points_for
from app.services.brand_graph import guilt_signal
from app.services.brand_probe_analysis import signals as probe_signals
from app.services.brand_infra_signals import FREE_SITE_HOSTS, cert_timing_finding, hosting_finding, registration_findings
from app.services.brand_mail_intent import intent_findings
from app.services.brand_lifecycle import DORMANT_ACTIVATION_DAYS
from app.services.brand_discovery_service import (
    BITSQUAT_MIN_LEN, LOCAL_LURE_WORDS, cctld_mimic, has_non_ascii, is_bit_flip, is_mixed_script, is_sound_alike, registrable_domain, scripts_in,
    similarity, skeleton, split_registrable, subdomain_brand_abuse, to_unicode, token_match, word_order_match,
)

# Words that, in a hostname, suggest a credential/payment lure (English first, then the Afrikaans/Zulu service
# words South African kits use — see brand_discovery_service.LOCAL_LURE_WORDS).
_LURE_WORDS = ("login", "signin", "secure", "verify", "auth", "account", "pay", "billing", "wallet", "support", "portal", *LOCAL_LURE_WORDS)


SUSPICIOUS_ABUSE_THRESHOLD = 60
CLASS_PRIOR_POINTS = 20.0           # expert-set; see the class_prior signal
SUSPICIOUS_IDENTITY_THRESHOLD = 55
ALERT_ABUSE_THRESHOLD = SUSPICIOUS_ABUSE_THRESHOLD
ALERT_IDENTITY_THRESHOLD = SUSPICIOUS_IDENTITY_THRESHOLD


@dataclass
class Signal:
    signal: str
    dimension: str  # "identity" | "abuse"
    weight: float
    summary: str
    data: dict = field(default_factory=dict)


@dataclass
class Assessment:
    identity_score: float
    abuse_score: float
    impact: str
    urgency: str
    threat_class: str | None
    suggested_status: str
    signals: list[Signal]

    @property
    def should_alert(self) -> bool:
        return (
            self.suggested_status in ("suspicious", "triaging")
            and self.abuse_score >= ALERT_ABUSE_THRESHOLD
            and self.identity_score >= ALERT_IDENTITY_THRESHOLD
        )


def _clamp(value: float) -> float:
    return max(0.0, min(100.0, value))


def assess_candidate(
    candidate_domain: str,
    *,
    primary_domain: str,
    official_domains: list[str],
    brand_tokens: list[str],
    discovery_class: str | None,
    enrichment: dict,
    now: datetime | None = None,
    lifecycle: dict | None = None,
    brand_words: list[str] | None = None,
    baseline: dict | None = None,
) -> Assessment:
    """`enrichment` keys (all optional): has_a, has_mx, registered_at (ISO str
    or datetime), ct_cert_issued_at (ISO str), ct_hit (bool)."""
    now = now or datetime.now(timezone.utc)
    cand_reg = registrable_domain(candidate_domain)
    owned = {registrable_domain(d) for d in [primary_domain, *official_domains]}

    if cand_reg in owned:
        return Assessment(
            0.0, 0.0, "low", "low", None, "customer_owned",
            [Signal("customer_owned", "identity", 0.0, f"{cand_reg} is one of your own registered domains.")],
        )

    cand_label, cand_tld = split_registrable(candidate_domain)
    brand_label = split_registrable(primary_domain)[0]
    cand_skel = skeleton(cand_label)
    signals: list[Signal] = []
    identity = 0.0
    abuse = 0.0
    threat_class = discovery_class

    # ── Identity: how much does it read as the brand? ────────────────────────
    brand_skels = {skeleton(t) for t in brand_tokens if t} | {skeleton(brand_label)}
    unicode_label = to_unicode(cand_label)

    if cand_label != brand_label and cand_skel in brand_skels:
        w = 60.0
        identity += w
        is_idn = has_non_ascii(cand_label)
        threat_class = "homoglyph"
        signals.append(Signal(
            "homoglyph", "identity", w,
            "Reads as your brand: " + (
                f"uses look-alike Unicode characters ({unicode_label})." if is_idn
                else "visually confusable characters make it indistinguishable at a glance."
            ),
            {"candidate": candidate_domain, "unicode": unicode_label, "skeleton": cand_skel},
        ))
        if is_idn:
            identity += 10
            signals.append(Signal("idn_homograph", "identity", 10.0, "Internationalised (non-ASCII) domain name — a classic homograph technique."))
    else:
        best_sim = max(similarity(cand_skel, s) for s in brand_skels)
        mimic = cctld_mimic(cand_label, brand_tokens)
        reordered = word_order_match(cand_label, brand_words or [])
        structural = bool(mimic or reordered)   # an explicit structural explanation replaces the fuzzy-similarity bands
        if cand_label == brand_label and cand_tld != split_registrable(primary_domain)[1]:
            w = 40.0
            identity += w
            threat_class = threat_class or "tld_swap"
            signals.append(Signal("tld_swap", "identity", w, f"Same name as your brand under a different TLD (.{cand_tld}).", {"tld": cand_tld}))
        elif (flip_of := next((t for t in brand_tokens if len(t) >= BITSQUAT_MIN_LEN and is_bit_flip(cand_label, t)), None)):
            w = 45.0
            identity += w
            threat_class = "bitsquat"
            signals.append(Signal("bit_flip", "identity", w, f"Differs from ‘{flip_of}’ by a single flipped bit in one character — a bit-squat that catches devices with memory errors, no mistyping needed.", {"brand": flip_of}))
        elif (sound_of := next((t for t in brand_tokens if is_sound_alike(cand_label, t)), None)):
            w = 45.0
            identity += w
            threat_class = "soundsquat"
            signals.append(Signal("sound_alike", "identity", w, f"Sounds the same as ‘{sound_of}’ read aloud — spelled differently on purpose, not by accident.", {"brand": sound_of}))
        elif not structural and best_sim >= 0.85:
            w = 45.0
            identity += w
            threat_class = threat_class or "typo"
            signals.append(Signal("domain_similarity", "identity", w, f"{round(best_sim * 100)}% similar to your brand name — likely a typo-squat.", {"similarity": round(best_sim, 2)}))
        elif not structural and best_sim >= 0.7:
            w = 25.0
            identity += w
            signals.append(Signal("domain_similarity", "identity", w, f"{round(best_sim * 100)}% similar to your brand name.", {"similarity": round(best_sim, 2)}))

        # Same length-aware rules as certificate-name matching (see token_match): a short or
        # common-word brand must be a whole word or sit next to a lure word, not just appear inside one.
        tiers = {t: token_match(cand_label, t) for t in brand_tokens if cand_label != t}
        matched = next((t for t, tier in tiers.items() if tier in ("substring", "segment", "affix")), None)
        if mimic:
            w = 55.0
            identity += w
            threat_class = "cctld_mimic"
            signals.append(Signal("cctld_mimic", "identity", w, f"Your brand name followed by a South African country tail ({'.co.za' if mimic == 'coza' else '.za'}) inside a different domain — dressed up to look local and official.", {"tail": mimic}))
        elif reordered:
            w = 50.0
            identity += w
            threat_class = "word_order"
            signals.append(Signal("word_order", "identity", w, f"The words of your brand name in a different order ({' '.join(brand_words or [])} → {cand_label}).", {"words": brand_words}))
        elif matched:
            # The full brand name embedded in a longer hostname is a stronger
            # identity claim than a fuzzy near-miss — unless the word is one that turns up in many unrelated names.
            # How common the brand word is in everyday domain names is shown as context but does NOT change the score:
            # discounting it was measured against the evaluation corpus (plan 2.2) and cost 12 real phishing names to
            # remove 12 hits, because the words that are "common" are mostly the most-attacked brands (google, amazon).
            common = tiers[matched] == "substring" and brand_background.is_common(matched)
            w = 55.0
            identity += w
            threat_class = "combosquat" if threat_class in (None, "typo") else threat_class
            data = {"token": matched}
            summary = f"Contains your brand name ‘{matched}’ combined with extra words."
            rate = brand_background.per_100k(matched)
            if rate is not None:
                data["background_per_100k"] = rate
            if common:
                summary += (f" ‘{matched}’ also appears in about {round(rate)} of every 100,000 popular domain names, "
                            "so expect some matches that have nothing to do with you.")
            signals.append(Signal("keyword_combo", "identity", w, summary, data))

        sub = subdomain_brand_abuse(candidate_domain, brand_tokens, [primary_domain, *official_domains])
        if sub:
            official_in = sub["kind"] == "official_domain_in_subdomain"
            w = 55.0 if official_in else 35.0
            identity += w
            threat_class = "subdomain_abuse"
            signals.append(Signal(
                "subdomain_brand", "identity", w,
                (f"Your domain name ({sub['matched']}) is written out inside the subdomain of an unrelated site ({sub['apex']}), so the address "
                 "reads as yours at a glance." if official_in else
                 f"Your brand name appears in the subdomain ‘{sub['subdomain']}’ of an unrelated site ({sub['apex']}). Software vendors also give customers "
                 "subdomains, so this alone is only a lead."),
                sub,
            ))

    if enrichment.get("ct_hit"):
        identity += 10
        signals.append(Signal("ct_certificate", "identity", 10.0, "A TLS certificate was issued for this name — someone is preparing a working HTTPS site.",
                              {"issued_at": _iso(enrichment.get("ct_cert_issued_at"))}))

    # ── Abuse: is it being used to deceive? ──────────────────────────────────
    registered_at = _as_dt(enrichment.get("registered_at"))
    age_days = (now - registered_at).days if registered_at else None
    if age_days is not None:
        if age_days <= 30:
            w = 30.0 if age_days <= 7 else 25.0  # the first week is when phishing infrastructure is stood up
            abuse += w
            signals.append(Signal("new_registration", "abuse", w, f"Registered only {max(age_days, 0)} day(s) ago.", {"age_days": age_days}))
        elif age_days <= 90:
            abuse += 12
            signals.append(Signal("new_registration", "abuse", 12.0, f"Registered {age_days} days ago.", {"age_days": age_days}))
        elif age_days > 1095:
            abuse -= 15
            signals.append(Signal("established_domain", "abuse", -15.0, f"Registered {age_days // 365} years ago — unlikely to be a fresh impersonation.", {"age_days": age_days}))

    has_a, has_mx = bool(enrichment.get("has_a")), bool(enrichment.get("has_mx"))
    # Liveness is about IMPACT (can it hurt someone today), not about how likely it is to be abuse: measured on real data
    # (brand_eval.abuse_lr), new registrations that attackers use resolve and have mail about as often as ordinary ones, so these
    # carry the measured weight (about nothing) and are shown as context.
    if has_mx:
        mx_w = points_for("mx_live", 15.0)
        abuse += mx_w
        signals.append(Signal("mx_live", "abuse", mx_w, "Has live mail (MX) records — it could send email that appears to come from this name. Measured: this alone does not set attackers apart from ordinary new registrations."))
    if has_a:
        a_w = points_for("dns_live", 10.0)
        abuse += a_w
        signals.append(Signal("dns_live", "abuse", a_w, "Resolves to a live web host (A record). Measured: this alone does not set attackers apart from ordinary new registrations; it raises the impact, not the likelihood."))

    cert_issued = _as_dt(enrichment.get("ct_cert_issued_at"))
    if cert_issued and (now - cert_issued).days <= 30:
        abuse += 10
        signals.append(Signal("recent_certificate", "abuse", 10.0, f"Certificate issued {max((now - cert_issued).days, 0)} day(s) ago."))

    # Lifecycle velocity (plan step 2.1). Weights are hand-set heuristics, to be calibrated in Stage 3.
    life = lifecycle or {}
    if life.get("activated") and (life.get("days_dormant_before_activation") or 0) >= DORMANT_ACTIVATION_DAYS:
        abuse += 15
        signals.append(Signal(
            "dormant_activated", "abuse", 15.0,
            f"Sat dormant for {life['days_dormant_before_activation']} days after registration, then started resolving or sending mail — "
            "the activation pattern of a prepared attack.",
            {"days_dormant": life["days_dormant_before_activation"]},
        ))
    if life.get("fast_progression"):
        steps = [g["flag"] for g in life.get("gained_after_discovery", [])]
        abuse += 10
        signals.append(Signal(
            "fast_progression", "abuse", 10.0,
            f"Gained {len(steps)} setup steps ({', '.join(steps)}) within {round(life['progression_hours'] or 0)} hours of each other.",
            {"steps": steps, "hours": life.get("progression_hours")},
        ))
    dormant_now = bool(life.get("dormant"))
    if dormant_now:
        age = life.get("dormant_days")
        signals.append(Signal(
            "dormant", "abuse", 0.0,
            "Registered" + (f" {age} days ago" if age is not None else "") + ", but not resolving or sending mail — watched for activation.",
            {"dormant_days": age},
        ))

    # Benign explainers from the customer's own infrastructure baseline (plan 2.0): a look-alike on the same
    # nameservers or the same server as the real domain is more likely the customer's own registration. Shared
    # platforms (Cloudflare and the like) are discounted inside shares_infrastructure — they prove little.
    for found in shares_infrastructure(enrichment, baseline):
        abuse += found["weight"]
        if found["signal"] == "same_nameservers":
            note = ("a shared DNS platform, so this is weak evidence" if found["shared_platform"]
                    else "consistent with being registered by you")
            summary = f"Uses the same nameservers as your domain ({', '.join(found['values'][:2])}) — {note}."
        else:
            summary = (f"Points at the same server address as your domain ({', '.join(found['values'][:2])}) — "
                       "it is probably yours. If it is, add it to your official domains.")
        signals.append(Signal(found["signal"], "abuse", found["weight"], summary, {"values": found["values"], "shared_platform": found["shared_platform"]}))

    # Email intent (plan 2.3): is this look-alike set up to send mail as this domain?
    base_dns = baseline or {}
    for f in intent_findings(enrichment.get("mail"), base_dns.get("mail_auth"), base_dns.get("mail_provider")):
        abuse += f["weight"]
        signals.append(Signal(f["signal"], "abuse", f["weight"], f["summary"], f["data"]))

    # Registration, certificate, hosting and campaign evidence (plan 2.4)
    infra_findings = list(registration_findings(enrichment.get("registration"), None if enrichment.get("platform_suffix") else cand_tld, now))
    for extra in (
        cert_timing_finding(enrichment.get("registered_at"), enrichment.get("ct_cert_issued_at"), now, enrichment.get("cert_issuer")),
        hosting_finding((enrichment.get("hosting") or {}).get("cname"), (enrichment.get("hosting") or {}).get("platform")),
    ):
        if extra:
            infra_findings.append(extra)
    infra_findings.extend(enrichment.get("clusters") or [])
    for f in infra_findings:
        abuse += f["weight"]
        signals.append(Signal(f["signal"], "abuse", f["weight"], f["summary"], f.get("data", {})))

    # Corroboration and benign explainers from outside the name and DNS (plan 2.5)
    corroboration = [popularity_finding(candidate_domain, cand_reg, on_platform=bool(enrichment.get("platform_suffix"))),
                     parking_finding(enrichment.get("ns")), *feed_findings(enrichment.get("feeds"))]
    for f in corroboration:
        if f:
            abuse += f["weight"]
            signals.append(Signal(f["signal"], "abuse", f["weight"], f["summary"], f.get("data", {})))

    # First-party evidence (plan 2.6): the customer's own reported emails and DMARC reports
    for f in [*reported_findings(enrichment.get("reported_emails")), *(enrichment.get("spoofer_pivot") or [])]:
        dim = f.get("dimension", "abuse")
        if dim == "identity":
            identity += f["weight"]
        else:
            abuse += f["weight"]
        signals.append(Signal(f["signal"], dim, f["weight"], f["summary"], f.get("data", {})))

    # Suspicion that flows from a known-bad look-alike through shared infrastructure (plan 4.2): one more line of evidence, labelled an assumption
    linked = guilt_signal(enrichment.get("guilt"))
    if linked:
        abuse += linked["weight"]
        signals.append(Signal(linked["signal"], "abuse", linked["weight"], linked["summary"], linked["data"]))

    # What the page itself showed when the egress worker probed it (plan 7.2): password forms, a copied icon, an odd certificate. Weights are assumptions.
    for p in probe_signals(enrichment.get("probe")):
        if p["weight"]:
            abuse += p["weight"]
        signals.append(Signal(p["signal"], p["dimension"], p["weight"], p["summary"], p["data"]))

    platform = enrichment.get("platform_suffix")
    if platform in FREE_SITE_HOSTS:
        abuse += 10
        signals.append(Signal(
            "platform_hosted", "abuse", 10.0,
            f"Lives on a free hosting platform ({platform}), not a domain anyone registered — it costs nothing to create, registration age doesn't apply, and any takedown goes to the platform.",
            {"platform_suffix": platform},
        ))
    elif platform:
        # The Public Suffix List also lists CDNs and cloud platforms (Akamai, Azure, CloudFront...). Large companies host
        # there too, so it is context for the analyst, not evidence of abuse (found by a live scan, plan 2.4).
        signals.append(Signal(
            "cloud_platform_hosted", "abuse", 0.0,
            f"Lives on a cloud or CDN platform ({platform}), not a domain anyone registered — any takedown goes to the platform. Not scored: ordinary companies host there too.",
            {"platform_suffix": platform},
        ))

    if is_mixed_script(cand_label):
        names = sorted(s.title() for s in scripts_in(cand_label))
        abuse += 15
        signals.append(Signal(
            "mixed_script", "abuse", 15.0,
            f"Mixes alphabets in one name ({' + '.join(names)}). Legitimate brands almost never do, and browsers show such names in raw "
            "punycode because this is how look-alikes are built.",
            {"scripts": names},
        ))

    lure = next((w for w in _LURE_WORDS if w in cand_label), None)
    if lure:
        lure_w = points_for("credential_lure_word", 10.0)
        abuse += lure_w
        signals.append(Signal("credential_lure_word", "abuse", lure_w, f"Hostname contains ‘{lure}’ — a common credential/payment-lure word.", {"word": lure}))

    if threat_class == "homoglyph" and (has_a or has_mx):
        abuse += 15
        signals.append(Signal("active_homoglyph", "abuse", 15.0, "A look-alike that is also live is rarely defensive or accidental."))

    # CLASS PRIOR (an explicit, labelled assumption: nobody has measured it). A name that is visually identical to the brand's is almost
    # never registered by accident, so it starts from a higher footing than an ordinary similar name. This is the principled replacement
    # for the liveness points that measurement removed (brand_eval.abuse_lr): it restores alerting for the strongest look-alikes without
    # pretending liveness is evidence.
    if threat_class == "homoglyph" or any(s.signal == "idn_homograph" for s in signals):
        abuse += CLASS_PRIOR_POINTS
        signals.append(Signal("class_prior", "abuse", CLASS_PRIOR_POINTS,
                              "ASSUMPTION, not a measurement: a name visually identical to yours is rarely registered by accident, so it starts from a higher footing.",
                              {"basis": "expert", "threat_class": "homoglyph"}))

    if not (has_a or has_mx) and age_days is None and not dormant_now:
        signals.append(Signal("no_infrastructure", "abuse", 0.0, "Not currently resolving and no registration data found — monitored for activation."))

    identity, abuse = _clamp(identity), _clamp(abuse)
    live = has_a or has_mx

    impact = "high" if (live and identity >= 60 and lure) else "medium" if live else "low"
    urgency = "high" if (live and abuse >= ALERT_ABUSE_THRESHOLD) else "medium" if abuse >= 40 else "low"

    if identity >= SUSPICIOUS_IDENTITY_THRESHOLD and abuse >= SUSPICIOUS_ABUSE_THRESHOLD:
        suggested = "suspicious"
    elif identity >= 40 and abuse >= 35:
        suggested = "triaging"
    else:
        suggested = "monitoring"

    return Assessment(identity, abuse, impact, urgency, threat_class, suggested, signals)


def _as_dt(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _iso(value) -> str | None:
    dt = _as_dt(value)
    return dt.isoformat() if dt else None
