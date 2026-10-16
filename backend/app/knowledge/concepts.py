"""
Concept Cards — PAIN_POINT_RESOLUTION_PLAN.md Pain 2. Not a separate course:
a short, dismissible explanation attached to the exact UI element that
caused real confusion in the training calls, rendered with the customer's
own current values substituted in rather than a generic glossary entry.

Distinct from app/knowledge/dmarc.py etc (which the AI advisor cites) —
these are rendered directly in the UI as a card, no LLM involved.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Concept:
    id: str
    term: str
    template: str       # may reference {placeholders} filled from live context
    learn_more: str     # longer, context-free fallback


CONCEPTS: dict[str, Concept] = {
    "dmarc.authentication_overview": Concept(
        id="dmarc.authentication_overview",
        term="Authentication",
        template=(
            "SPF and DKIM are authentication mechanisms — they prove a message came from where it "
            "claims. DMARC alignment then checks whether what authenticated the message matches "
            "what your recipients actually see in the From: field."
        ),
        learn_more=(
            "Authentication answers 'did this come from somewhere authorized.' Alignment then asks "
            "the follow-up question: 'authorized for THIS domain specifically, the one the recipient "
            "sees.' A message can be authenticated and still fail DMARC if it's not aligned."
        ),
    ),
    "dmarc.alignment": Concept(
        id="dmarc.alignment",
        term="Alignment",
        template=(
            "Alignment means the domain that authenticated this message ({auth_domain}) matches the "
            "domain your recipients see ({header_from}). {aligned_summary}"
        ),
        learn_more=(
            "DMARC passes if EITHER SPF or DKIM aligns with the visible From: domain — it doesn't "
            "require both. 'Aligned' means the authenticated domain matches the From: domain (or its "
            "parent, under relaxed alignment, which is the default almost everywhere)."
        ),
    ),
    "dmarc.compliance": Concept(
        id="dmarc.compliance",
        term="Compliance",
        template=(
            "Compliance is the percentage of your mail volume that passes DMARC — currently "
            "{compliance_pct}% for this domain. It's calculated from real aggregate reports, not "
            "estimated."
        ),
        learn_more=(
            "Compliance % = (messages that passed DMARC) / (total messages seen in aggregate "
            "reports) × 100. It's the single number the enforcement gates (recommendation_engine.py) "
            "check before recommending you advance your policy."
        ),
    ),
    "dmarc.return_path": Concept(
        id="dmarc.return_path",
        term="Envelope-From (Return-Path)",
        template=(
            "Envelope-From (also called Return-Path) is where bounce messages go — {envelope_from}. "
            "It's often a different domain than what's visible in the From: header ({header_from}), "
            "especially for marketing/ESP platforms — that's normal, not a sign of spoofing."
        ),
        learn_more=(
            "SPF checks the envelope-from (the technical bounce address) against your domain's SPF "
            "record. DKIM checks whatever domain actually signed the message. DMARC alignment checks "
            "BOTH against the visible header-from — a forwarder changing the envelope is expected "
            "behavior, not evidence of spoofing on its own."
        ),
    ),
    "dmarc.policy_stage": Concept(
        id="dmarc.policy_stage",
        term="DMARC policy stage",
        template=(
            "This domain is at p={stage}. none monitors without acting on mail, quarantine routes "
            "failing mail to spam, reject blocks it before delivery. Advancing should only happen "
            "once compliance is sustained, not just briefly high."
        ),
        learn_more=(
            "Stages only ever move forward in ZoneProof's recommendations — loosening a policy is a "
            "deliberate human decision, never something the system suggests as a 'fix.'"
        ),
    ),
    "tls.mode": Concept(
        id="tls.mode",
        term="MTA-STS mode",
        template=(
            "This domain's MTA-STS policy is in {mode} mode. testing reports TLS failures without "
            "rejecting mail; enforce rejects mail from senders that can't negotiate TLS."
        ),
        learn_more=(
            "The mode lives only in the HTTPS-hosted policy file — the DNS TXT record never carries "
            "it, it only signals the policy exists. Senders cache a fetched policy, so a mode change "
            "doesn't take effect everywhere instantly."
        ),
    ),
}


def render_concept(concept_id: str, context: dict | None = None) -> dict:
    """
    Returns {term, text, learn_more}. Falls back to learn_more (context-free)
    if the template references a context key that wasn't provided — never
    raises, never shows a half-rendered "{placeholder}" to the user.
    """
    concept = CONCEPTS.get(concept_id)
    if not concept:
        return {"term": concept_id, "text": "No explanation available for this concept yet.", "learn_more": ""}

    ctx = dict(context or {})
    if "aligned_summary" not in ctx and "auth_domain" in ctx and "header_from" in ctx:
        ctx["aligned_summary"] = (
            "These match — aligned." if ctx["auth_domain"] == ctx["header_from"]
            else f"These don't match, so this fails alignment."
        )

    try:
        text = concept.template.format(**ctx)
    except (KeyError, IndexError):
        text = concept.learn_more

    return {"term": concept.term, "text": text, "learn_more": concept.learn_more}
