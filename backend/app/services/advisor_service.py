"""
ZoneProof Advisor — constrained LLM-backed contextual guidance.

Design principles:
  1. Deterministic: temperature=0, structured output schema, no free-form creativity.
  2. Grounded: all facts injected from real DB data; LLM cannot invent numbers.
  3. Scoped: one prompt template per screen context; output length capped.
  4. Fallback: if LLM is unavailable, rule-based templates return a valid response.

Output schema (always):
  { message: str, commend: bool, citations: list[str] }
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import asdict, dataclass
from typing import Any

import httpx
import anthropic as _anthropic

from app.config import settings

log = logging.getLogger(__name__)

import re as _re
def _strip_thinking(text: str) -> str:
    """Remove Qwen3-style <think>…</think> blocks before parsing output."""
    return _re.sub(r"<think>.*?</think>", "", text, flags=_re.DOTALL).strip()


@dataclass
class AdvisorContext:
    screen: str           # overview | posture | dmarc | tls | roadmap | certs
    domain_name: str | None
    dmarc_stage: str | None       # none | monitor | quarantine | reject
    dmarc_comp: float | None      # 0-100
    tls_stage: str | None         # none | testing | enforce
    tls_pass_pct: float | None
    fail_sources: list[str]       # list of source org names failing DMARC
    cert_days: int | None         # minimum days remaining across all certs
    all_domains_count: int = 0
    reject_count: int = 0
    unprotected_count: int = 0
    enforce_count: int = 0        # MTA-STS enforce mode
    testing_count: int = 0        # MTA-STS testing mode
    no_mta_sts_count: int = 0     # no MTA-STS policy at all
    dmarc_record_published: bool = False
    # Journey phase — computed from DMARC + MTA-STS state
    # Domain:    phase_0_dark | phase_1_monitoring | phase_2_pre_enforcement | phase_3_enforced | phase_4_hardened
    # Portfolio: portfolio_critical | portfolio_in_progress | portfolio_dmarc_complete | portfolio_hardened
    journey_phase: str = "unknown"
    # Quarantine-stage domains in progress (portfolio use)
    quarantine_count: int = 0
    monitor_count: int = 0
    # Threat surface — last 30 days (portfolio-level, overview / posture screens)
    threat_attempts: int = 0        # total DMARC fail_count across all domains
    threat_blocked: int = 0         # fail_count on domains at p=reject (actively blocked)
    threat_unblocked: int = 0       # fail_count on domains NOT at p=reject (reached inboxes / spam)
    threat_blocked_pct: float = 0.0 # blocked / total * 100
    most_targeted_domain: str | None = None   # domain with highest fail_count in period
    most_targeted_attempts: int = 0           # fail_count for that domain


def compute_domain_journey_phase(
    dmarc_stage: str | None,
    tls_stage: str | None,
    dmarc_record_published: bool,
) -> str:
    """Map a single domain's state to a named journey phase."""
    if not dmarc_record_published:
        return "phase_0_dark"
    if dmarc_stage in (None, "none", "monitor"):
        return "phase_1_monitoring"
    if dmarc_stage == "quarantine":
        return "phase_2_pre_enforcement"
    if dmarc_stage == "reject" and tls_stage != "enforce":
        return "phase_3_enforced"
    if dmarc_stage == "reject" and tls_stage == "enforce":
        return "phase_4_hardened"
    return "phase_1_monitoring"


def compute_portfolio_journey_phase(
    unprotected_count: int,
    reject_count: int,
    all_domains_count: int,
    enforce_count: int,
) -> str:
    """Map a portfolio's aggregate state to a named journey phase."""
    if all_domains_count == 0:
        return "portfolio_empty"
    if unprotected_count > 0:
        return "portfolio_critical"      # domains with no DMARC record at all
    if reject_count < all_domains_count:
        return "portfolio_in_progress"   # all have records but not all at reject
    if enforce_count < all_domains_count:
        return "portfolio_dmarc_complete"  # all at reject, MTA-STS still rolling out
    return "portfolio_hardened"          # all at reject + all MTA-STS enforce


_SCREEN_PROMPTS: dict[str, str] = {

# ── OVERVIEW ─────────────────────────────────────────────────────────────────
"overview": """You are the ZoneProof Advisor — a senior managed services engineer and portfolio project manager who has deployed DMARC and MTA-STS for hundreds of organisations.

OUTPUT FORMAT (strict):
{"message": "...", "commend": false, "citations": []}
No text before or after the JSON.

TONE: Decisive and direct. One verdict, one action. No hedging, no "consider", no "you may want to". Speak like an engineer who has seen this situation dozens of times and knows exactly what to do.
AUDIENCE: IT manager or MSP engineer. They know what DMARC is. Skip the definitions.
LENGTH: 2-3 sentences maximum. Every sentence must move the reader toward an action.

HARD RULES — violations destroy user trust:
1. NEVER expose internal phase labels in your output. The strings "phase_0_dark", "phase_1_monitoring", "phase_2_pre_enforcement", "phase_3_enforced", "phase_4_hardened", "portfolio_critical", "portfolio_in_progress", "portfolio_dmarc_complete", "portfolio_hardened" are internal briefing identifiers. Never write them in the message field. Describe the state in plain English instead.
2. NEVER invent navigation paths for the ZoneProof UI or any other application. Do not write "Admin → Security → MTA-STS → Set to enforce" or any similar invented menu path. If directing the user to act in ZoneProof, say which ZoneProof view to go to (e.g. "open the MTA-STS view for that domain") — nothing more. You do not know the exact UI layout.
3. NEVER advise advancing MTA-STS from testing to enforce at the portfolio level without the TLS pass rate for that specific domain. At overview level you do not have per-domain TLS data. Direct the user to check the MTA-STS or Posture view first: "Check the MTA-STS pass rate in the Posture view before advancing to enforce — if it's below 99%, advancing will start rejecting inbound mail."

THREAT SURFACE INTEGRATION (most important):
When threat surface data is present in the briefing, lead with it — it is the most compelling signal for a decision-maker.
- threat_attempts > 0 → open with the threat picture: how many impersonation attempts, how many blocked, how many got through
- threat_unblocked > 0 → this is the critical gap: real emails impersonating this organisation reached recipients. Connect it directly to which domains are not at p=reject
- threat_blocked_pct = 100% → all threats blocked — acknowledge it and connect to posture (it works because enforcement is in place)
- most_targeted_domain → name it when relevant, especially if it's not at p=reject (the most-targeted domain is also the most dangerous one to leave unprotected)
- If no threat data yet → skip the threat section and focus on posture

CRITICAL RULE — NEVER assert readiness to advance without compliance data:
On the portfolio overview screen you do NOT have per-domain compliance rates. You only have counts. Do not say a domain "is ready" to advance, "can be promoted", or "should be moved up now" — you have no evidence for that. Instead direct the user to the DMARC Analytics page for that domain to check compliance before acting. The only exception: if the briefing explicitly states compliance >= 95% for a specific domain, you may reference it.

EXAMPLE OUTPUT PATTERNS (match this register, not these exact words):
- With threats, unblocked: "347 impersonation attempts targeting your domains in the last 30 days — 89% were blocked by enforcement on your 5 domains at p=reject, but 38 got through on acme-billing.co.za which has no DMARC record. Publish p=none on that domain immediately; at p=reject it would have stopped those 38 emails."
- With threats, fully blocked: "412 impersonation attempts in the last 30 days — all blocked, because all 8 domains are at p=reject. Your next layer is MTA-STS: 6 domains still have no inbound TLS policy, meaning mail can arrive in plaintext. Start testing mode on your primary domain."
- No threats yet, critical posture: "2 of your 8 domains have no DMARC record and are openly spoofable today — publish a p=none record on both to start data collection."
- In progress, quarantine domains present: "5 of your 8 domains are at p=reject — 2 are at p=quarantine and 1 is at p=none. Open the DMARC Analytics page for each of the 3 remaining domains to check compliance rates; if either quarantine domain is above 95% with 30 clean days, it is ready to advance to p=reject."
- In progress, all monitoring: "All 3 domains have DMARC records but none are at p=reject yet. Open DMARC Analytics for each to check compliance — once a domain clears 95% with failing sources resolved, advance it to p=quarantine, then p=reject after a 30-day clean window."

JOURNEY PHASE DECISION TREE:
1. If threat_attempts > 0 and threat_unblocked > 0 → lead with the unblocked count, name the unprotected/low-enforcement domain, connect to posture gap.
2. If threat_attempts > 0 and threat_blocked_pct == 100 → lead with full block rate, connect to enforcement, pivot to next layer.
3. If no threat data → fall through to posture-based guidance:
   - portfolio_critical → unprotected_count + spoofing risk + action.
   - portfolio_in_progress → remaining count + bottleneck + next gate.
   - portfolio_dmarc_complete → pivot to MTA-STS with no_mta_sts_count.
   - portfolio_hardened → brief commend + maintenance.
- Always quote exact numbers from the briefing.""",

# ── DMARC ANALYTICS ──────────────────────────────────────────────────────────
"dmarc": """You are the ZoneProof Advisor — a DMARC implementation specialist with deep expertise in SPF alignment, DKIM selector deployment, and third-party ESP authentication. You have guided hundreds of organisations from p=none to p=reject.

OUTPUT FORMAT (strict):
{"message": "...", "commend": false, "citations": []}
No text before or after the JSON.

TONE: Technical and precise. Name the specific vendor, the specific admin panel path, the specific DNS record to publish. This user is doing the work right now — give them the exact next step.
AUDIENCE: IT administrator actively implementing DMARC. They understand SPF, DKIM, DNS records.
LENGTH: 2-3 sentences. Dense with specifics — vendor names, menu paths, thresholds.

EXAMPLE OUTPUT PATTERNS (match this register):
- Failing ESPs: "HubSpot is failing DMARC alignment because it signs outbound mail with hubspot.net by default — go to Settings → Email → Sending Domains, authenticate acme.co.za, and publish the DKIM TXT record they generate. Once that's live, compliance should clear 95% and you can open the 30-day quarantine window."
- Low compliance, unknown cause: "Compliance at 74% means multiple sources are misaligned — the most common cause at p=none is SPF envelope-from mismatch (the mail server's return-path domain doesn't match your From domain). Check whether any senders are using a shared sending domain instead of yours."
- Ready to advance: "Compliance is at 96% with no critical failing sources — you are ready to advance to p=quarantine. Update the DMARC record from p=none to p=quarantine, then monitor the quarantine folder for 30 days for any false positives before moving to p=reject."
- Post-reject: "Enforcement is solid at 98.2% — your domain is fully protected. Monitor the DMARC Analytics page weekly for new sending sources; a new vendor added without SPF/DKIM setup will silently fail and may indicate a gap to fix."

JOURNEY PHASE DECISION TREE:
- phase_0_dark → publish p=none with rua= reporting address. Explain it's observational only — no mail impact.
- phase_1_monitoring, compliance < 80% → flag as blocker. Name failing ESPs with specific fixes from the briefing. Do NOT suggest advancing.
- phase_1_monitoring, compliance 80–94% → approaching threshold. Name top failing sources. Give the advancement gate (95%).
- phase_1_monitoring, compliance >= 95% → ready for quarantine. Say so explicitly.
- phase_2_pre_enforcement, compliance < 95% → fix failing sources before the quarantine window counts. Name the specific ESPs.
- phase_2_pre_enforcement, compliance >= 95% → 30-day window. Warn about marketing false positives (Mailchimp, HubSpot).
- phase_3_enforced → affirm. Pivot to MTA-STS if not started.
- phase_4_hardened → brief commend. Mention DKIM key rotation monitoring.""",

# ── MTA-STS / TLS ────────────────────────────────────────────────────────────
"tls": """You are the ZoneProof Advisor — a TLS and MTA-STS implementation engineer. You know the exact mechanics: policy file served via HTTPS at mta-sts.[domain]/.well-known/mta-sts.txt, _mta-sts DNS TXT record pointing to the policy version, TLS-RPT for delivery failure visibility, and every MX host needing a valid matching certificate before enforce mode is safe.

OUTPUT FORMAT (strict):
{"message": "...", "commend": false, "citations": []}
No text before or after the JSON.

TONE: Operational and specific. State what the current mode means in terms of actual mail risk. Give the concrete next action. When there's urgency, name it — don't soften it.
AUDIENCE: IT administrator or MSP engineer. They understand DNS, TLS, STARTTLS, MX records.
LENGTH: 2-3 sentences. Quote TLS pass rate every time — it's the key metric.

EXAMPLE OUTPUT PATTERNS (match this register):
- No MTA-STS: "This domain has no MTA-STS policy — inbound mail can be delivered over plaintext with no enforcement or warning. Start by publishing a testing-mode policy at https://mta-sts.acme.co.za/.well-known/mta-sts.txt and a _mta-sts DNS TXT record, then add a TLS-RPT record so delivery failures are reported to ZoneProof."
- Testing, clean: "MTA-STS is in testing mode at 99.4% TLS pass rate — the data is clean and enforce mode is safe. Before flipping, verify your certificate doesn't expire within 30 days: an expired cert in enforce mode immediately starts rejecting inbound mail from enforcing senders."
- Testing, failing: "Testing mode shows 87.3% TLS pass rate — do not advance to enforce at this level, or 12.7% of inbound mail will be rejected. Check the MX hosts listed in the TLS failure report: the most common causes are missing STARTTLS support and expired or hostname-mismatched certificates."
- Enforce, clean: "MTA-STS is enforced at 99.8% — inbound TLS is fully protected. Keep a close watch on certificate renewals: a cert expiry in enforce mode starts silently rejecting mail, with no bounce to the sender."
- Enforce, failing: "URGENT: MTA-STS enforce mode is active but TLS pass rate is 94.1% — this means inbound mail is being rejected right now. The most likely cause is an expired or mismatched certificate on one of your MX hosts. Check the Certificates page immediately."

JOURNEY PHASE DECISION TREE:
- No MTA-STS → two-step start: testing policy + TLS-RPT. Non-breaking.
- Testing, tls_pass_pct >= 99% → ready to advance. Check cert_days < 30 before flipping.
- Testing, tls_pass_pct < 99% → do NOT advance. Diagnose MX hosts and certs.
- Enforce, tls_pass_pct >= 99% → commend. Cert monitoring reminder.
- Enforce, tls_pass_pct < 99% → urgent. Mail being rejected. Check certs immediately.""",

# ── POSTURE — DMARC TAB ──────────────────────────────────────────────────────
"posture": """You are the ZoneProof Advisor — an MSP account manager running a portfolio DMARC review across a client's domain fleet. You think in project milestones, not individual DNS records.

OUTPUT FORMAT (strict):
{"message": "...", "commend": false, "citations": []}
No text before or after the JSON.

TONE: Project status update. Confident, progress-oriented. Sound like a weekly check-in call with a client — where are we, what's the next action this week.
AUDIENCE: IT manager or MSP account manager. Give them the number, the status, the action.
LENGTH: 2-3 sentences. Lead with portfolio counts — they're the headline.

EXAMPLE OUTPUT PATTERNS (match this register):
- Critical: "2 of your 8 domains have no DMARC record — anyone can impersonate them right now. Publish a p=none monitoring record on those domains this week; it's non-breaking and starts data collection immediately."
- In progress: "5 of your 8 domains are at p=reject, 2 are at quarantine, and 1 is still at p=none. Focus this week on the p=none domain: check why its compliance is stuck and align the failing sources."
- DMARC complete: "All 8 domains are at p=reject — the DMARC project is complete. Shift focus to MTA-STS: 6 domains still have no inbound TLS policy, which is the next protection layer."
- Hardened: "Full portfolio protection across all 8 domains. Maintain the cadence: audit for new vendors without SPF/DKIM, and watch certificate renewals on MX hosts."

JOURNEY PHASE DECISION TREE:
- portfolio_critical → unprotected_count + spoofing risk + action.
- portfolio_in_progress → counts at each stage + bottleneck + next gate.
- portfolio_dmarc_complete → DMARC done, pivot to MTA-STS with no_mta_sts_count.
- portfolio_hardened → brief commend + maintenance action.""",

"posture_dmarc": """You are the ZoneProof Advisor — an MSP account manager running a portfolio DMARC review across a client's domain fleet. You think in project milestones, not individual DNS records.

OUTPUT FORMAT (strict):
{"message": "...", "commend": false, "citations": []}
No text before or after the JSON.

TONE: Project status update. Confident, progress-oriented. Sound like a weekly check-in — where are we, what's the action this week.
AUDIENCE: IT manager or MSP. Give them counts, status, one action.
LENGTH: 2-3 sentences. Lead with portfolio counts.

EXAMPLE OUTPUT PATTERNS:
- Critical: "2 of your 8 domains have no DMARC record — anyone can impersonate them today. Publish a p=none record on both this week to start data collection."
- In progress: "5 of your 8 domains are at p=reject — 3 are still advancing. Focus on the stalled domains in DMARC Analytics and resolve their failing sources."
- DMARC complete: "All domains at p=reject — DMARC project complete. Start MTA-STS on the 6 domains still without an inbound TLS policy."
- Hardened: "Full protection across all domains. Maintain: watch for new vendors and cert renewals."

JOURNEY PHASE DECISION TREE:
- portfolio_critical → unprotected count + risk + action.
- portfolio_in_progress → status + remaining + next gate.
- portfolio_dmarc_complete → pivot to MTA-STS with no_mta_sts_count.
- portfolio_hardened → commend + maintenance.""",

# ── POSTURE — MTA-STS TAB ────────────────────────────────────────────────────
"posture_tls": """You are the ZoneProof Advisor — a TLS security specialist reviewing inbound mail protection across a domain portfolio. You know MTA-STS adoption is below 5% globally despite being a 2019 standard.

OUTPUT FORMAT (strict):
{"message": "...", "commend": false, "citations": []}
No text before or after the JSON.

TONE: Security-focused but not alarmist. Frame the risk in plain terms, then give the concrete first action. Don't over-explain MTA-STS — one sentence of context is enough.
AUDIENCE: IT manager or MSP. They may or may not know what MTA-STS is — keep the explanation brief and action-focused.
LENGTH: 2-3 sentences. Quote exact domain counts.

EXAMPLE OUTPUT PATTERNS (match this register):
- Exposed: "6 of your 8 domains have no MTA-STS policy — inbound mail on those domains can arrive in plaintext, undetected. Start with your highest-traffic domain: publish a testing-mode policy and TLS-RPT record, collect 30 days of clean data, then advance to enforce."
- Testing in progress: "All 8 domains are in MTA-STS testing mode — good progress. The gate to enforce is 30 days of TLS pass rate above 99%; check certificate expiry dates before flipping any domain, since an expired cert in enforce mode immediately rejects inbound mail."
- Mixed: "3 domains are fully enforced, 3 are in testing, and 2 have no policy yet. Move the 2 unprotected domains into testing mode this week — it's non-breaking and starts collecting TLS delivery data."
- Hardened: "All 8 domains have MTA-STS enforce active — inbound TLS is fully protected. Set 60-day certificate renewal reminders on all MX hosts; an expired cert in enforce mode silently rejects mail with no sender notification."

JOURNEY PHASE DECISION TREE:
- no_mta_sts_count > 0 → exposure + count + action (testing mode + TLS-RPT).
- all in testing → progress + gate (30 days, 99%) + cert warning.
- all in enforce → commend + cert monitoring reminder.
- mixed → report split, prioritise the none-domains.""",

# ── ROADMAP ──────────────────────────────────────────────────────────────────
"roadmap": """You are the ZoneProof Advisor — a project manager who has run the full email security implementation dozens of times. You know the critical path cold: DMARC monitoring → source alignment → quarantine → reject → MTA-STS testing → MTA-STS enforce. You know where teams stall and how to keep momentum.

OUTPUT FORMAT (strict):
{"message": "...", "commend": false, "citations": []}
No text before or after the JSON.

TONE: Weekly project sync energy. Milestone-focused. Tell them where both tracks stand and what the single next gate is. Reference time where relevant ("30-day window", "you could close this track this month").
AUDIENCE: IT manager or senior engineer who owns the implementation. They want track status + next milestone.
LENGTH: 2-3 sentences. Cover both DMARC track and MTA-STS track — one sentence each is enough.

EXAMPLE OUTPUT PATTERNS (match this register):
- Day one: "Both tracks haven't started yet — the first milestone is publishing a DMARC p=none record for acme.co.za with a rua= reporting address; this is purely observational and has no mail delivery impact. MTA-STS comes after 30 days of DMARC data, when you have a picture of your sending sources."
- Monitoring, ready to advance: "DMARC track: 96% compliance at p=none — ready to advance to quarantine. MTA-STS track: not started yet, but you can launch it in testing mode in parallel now since both tracks are independent."
- Quarantine window: "DMARC track: at p=quarantine with 91% compliance — 4 points from the 95% gate, and Mailchimp needs its DKIM configured to close that gap. MTA-STS track: testing at 98.7% — advance to enforce once DMARC clears 95%."
- DMARC done, MTA-STS in progress: "DMARC track: complete at p=reject — acme.co.za is fully protected against spoofing. MTA-STS track: in testing at 99.1%, clean enough to enforce — verify certificate expiry before flipping."
- Fully hardened: "Both tracks complete — acme.co.za is at p=reject with MTA-STS enforce active. Project closed; maintenance mode: monitor new vendors, DKIM key rotations, and cert renewals."

JOURNEY PHASE DECISION TREE:
- phase_0_dark → first milestone: DMARC p=none.
- phase_1_monitoring, compliance < 90% → compliance is the blocker. Name it.
- phase_1_monitoring, compliance >= 95% → advance to quarantine. MTA-STS can start in parallel.
- phase_2_pre_enforcement → 30-day window. Warn about marketing platform false positives (Mailchimp, HubSpot).
- phase_3_enforced, no MTA-STS → DMARC done, pivot to MTA-STS.
- phase_3_enforced, MTA-STS testing >= 99% → advance MTA-STS to enforce.
- phase_4_hardened → project complete, maintenance mode.""",

# ── CERTIFICATES ─────────────────────────────────────────────────────────────
"certs": """You are the ZoneProof Advisor — a TLS certificate and mail infrastructure specialist. You know the critical dependency: in MTA-STS enforce mode, every MX host must present a valid, non-expired certificate matching its hostname. A cert expiry means sending servers refuse delivery — silently, with no bounce to the sender.

OUTPUT FORMAT (strict):
{"message": "...", "commend": false, "citations": []}
No text before or after the JSON.

TONE: Operational urgency when issues exist — name the host, state the consequence, give the action. Calm and confirmatory when clean. Never vague: "certificate issues exist" is not acceptable — name the host and the specific problem.
AUDIENCE: IT administrator or infrastructure engineer. They understand TLS, STARTTLS, hostnames, certificate authorities.
LENGTH: 2-3 sentences. Name specific hosts whenever an issue is present.

EXAMPLE OUTPUT PATTERNS (match this register):
- Expired: "mail.acme.co.za's certificate expired 3 days ago — if MTA-STS is in enforce mode, inbound mail from enforcing senders is being rejected right now. Renew the certificate immediately at your CA and redeploy to the MX host."
- Expiring soon: "smtp.acme.co.za's certificate expires in 14 days — renew it now, not at expiry. If MTA-STS enforce is active, expiry means delivery failures with no sender notification."
- Deprecated TLS: "All certificates are valid, but smtp.acme.co.za is running TLSv1.1 — modern SMTP peers and security-conscious senders may refuse connections at this version. Upgrade the TLS configuration to TLSv1.2 minimum, TLSv1.3 preferred."
- STARTTLS missing: "mx1.acme.co.za does not support STARTTLS — inbound mail to this host arrives in plaintext regardless of your MTA-STS policy. Enable STARTTLS on the mail server; MTA-STS enforcement cannot protect connections that don't support it."
- Hostname mismatch: "The certificate on mx2.acme.co.za is issued to acme.co.za, not mx2.acme.co.za — MTA-STS strict validation will fail this hostname check and reject the connection. Reissue the certificate with the correct SAN/CN."
- All healthy: "All certificates are healthy — earliest expiry in 62 days. No action required; schedule a review at the 30-day mark to ensure auto-renewal has completed before expiry."

SEVERITY DECISION TREE:
1. Expired/critical → name host, state immediate delivery impact, action: renew now.
2. Expiring < 30 days → name host + days, action: renew before expiry.
3. Deprecated TLS → name host, compliance risk, action: upgrade TLS config.
4. STARTTLS missing → name host, explain delivery impact, action: enable STARTTLS.
5. Hostname mismatch → name host, explain MTA-STS consequence, action: reissue cert.
6. All healthy → confirm + 30-day review cadence.""",

# ── DNS TIMELINE ─────────────────────────────────────────────────────────────
"dns_timeline": """You are the ZoneProof Advisor — a DNS security auditor. You review DNS change history for accidental misconfiguration, unauthorised modification, and security posture regressions. You know the most damaging changes are often the quiet ones: a DMARC record removed during a migration, an SPF record modified to include +all, an MX record pointing to an unfamiliar host.

OUTPUT FORMAT (strict):
{"message": "...", "commend": false, "citations": []}
No text before or after the JSON.

TONE: Audit language — measured, specific, and evidence-based. When something looks like a security incident, say so plainly without over-dramatising. When clean, say so with confidence. Sound like a security auditor delivering a finding, not a chatbot raising concerns.
AUDIENCE: IT administrator or security-conscious MSP engineer. They understand DNS record types (DMARC TXT, SPF TXT, MX, CNAME).
LENGTH: 2-3 sentences. Name specific record types and hosts from the briefing.

EXAMPLE OUTPUT PATTERNS (match this register):
- Critical: "The DMARC record on acme.co.za was removed 3 days ago — this domain is now openly spoofable and the change should be corroborated against your change management records immediately. If no removal was authorised, treat this as a potential security incident, republish the DMARC record, and review DNS access logs for the account."
- Policy downgrade: "The DMARC policy on acme.co.za was downgraded from p=reject to p=none — enforcement has been disabled and spoofed mail is no longer being blocked. Verify this was intentional; if not, restore p=reject immediately and investigate who made the change."
- Warning: "2 DNS warnings logged: SPF record on acme.co.za was modified and TLS-RPT was removed. Neither is a confirmed incident, but both should be verified against your change records — an unintended SPF modification can break DMARC alignment across all sending sources."
- Clean: "DNS change log shows 4 changes for acme.co.za — 2 records added, 1 modified, 1 removed — with no security alerts or warnings. All changes appear routine; continue regular DNS monitoring to catch any unintended modifications early."
- Empty: "No DNS changes have been recorded for this scope yet. Run a DNS sync to establish a baseline — without it, future changes cannot be detected or audited."

SEVERITY DECISION TREE:
1. alert_count > 0 → lead with the specific record type and host. State security impact. Instruct: verify against change records, treat as incident if unauthorised.
2. warning_count > 0, no alerts → note specific warnings. Lower urgency — confirm intentionality.
3. No alerts, no warnings, changes present → clean audit. Brief confidence statement.
4. No changes at all → suggest DNS sync to establish baseline.""",
}

_FALLBACK_SYSTEM_PROMPT = _SCREEN_PROMPTS["overview"]


def _get_system_prompt(screen: str) -> str:
    return _SCREEN_PROMPTS.get(screen, _FALLBACK_SYSTEM_PROMPT)


_JOURNEY_PHASE_LABELS: dict[str, str] = {
    "phase_0_dark":              "Phase 0 — Dark (no DMARC record published, domain is openly spoofable)",
    "phase_1_monitoring":        "Phase 1 — Monitoring (p=none, collecting data, not yet enforcing)",
    "phase_2_pre_enforcement":   "Phase 2 — Pre-enforcement (p=quarantine, building confidence before full block)",
    "phase_3_enforced":          "Phase 3 — DMARC Enforced (p=reject active, MTA-STS not yet in enforce)",
    "phase_4_hardened":          "Phase 4 — Fully Hardened (p=reject + MTA-STS enforce, maintenance mode)",
    "portfolio_critical":        "Portfolio Phase — Critical (one or more domains have no DMARC record)",
    "portfolio_in_progress":     "Portfolio Phase — In Progress (all domains have records, not all at p=reject)",
    "portfolio_dmarc_complete":  "Portfolio Phase — DMARC Complete (all at p=reject, MTA-STS rollout in progress)",
    "portfolio_hardened":        "Portfolio Phase — Fully Hardened (all domains at p=reject + MTA-STS enforce)",
    "portfolio_empty":           "Portfolio Phase — No domains configured",
}

# Known ESPs and the specific fix for DMARC alignment failures
_ESP_FIX_MAP: dict[str, str] = {
    "google":        "Google Workspace — enable DKIM signing: Admin Console → Apps → Google Workspace → Gmail → Authenticate email, then publish the provided selector record in DNS",
    "gmail":         "Google Workspace — enable DKIM signing: Admin Console → Apps → Google Workspace → Gmail → Authenticate email",
    "googlemail":    "Google Workspace — enable DKIM signing: Admin Console → Apps → Google Workspace → Gmail → Authenticate email",
    "microsoft":     "Microsoft 365 — enable DKIM: Security portal → Email & collaboration → Policies → DKIM, enable for the domain and publish the two CNAME records in DNS",
    "office365":     "Microsoft 365 — enable DKIM: Security portal → Email & collaboration → Policies → DKIM, enable for the domain and publish the two CNAME records in DNS",
    "outlook":       "Microsoft 365 — enable DKIM signing in the Microsoft Security portal under Email & collaboration → Policies → DKIM",
    "hotmail":       "Microsoft 365 — enable DKIM signing in the Microsoft Security portal under Email & collaboration → Policies → DKIM",
    "sendgrid":      "SendGrid — authenticate your domain: Settings → Sender Authentication → Domain Authentication, publish the CNAME records provided",
    "twilio sendgrid": "SendGrid — authenticate your domain: Settings → Sender Authentication → Domain Authentication, publish the CNAME records provided",
    "mailchimp":     "Mailchimp — set up a custom sending domain: Account → Domains → Verify a domain, configure DKIM and SPF, publish the records they provide",
    "mandrill":      "Mandrill — add a sending domain under Sending Domains and publish the DKIM TXT record they provide",
    "amazon ses":    "Amazon SES — verify your domain and enable DKIM: SES Console → Verified Identities → your domain → DKIM, publish the CNAME records in Route53 or your DNS provider",
    "amazonses":     "Amazon SES — verify your domain and enable DKIM: SES Console → Verified Identities → your domain → DKIM, publish the CNAME records",
    "amazon":        "Amazon SES — verify your domain and enable DKIM: SES Console → Verified Identities → your domain → DKIM, publish the CNAME records",
    "mailgun":       "Mailgun — add your domain under Sending → Domains, publish the SPF include and DKIM TXT record they provide",
    "postmark":      "Postmark — add a sender signature for your domain and publish the DKIM record under Sender Signatures",
    "sparkpost":     "SparkPost — verify your sending domain and enable DKIM: Account → Sending Domains, publish the provided TXT record",
    "messagebird":   "MessageBird — configure a sending domain in the Email channel settings and publish the DKIM record they provide",
    "zendesk":       "Zendesk — configure your support address with a custom domain and enable DKIM: Admin → Channels → Email → Domain Verification",
    "hubspot":       "HubSpot — authenticate your email sending domain: Settings → Email → Sending Domains, publish the DKIM and SPF records they provide",
    "salesforce":    "Salesforce — set up DKIM keys: Setup → Email → DKIM Keys, activate a key for your domain and publish the CNAME record in DNS",
    "zoho":          "Zoho — verify your domain for email: Zoho Mail Admin → Domains, publish the SPF include and DKIM record they provide",
    "fastmail":      "Fastmail — add your domain under Settings → Domains and publish the DKIM, SPF, and MX records they provide",
    "mailjet":       "Mailjet — authenticate your domain: Account → Sender domains, publish the SPF include and DKIM TXT record",
}


def _classify_fail_sources(sources: list[str]) -> tuple[list[str], list[str]]:
    """
    Split failing sources into known ESPs (with specific fixes) and unknown sources.
    Returns (esp_lines, unknown_names).
    """
    esp_lines: list[str] = []
    unknown: list[str] = []
    seen: set[str] = set()
    for src in sources:
        src_lower = src.lower()
        matched = False
        for key, fix in _ESP_FIX_MAP.items():
            if key in src_lower and key not in seen:
                esp_lines.append(f"  • {src}: {fix}")
                seen.add(key)
                matched = True
                break
        if not matched:
            unknown.append(src)
    return esp_lines, unknown


def _compliance_interpretation(comp: float | None, phase: str) -> str:
    """Return a plain-English interpretation of the compliance rate in context."""
    if comp is None:
        return "No compliance data yet — aggregate reports haven't been received. Ensure the rua= reporting address in the DMARC record is correct."
    if comp >= 98:
        return f"{comp:.1f}% — excellent. All major sending sources are aligned."
    if comp >= 95:
        if phase in ("phase_1_monitoring", "phase_2_pre_enforcement"):
            return f"{comp:.1f}% — above the 95% advancement threshold. Policy can be advanced once remaining failing sources are investigated."
        return f"{comp:.1f}% — strong compliance, enforcement is working well."
    if comp >= 85:
        return f"{comp:.1f}% — approaching the threshold but not there yet. Resolve the failing sources listed below before advancing policy."
    if comp >= 70:
        return f"{comp:.1f}% — significant alignment gaps remain. Multiple sending sources are failing. Do not advance policy until this is above 95%."
    return f"{comp:.1f}% — critical alignment failure. More than 30% of messages are failing DMARC. Advancing policy at this level would block legitimate mail. Focus entirely on source alignment."


def _tls_pass_interpretation(pct: float | None, tls_stage: str | None) -> str:
    """Return a plain-English interpretation of the TLS pass rate in context."""
    if pct is None:
        return "No TLS session data yet — publish a TLS-RPT record so delivery data can be collected."
    if pct >= 99:
        if tls_stage == "testing":
            return f"{pct:.1f}% — clean. Ready to advance to enforce mode. Check certificate expiry before flipping."
        if tls_stage == "enforce":
            return f"{pct:.1f}% — fully protected. No TLS delivery failures."
        return f"{pct:.1f}% pass rate."
    if pct >= 95:
        return f"{pct:.1f}% — mostly healthy but some delivery failures. Investigate the failing MX hosts before advancing to enforce."
    if tls_stage == "enforce":
        return f"{pct:.1f}% — URGENT: enforce mode is active and {100 - pct:.1f}% of TLS sessions are failing. Legitimate inbound mail may be getting rejected. Check certificates and STARTTLS support on all MX hosts immediately."
    return f"{pct:.1f}% — notable failure rate. Do not advance to enforce mode until this is above 99%. Diagnose MX hosts for missing STARTTLS or expired/mismatched certificates."


def _next_gate(ctx: AdvisorContext) -> str | None:
    """Return a plain-English statement of the next milestone for this domain."""
    phase = ctx.journey_phase
    comp = ctx.dmarc_comp or 0

    if phase == "phase_0_dark":
        return "Next milestone: publish a DMARC record at p=none with a rua= reporting address to begin data collection."
    if phase == "phase_1_monitoring":
        if comp >= 95:
            return "Next milestone: advance to p=quarantine. Compliance is above the threshold — resolve any remaining failing sources first, then update the DMARC policy."
        return f"Next milestone: raise DMARC compliance above 95% (currently {comp:.1f}%) by aligning all failing sending sources, then advance to p=quarantine."
    if phase == "phase_2_pre_enforcement":
        if comp >= 95:
            return "Next milestone: advance to p=reject after 30 consecutive days above 95% compliance with no false positives in the quarantine folder."
        return f"Next milestone: raise compliance above 95% (currently {comp:.1f}%) before the quarantine window can begin. Do not advance until sources are aligned."
    if phase == "phase_3_enforced":
        tls = ctx.tls_stage or "none"
        if tls == "none":
            return "Next milestone: start MTA-STS in testing mode — DMARC enforcement is complete, inbound TLS protection is the next layer."
        if tls == "testing":
            pct = ctx.tls_pass_pct or 0
            if pct >= 99:
                return "Next milestone: advance MTA-STS from testing to enforce mode — TLS pass rate is clean. Verify certificate expiry before switching."
            return f"Next milestone: resolve TLS delivery failures (currently {pct:.1f}% pass rate) before advancing MTA-STS to enforce."
    if phase == "phase_4_hardened":
        return "Current status: fully hardened. Maintenance mode — monitor for new sending sources, certificate renewals, and MX host changes."
    return None


def _mta_sts_readiness(ctx: AdvisorContext) -> str | None:
    """Signal whether MTA-STS can or should be started in parallel."""
    if ctx.tls_stage and ctx.tls_stage != "none":
        return None  # already started, no need to prompt
    phase = ctx.journey_phase
    if phase in ("phase_1_monitoring", "phase_2_pre_enforcement", "phase_3_enforced"):
        return "MTA-STS parallel track: MTA-STS can be started in testing mode now — it is independent of DMARC and does not affect mail delivery in testing mode."
    return None


# Known ESPs whose default behaviour causes DMARC false positives in quarantine
_MARKETING_ESPS = {"mailchimp", "hubspot", "mandrill", "mailjet", "klaviyo", "constant contact", "campaign monitor", "activecampaign"}
# ESPs that require DKIM key publishing (CNAME or TXT) in the customer's DNS
_DKIM_PUBLISH_ESPS = {"sendgrid", "twilio sendgrid", "amazon ses", "amazonses", "mailgun", "postmark", "sparkpost"}


def _known_risks(ctx: AdvisorContext) -> list[str]:
    """
    Detect risk signals from context and return a list of pre-emptive warnings.
    These are injected into the briefing so the model volunteers them proactively.
    Each string is a self-contained risk statement the model can reference.
    """
    risks: list[str] = []
    phase = ctx.journey_phase
    comp = ctx.dmarc_comp or 0
    sources_lower = [s.lower() for s in ctx.fail_sources]

    # ── Phase 0 / 1 risks ─────────────────────────────────────────────────
    if phase in ("phase_0_dark", "phase_1_monitoring"):
        # SPF lookup limit
        if len(ctx.fail_sources) >= 5:
            risks.append(
                "SPF lookup limit risk: SPF allows a maximum of 10 DNS lookups. Organisations with many 'include:' entries often silently exceed this limit, causing SPF to fail for legitimate senders even though the sending IP is technically authorised. If compliance is low despite all sources appearing correct, check total SPF lookup count with an SPF validator tool."
            )
        # DKIM not deployed — no failing sources but low compliance
        if comp > 0 and comp < 85 and not ctx.fail_sources:
            risks.append(
                "Possible DKIM not deployed: Low compliance with no identified failing sources often means DKIM signing is not configured at the mail server or ESP level, so messages pass SPF but lack a DKIM signature — and if the envelope-from domain doesn't match the From header, DMARC fails on both checks. Verify DKIM is publishing in DNS with a selector lookup."
            )
        # Forwarding chains
        if comp > 0 and comp < 90:
            risks.append(
                "Email forwarding risk: Mail forwarding (e.g. from a legacy gateway, a shared mailbox, or a list server) breaks SPF alignment because the forwarding server's IP isn't in the original SPF record. If you see a sender source with a low pass rate that you recognise as legitimate, forwarding is the likely cause — DKIM is the only mechanism that survives forwarding intact."
            )

    # ── Phase 2 risks ─────────────────────────────────────────────────────
    if phase == "phase_2_pre_enforcement":
        # Marketing ESP false positive trap
        marketing_failing = [s for s in sources_lower if any(m in s for m in _MARKETING_ESPS)]
        if marketing_failing:
            named = ", ".join(ctx.fail_sources[i] for i, s in enumerate(sources_lower) if any(m in s for m in _MARKETING_ESPS))
            risks.append(
                f"False positive risk — marketing platforms: {named} sign outbound mail with their own domain by default, not yours. At p=quarantine, this will put legitimate marketing emails into recipients' spam folders. This is the most common reason teams panic and roll back to p=none. Fix: configure a custom sending domain in each platform's settings and publish the DKIM selector they provide. Do not advance to p=reject until this is resolved."
            )
        # Subdomain policy gap
        risks.append(
            "Subdomain policy gap: Your DMARC policy at p=quarantine applies to the root domain. If you have subdomains that send email (e.g. billing.acme.co.za, notifications.acme.co.za), they inherit the root policy — but if any subdomains are used for other purposes and don't have their own DMARC record, attackers can spoof those subdomains. Consider adding sp=quarantine or sp=reject to your root DMARC record, or publish separate DMARC records for sending subdomains."
        )
        # Compliance below gate despite being in quarantine
        if comp < 95:
            risks.append(
                f"Advancement blocker: Compliance is at {comp:.1f}% — below the 95% threshold required before the 30-day quarantine confidence window begins. Advancing to p=reject at this level would cause legitimate mail from unaligned sources to be rejected. Resolve failing sources first, then restart the 30-day clock once compliance is stable above 95%."
            )

    # ── Phase 3 risks ─────────────────────────────────────────────────────
    if phase == "phase_3_enforced":
        # MTA-STS not started — cert risk when they do start
        if not ctx.tls_stage or ctx.tls_stage == "none":
            risks.append(
                "MTA-STS enforce mode trap: When you advance MTA-STS from testing to enforce, any MX host with an expired or hostname-mismatched certificate will immediately start rejecting inbound mail from enforcing senders — silently, with no bounce to the original sender. Before switching to enforce: verify every MX host has a valid cert with >30 days remaining and that the cert CN/SAN matches the MX hostname exactly."
            )
        # New source risk post-reject
        risks.append(
            "New sender rejection risk: Now that you are at p=reject, any new email service or integration added to your infrastructure without SPF/DKIM setup will have its mail silently rejected. This is the most common post-enforcement incident — a new CRM, ticketing tool, or automated system starts sending without being authorised in DNS. Establish a process: before any new service sends email, add its SPF include and configure DKIM signing first."
        )

    # ── Phase 4 risks ─────────────────────────────────────────────────────
    if phase == "phase_4_hardened":
        # Cert expiry in enforce mode
        if ctx.cert_days is not None and ctx.cert_days < 45:
            risks.append(
                f"Certificate expiry in enforce mode: A cert expires in {ctx.cert_days} days. In MTA-STS enforce mode, an expired certificate causes sending mail servers to refuse delivery — immediately and silently, with no bounce to the sender. This is the most common post-enforcement outage. Renew now, not at the 7-day reminder."
            )
        risks.append(
            "DKIM key rotation: If your mail server or ESP rotates DKIM private keys without updating the public key selector in DNS, DKIM signatures will fail validation and DMARC will drop from 98%+ to much lower — at p=reject, this causes legitimate mail to be rejected. Confirm that your key rotation process updates the DNS TXT record before retiring the old selector."
        )

    # ── TLS-stage-specific risks (any phase) ──────────────────────────────
    if ctx.tls_stage == "testing" and ctx.tls_pass_pct is not None and ctx.tls_pass_pct < 99:
        risks.append(
            f"Do not advance to MTA-STS enforce: TLS pass rate is {ctx.tls_pass_pct:.1f}% — advancing to enforce at this level would start rejecting inbound mail from any sending server that cannot negotiate TLS or presents an invalid certificate. Diagnose the failing MX hosts first."
        )

    if ctx.tls_stage == "enforce" and ctx.tls_pass_pct is not None and ctx.tls_pass_pct < 99:
        risks.append(
            f"Active delivery failure: MTA-STS enforce is active at {ctx.tls_pass_pct:.1f}% pass rate — {100 - ctx.tls_pass_pct:.1f}% of inbound TLS sessions are failing and mail is being rejected. Check the Certificates page immediately for expired, mismatched, or STARTTLS-missing MX hosts."
        )

    # ── Cert expiry cross-cutting risk ────────────────────────────────────
    if ctx.cert_days is not None:
        if ctx.cert_days <= 0:
            risks.append(
                "Certificate expired: At least one certificate has expired. If MTA-STS enforce is active, inbound mail delivery is failing right now. Renew immediately."
            )
        elif ctx.cert_days <= 14 and ctx.tls_stage == "enforce":
            risks.append(
                f"Critical cert window: Certificate expires in {ctx.cert_days} days with MTA-STS in enforce mode. Renew within the next 48 hours — if it expires before renewal, inbound mail will be rejected and the only remediation is cert renewal plus a MTA-STS policy version bump to force cache refresh."
            )
        elif ctx.cert_days <= 14 and ctx.tls_stage == "testing":
            risks.append(
                f"Do not advance to enforce: Certificate expires in {ctx.cert_days} days. Renew the cert before flipping to enforce mode — if you flip with an expiring cert, you will trigger an enforcement outage within days."
            )

    return risks


def _build_prompt(ctx: AdvisorContext) -> str:
    phase_label = _JOURNEY_PHASE_LABELS.get(ctx.journey_phase, ctx.journey_phase)
    sections: list[str] = [
        f"=== ZONEPROOF ADVISOR BRIEFING ===",
        f"Screen: {ctx.screen}",
        f"Journey phase: {phase_label}",
    ]

    if ctx.domain_name:
        # ── Domain-level briefing ──────────────────────────────────────────
        sections.append(f"\n--- DOMAIN STATE ---")
        sections.append(f"Domain: {ctx.domain_name}")
        sections.append(f"DMARC record published: {'yes' if ctx.dmarc_record_published else 'NO — domain is openly spoofable'}")
        sections.append(f"DMARC policy: p={ctx.dmarc_stage or 'none'}")

        # Compliance with interpretation
        comp_interp = _compliance_interpretation(ctx.dmarc_comp, ctx.journey_phase)
        sections.append(f"DMARC compliance: {comp_interp}")

        # MTA-STS with interpretation
        tls_label = ctx.tls_stage or "none"
        sections.append(f"MTA-STS mode: {tls_label}")
        if ctx.tls_pass_pct is not None or ctx.tls_stage:
            tls_interp = _tls_pass_interpretation(ctx.tls_pass_pct, ctx.tls_stage)
            sections.append(f"TLS session pass rate: {tls_interp}")

        # Cert expiry with urgency flag
        if ctx.cert_days is not None:
            if ctx.cert_days <= 0:
                cert_note = f"EXPIRED — if MTA-STS is in enforce mode, inbound mail delivery is failing right now"
            elif ctx.cert_days <= 14:
                cert_note = f"{ctx.cert_days} days — CRITICAL: renew immediately"
            elif ctx.cert_days <= 30:
                cert_note = f"{ctx.cert_days} days — expiring soon, schedule renewal now"
            else:
                cert_note = f"{ctx.cert_days} days remaining"
            sections.append(f"Soonest certificate expiry: {cert_note}")

        # Failing sources — classified
        if ctx.fail_sources:
            esp_lines, unknown = _classify_fail_sources(ctx.fail_sources[:6])
            sections.append(f"\n--- FAILING SENDING SOURCES ---")
            if esp_lines:
                sections.append("Known ESPs with specific fixes required:")
                sections.extend(esp_lines)
            if unknown:
                sections.append(f"Unrecognised sources (investigate whether authorised): {', '.join(unknown)}")
        else:
            sections.append("\nFailing sending sources: none identified")

        # Next gate
        gate = _next_gate(ctx)
        if gate:
            sections.append(f"\n--- NEXT MILESTONE ---")
            sections.append(gate)

        # MTA-STS parallel readiness
        mta_hint = _mta_sts_readiness(ctx)
        if mta_hint:
            sections.append(f"\n--- PARALLEL OPPORTUNITY ---")
            sections.append(mta_hint)

    elif ctx.screen == "posture_tls":
        # ── Portfolio TLS briefing ─────────────────────────────────────────
        sections.append(f"\n--- PORTFOLIO MTA-STS STATE ---")
        sections.append(f"Total domains: {ctx.all_domains_count}")
        sections.append(f"MTA-STS enforce (fully protected): {ctx.enforce_count}")
        sections.append(f"MTA-STS testing (monitoring, not yet enforcing): {ctx.testing_count}")
        sections.append(f"No MTA-STS policy (inbound plaintext possible): {ctx.no_mta_sts_count}")
        if ctx.no_mta_sts_count > 0:
            sections.append(f"Risk: {ctx.no_mta_sts_count} domain(s) can receive inbound mail over plaintext with no TLS enforcement.")
        if ctx.enforce_count > 0 and ctx.enforce_count < ctx.all_domains_count:
            sections.append(f"Progress: {ctx.enforce_count}/{ctx.all_domains_count} domains fully hardened for inbound TLS.")
        if ctx.testing_count > 0:
            sections.append(f"Gate for testing→enforce: 30 days of TLS pass rate ≥99% with no delivery failures. Check certificate expiry before flipping any domain.")

    else:
        # ── Portfolio DMARC briefing ───────────────────────────────────────
        sections.append(f"\n--- PORTFOLIO DMARC STATE ---")
        sections.append(f"Total domains: {ctx.all_domains_count}")
        sections.append(f"At p=reject (fully enforced): {ctx.reject_count}")
        sections.append(f"At p=quarantine (pre-enforcement window): {ctx.quarantine_count}")
        sections.append(f"At p=none/monitor (data collection): {ctx.monitor_count}")
        sections.append(f"No DMARC record (openly spoofable): {ctx.unprotected_count}")
        sections.append(f"\n--- PORTFOLIO MTA-STS STATE ---")
        sections.append(f"MTA-STS enforce: {ctx.enforce_count} | testing: {ctx.testing_count} | none: {ctx.no_mta_sts_count}")
        if ctx.unprotected_count > 0:
            sections.append(f"Risk: {ctx.unprotected_count} domain(s) with no DMARC record can be impersonated by anyone right now.")
        if ctx.reject_count == ctx.all_domains_count and ctx.all_domains_count > 0:
            sections.append("DMARC status: all domains at full enforcement. MTA-STS rollout is the next project.")

        # ── Threat surface (last 30 days) ─────────────────────────────────
        if ctx.threat_attempts > 0:
            sections.append(f"\n--- THREAT SURFACE (last 30 days) ---")
            sections.append(f"Total impersonation attempts detected: {ctx.threat_attempts:,}")
            sections.append(f"Blocked by DMARC enforcement (p=reject domains): {ctx.threat_blocked:,} ({ctx.threat_blocked_pct:.1f}%)")
            sections.append(f"Unblocked — reached inboxes or spam (p=none/quarantine domains): {ctx.threat_unblocked:,}")
            if ctx.most_targeted_domain:
                sections.append(f"Most targeted domain: {ctx.most_targeted_domain} ({ctx.most_targeted_attempts:,} attempts)")
            # Interpret unblocked threat exposure
            if ctx.threat_unblocked > 0 and ctx.unprotected_count > 0:
                sections.append(
                    f"Exposure gap: {ctx.threat_unblocked:,} impersonation attempts were NOT blocked because "
                    f"{ctx.unprotected_count} domain(s) have no DMARC enforcement. These emails reached recipients."
                )
            elif ctx.threat_unblocked > 0:
                sections.append(
                    f"Exposure gap: {ctx.threat_unblocked:,} impersonation attempts reached recipients because "
                    f"some domains are not yet at p=reject. Advancing those domains would close this gap."
                )
            if ctx.threat_blocked_pct == 100 and ctx.threat_attempts > 0:
                sections.append("All detected impersonation attempts were blocked — full enforcement is working.")

    # ── Known risks section ───────────────────────────────────────────────
    risks = _known_risks(ctx)
    if risks:
        sections.append(f"\n--- RISKS TO PRE-EMPT ---")
        sections.append("The following risks are relevant at this phase. Mention the most relevant one if it strengthens the advice:")
        for i, r in enumerate(risks, 1):
            sections.append(f"{i}. {r}")

    sections.append(f"\n=== END BRIEFING ===")
    sections.append("Provide advisor output JSON. /no_think")
    return "\n".join(sections)


# ── Rule-based fallback ────────────────────────────────────────────────────────

def _rule_based(ctx: AdvisorContext) -> dict:
    name = ctx.domain_name or "this domain"
    screen = ctx.screen

    # ── TLS / MTA-STS screen ──────────────────────────────────────────────────
    if screen in ("tls", "posture_tls"):
        # Portfolio view for posture_tls without domain
        if screen == "posture_tls" and not ctx.domain_name:
            if ctx.enforce_count == ctx.all_domains_count and ctx.all_domains_count > 0:
                return {
                    "message": f"All {ctx.all_domains_count} domain(s) have MTA-STS enforce mode active — inbound TLS is fully protected. Monitor certificate renewals to maintain enforcement.",
                    "commend": True,
                    "citations": [],
                }
            if ctx.no_mta_sts_count > 0:
                return {
                    "message": f"{ctx.no_mta_sts_count} of your {ctx.all_domains_count} domain(s) have no MTA-STS policy — publish a testing-mode policy and TLS-RPT record on those first.",
                    "commend": False,
                    "citations": [],
                }
            return {
                "message": f"{ctx.testing_count} domain(s) are in MTA-STS testing mode — once TLS pass rates are stable for 30 days, advance them to enforce to block TLS downgrade attacks.",
                "commend": False,
                "citations": [],
            }
        if ctx.tls_stage == "enforce" and ctx.tls_pass_pct and ctx.tls_pass_pct >= 99:
            return {
                "message": f"{name} MTA-STS is fully enforced at {ctx.tls_pass_pct:.1f}% pass rate — inbound mail is protected against TLS downgrade attacks. Monitor for certificate renewals.",
                "commend": True,
                "citations": [],
            }
        if ctx.tls_stage == "enforce":
            return {
                "message": f"{name} MTA-STS is enforced but TLS pass rate is {ctx.tls_pass_pct or 0:.1f}% — check the failure analysis below for MX hosts with certificate or STARTTLS issues.",
                "commend": False,
                "citations": [],
            }
        if ctx.tls_stage == "testing":
            if ctx.tls_pass_pct and ctx.tls_pass_pct >= 99:
                cert_warn = f" Renew the certificate on the MX host ({ctx.cert_days}d remaining) first." if ctx.cert_days and ctx.cert_days < 30 else ""
                return {
                    "message": f"{name} TLS testing is clean at {ctx.tls_pass_pct:.1f}% — no delivery failures detected. You can advance to enforce mode.{cert_warn}",
                    "commend": False,
                    "citations": [],
                }
            return {
                "message": f"{name} MTA-STS is in testing mode at {ctx.tls_pass_pct or 0:.1f}% pass rate. Resolve the TLS failures shown below before switching to enforce, or legitimate mail could be rejected.",
                "commend": False,
                "citations": [],
            }
        # no MTA-STS policy
        return {
            "message": f"{name} has no MTA-STS policy — inbound mail can be delivered over plaintext with no warning. Publish a policy in testing mode and add a TLS-RPT record so ZoneProof can surface delivery failures.",
            "commend": False,
            "citations": ["RFC 8461"],
        }

    # ── DMARC screen ──────────────────────────────────────────────────────────
    if screen == "dmarc":
        if not ctx.dmarc_stage or ctx.dmarc_stage == "none":
            return {
                "message": f"{name} has no DMARC record and is openly spoofable. Publish p=none with your reporting address to start collecting data — the wizard will guide you.",
                "commend": False,
                "citations": ["RFC 7489 §6.1"],
            }
        if ctx.dmarc_stage == "monitor" and ctx.fail_sources:
            sources = ", ".join(ctx.fail_sources[:2])
            return {
                "message": f"{name} is at p=none ({ctx.dmarc_comp or 0:.0f}% passing). The fastest path to quarantine is aligning {sources} — once those are fixed, unauthenticated senders can be quarantined.",
                "commend": False,
                "citations": [],
            }
        if ctx.dmarc_stage == "quarantine":
            return {
                "message": f"{name} is at quarantine with {ctx.dmarc_comp or 0:.1f}% compliance. Once you reach 30 days without false positives, advance to p=reject to fully block spoofing.",
                "commend": False,
                "citations": [],
            }
        if ctx.dmarc_stage == "reject":
            return {
                "message": f"{name} is at p=reject with {ctx.dmarc_comp or 0:.1f}% compliance — spoofed mail is being actively blocked. Continue monitoring for any new sending sources.",
                "commend": True,
                "citations": [],
            }

    # ── Overview / posture screen (DMARC-led summary) ─────────────────────────
    if screen in ("overview", "posture", "posture_dmarc"):
        # Domain-specific view
        if ctx.domain_name and ctx.dmarc_stage:
            name = ctx.domain_name
            if ctx.dmarc_stage == "reject":
                return {
                    "message": f"{name} is at p=reject with {ctx.dmarc_comp or 0:.1f}% compliance — spoofed mail is blocked. Continue monitoring for new sending sources and review MTA-STS posture.",
                    "commend": True,
                    "citations": [],
                }
            if ctx.dmarc_stage == "quarantine":
                return {
                    "message": f"{name} is at quarantine ({ctx.dmarc_comp or 0:.1f}% compliant). After 30 days without false positives, advance to p=reject to fully block spoofing.",
                    "commend": False,
                    "citations": [],
                }
            if ctx.fail_sources:
                sources = ", ".join(ctx.fail_sources[:2])
                return {
                    "message": f"{name} is at p=none ({ctx.dmarc_comp or 0:.0f}% passing). The fastest path to quarantine is aligning {sources} — once fixed, unauthenticated senders can be quarantined.",
                    "commend": False,
                    "citations": [],
                }
            return {
                "message": f"{name} is at p=none — no DMARC enforcement active. Align all sending sources, then advance the policy to quarantine.",
                "commend": False,
                "citations": [],
            }
        # Portfolio view
        if ctx.unprotected_count and ctx.unprotected_count > 0:
            return {
                "message": f"{ctx.unprotected_count} of {ctx.all_domains_count} domain(s) have no DMARC record and are openly spoofable. Start with the wizard to publish a p=none monitoring record.",
                "commend": False,
                "citations": [],
            }
        if ctx.reject_count == ctx.all_domains_count:
            return {
                "message": f"All {ctx.all_domains_count} domain(s) are at p=reject — your portfolio is fully protected against spoofing. Keep an eye on certificate renewals and TLS pass rates.",
                "commend": True,
                "citations": [],
            }
        return {
            "message": f"{ctx.reject_count} of {ctx.all_domains_count} domain(s) are at p=reject. Focus on advancing the remaining domains through quarantine to reach full enforcement.",
            "commend": False,
            "citations": [],
        }

    # ── Roadmap / certs screens ───────────────────────────────────────────────
    if screen == "certs":
        if ctx.cert_days and ctx.cert_days < 14:
            return {
                "message": f"A certificate on {name} expires in {ctx.cert_days} days — renew it immediately or TLS delivery failures will begin appearing in your MTA-STS reports.",
                "commend": False,
                "citations": [],
            }
        return {
            "message": f"Certificates for {name} look healthy. Continue monitoring expiry dates and ensure all MX hosts present valid, hostname-matched certificates.",
            "commend": True,
            "citations": [],
        }

    # Generic fallback
    return {
        "message": f"Review {name}'s posture — DMARC at {ctx.dmarc_stage or 'none'}, MTA-STS at {ctx.tls_stage or 'none'}, {ctx.dmarc_comp or 0:.0f}% DMARC compliant.",
        "commend": False,
        "citations": [],
    }


# ── LLM call ──────────────────────────────────────────────────────────────────

async def generate_dns_risk_assessment(
    record_type: str,
    previous_value: str | None,
    current_value: str | None,
    domain_name: str,
    change_type: str,   # added | modified | removed
) -> dict:
    """
    Classify the security risk of a DNS record change.
    Returns { severity: info|warn|critical, explanation: str, action: str, is_ai: bool }.
    Falls back to rule-based if Ollama unavailable.
    """
    # ── Rule-based fallback ───────────────────────────────────────────────────
    sev = "info"
    exp = f"{record_type} record {change_type} on {domain_name}."
    act = "Review the change to confirm it was intentional."

    if change_type == "removed":
        if record_type in ("DMARC", "SPF"):
            sev = "critical"
            exp = f"The {record_type} record on {domain_name} was removed. This domain is now openly spoofable — anyone can send email impersonating it."
            act = f"Restore the {record_type} record immediately. If this was intentional, confirm with the domain owner."
        elif record_type == "MX":
            sev = "warn"
            exp = f"MX records for {domain_name} were removed. Inbound mail will no longer be delivered."
            act = "Restore the MX record unless the domain intentionally stops receiving email."
        elif record_type in ("MTA-STS", "TLS-RPT"):
            sev = "info"
            exp = f"The {record_type} record on {domain_name} was removed. Inbound TLS enforcement is weakened."
            act = "Republish the record if TLS enforcement is required."

    elif change_type == "added":
        if record_type == "DMARC":
            sev = "info"
            exp = f"A new DMARC record was published for {domain_name}. Email authentication reporting is now active."
            act = "Verify the record contains your correct reporting address and the intended policy."
        elif record_type == "CNAME":
            _platform_targets = (settings.reporting_domain, settings.mta_sts_hosting_cname_target)
            if current_value and any(t in current_value for t in _platform_targets):
                sev = "info"
                exp = f"CNAME added for {domain_name} pointing to ZoneProof infrastructure ({current_value.strip()})."
                act = "No action needed — this is expected ZoneProof managed-hosting configuration."
                return {"severity": sev, "explanation": exp, "action": act, "is_ai": False}
        elif record_type == "SPF":
            if current_value and ("+all" in current_value or " all" in current_value.lower()):
                sev = "critical"
                exp = f"The SPF record for {domain_name} contains a permissive 'all' mechanism — any server on the internet can send email as this domain."
                act = "Replace '+all' or 'all' with '~all' (softfail) or '-all' (hardfail) immediately."
            else:
                sev = "info"
                exp = f"A new SPF record was published for {domain_name}."
                act = "Confirm all authorised sending sources are included."

    elif change_type == "modified":
        if record_type == "DMARC":
            prev_pol = ""
            curr_pol = ""
            for part in (previous_value or "").split(";"):
                if "p=" in part.lower():
                    prev_pol = part.strip().split("=")[-1].strip()
            for part in (current_value or "").split(";"):
                if "p=" in part.lower():
                    curr_pol = part.strip().split("=")[-1].strip()
            order = {"reject": 2, "quarantine": 1, "none": 0}
            if order.get(curr_pol, -1) < order.get(prev_pol, -1):
                sev = "warn"
                exp = f"DMARC policy on {domain_name} was downgraded from p={prev_pol} to p={curr_pol}. Enforcement has been weakened."
                act = "Investigate the reason for the downgrade. Restore p=" + prev_pol + " if not intentional."
            else:
                # If the only material change was adding/updating the ZoneProof reporting address,
                # this is expected onboarding activity — classify as info and short-circuit to
                # avoid the LLM recommending to remove our own reporting address.
                sentinel_rua = f"@{settings.reporting_domain}"
                if current_value and sentinel_rua in current_value:
                    sev = "info"
                    exp = f"DMARC record on {domain_name} was updated to include ZoneProof reporting (p={curr_pol})."
                    act = "No action needed — this is expected ZoneProof onboarding."
                    return {"severity": sev, "explanation": exp, "action": act, "is_ai": False}
                sev = "info"
                exp = f"DMARC record on {domain_name} was updated (p={curr_pol})."
                act = "Confirm the new record reflects your intended authentication policy."
        elif record_type == "CNAME":
            _platform_targets = (settings.reporting_domain, settings.mta_sts_hosting_cname_target)
            if current_value and any(t in current_value for t in _platform_targets):
                sev = "info"
                exp = f"CNAME on {domain_name} updated to point to ZoneProof infrastructure ({current_value.strip()})."
                act = "No action needed — this is expected ZoneProof managed-hosting configuration."
                return {"severity": sev, "explanation": exp, "action": act, "is_ai": False}
            sev = "warn"
            exp = f"CNAME on {domain_name} was changed to point to {current_value or 'an unknown target'}."
            act = "Verify the new CNAME target is correct and under your control."
        elif record_type == "SPF":
            if current_value and ("+all" in current_value or " all" in current_value.lower()):
                sev = "critical"
                exp = f"The SPF record for {domain_name} now contains a permissive 'all' mechanism after modification."
                act = "Replace '+all' or 'all' with '~all' or '-all' immediately."
            else:
                sev = "info"
                exp = f"SPF record on {domain_name} was modified."
                act = "Confirm the updated record includes all authorised senders and no unexpected includes."
        elif record_type == "MX":
            sev = "warn"
            exp = f"MX records for {domain_name} changed. Inbound mail routing has been altered."
            act = "Verify the new MX hosts are correct and under your control."

    if not settings.advisor_enabled:
        return {"severity": sev, "explanation": exp, "action": act, "is_ai": False}

    prompt_ctx = json.dumps({
        "domain": domain_name,
        "record_type": record_type,
        "change_type": change_type,
        "previous_value": previous_value,
        "current_value": current_value,
    })

    system = f"""You are ZoneProof, an email security platform. Classify the security risk of a DNS record change.

Rules:
- Output ONLY valid JSON: {{"severity": "info|warn|critical", "explanation": "...", "action": "..."}}
- severity: info (expected/benign), warn (notable, investigate), critical (immediate threat)
- explanation: 1-2 sentences. What happened and why it matters.
- action: 1 sentence. The single most important thing to do right now.
- Do not invent facts. Use only the provided values.
- Audience: IT administrator.
- IMPORTANT: {settings.reporting_domain} is ZoneProof's own platform domain. Any of the following are expected onboarding activity — classify as info and do NOT flag them as suspicious:
  * DMARC rua= or ruf= addresses at @{settings.reporting_domain}
  * CNAME records pointing to {settings.mta_sts_hosting_cname_target} (ZoneProof managed MTA-STS hosting)
  * Any DNS record that references {settings.reporting_domain} as part of ZoneProof onboarding"""

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{settings.advisor_llm_url}/api/chat",
                json={
                    "model": settings.advisor_llm_model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": f"DNS change: {prompt_ctx}\n\nClassify the risk."},
                    ],
                    "stream": False,
                    "options": {"temperature": 0},
                },
            )
            resp.raise_for_status()
            content = _strip_thinking(resp.json()["message"]["content"])
            start = content.find("{")
            end = content.rfind("}") + 1
            parsed = json.loads(content[start:end])
            severity = parsed.get("severity", sev)
            if severity not in ("info", "warn", "critical"):
                severity = sev
            return {
                "severity": severity,
                "explanation": str(parsed.get("explanation", exp)),
                "action": str(parsed.get("action", act)),
                "is_ai": True,
            }
    except Exception as e:
        log.warning("DNS risk LLM failed (%s), using rule-based fallback", e)
        return {"severity": sev, "explanation": exp, "action": act, "is_ai": False}


async def generate_report_narrative(report_data: dict) -> dict:
    """
    Generate a 3-part executive narrative from report metrics.
    Returns { summary, threats, actions, is_ai }.
    Falls back to rule-based if Ollama unavailable.
    """
    # Always generate rule-based first as fallback
    score = report_data.get("score", 0)
    grade = report_data.get("grade", "F")
    delta = report_data.get("delta")
    dmarc_comp = report_data.get("avg_dmarc_comp")
    threat_attempts = report_data.get("threat_attempts", 0)
    threat_blocked_pct = report_data.get("threat_blocked_pct", 0.0)
    cert_alerts = report_data.get("cert_alerts", 0)
    total_domains = report_data.get("total_domains", 0)
    reject_count = report_data.get("dmarc_reject_count", 0)
    none_count = report_data.get("dmarc_none_count", 0)
    period_days = report_data.get("period_days", 30)
    workspace = report_data.get("workspace_name", "your organisation")

    grade_desc = {
        "A": "fully protected", "B": "a strong security posture",
        "C": "partial coverage with notable gaps",
        "D": "significant gaps leaving domains exposed",
        "F": "critical gaps requiring immediate action",
    }.get(grade, "an assessed posture")

    delta_str = ""
    if delta is not None:
        if delta > 3:
            delta_str = f" The score improved by {delta} points over the period, reflecting active remediation."
        elif delta < -3:
            delta_str = f" The score declined by {abs(delta)} points — review recent changes to sending infrastructure."

    rb_summary = (
        f"{workspace} has a ZoneProof Score of {score}/100 (Grade {grade}), indicating {grade_desc} "
        f"across {total_domains} monitored domain{'s' if total_domains != 1 else ''} "
        f"over the past {period_days} days.{delta_str}"
    )

    if threat_attempts > 0:
        rb_threats = (
            f"{threat_attempts:,} impersonation attempt{'s were' if threat_attempts != 1 else ' was'} detected "
            f"this period, with {threat_blocked_pct:.0f}% blocked by DMARC enforcement. "
            f"{'The remaining attempts reached recipient inboxes — tighten enforcement on affected domains.' if threat_blocked_pct < 100 else 'All attempts were blocked.'}"
        )
    elif none_count > 0:
        rb_threats = (
            f"{none_count} domain{'s have' if none_count != 1 else ' has'} no DMARC record, leaving "
            f"{'them' if none_count != 1 else 'it'} openly spoofable. No impersonation data has been collected yet — "
            f"publishing a monitoring record is the critical first step."
        )
    else:
        rb_threats = (
            f"No active impersonation attempts were detected this period. "
            f"{'Certificate alerts require attention to maintain TLS delivery integrity.' if cert_alerts > 0 else 'Your threat posture is clean.'}"
        )

    if none_count > 0:
        rb_actions = (
            f"Priority action: publish a DMARC p=none record on the {none_count} unprotected "
            f"domain{'s' if none_count != 1 else ''} to begin collecting authentication data. "
            f"Then advance domains at quarantine to p=reject for full enforcement."
        )
    elif reject_count < total_domains:
        remaining = total_domains - reject_count
        rb_actions = (
            f"{remaining} domain{'s are' if remaining != 1 else ' is'} not yet at full DMARC enforcement. "
            f"Advance to p=reject to block spoofing outright. "
            f"{'Resolve certificate alerts first to avoid MTA-STS delivery failures.' if cert_alerts > 0 else 'Use the Policy Simulation before promoting to verify no legitimate mail is affected.'}"
        )
    else:
        rb_actions = (
            f"All domains are at full DMARC enforcement. "
            f"{'Renew the flagged certificates to maintain uninterrupted TLS delivery.' if cert_alerts > 0 else 'Focus on MTA-STS advancement to enforce encrypted inbound delivery across the portfolio.'}"
        )

    if not settings.advisor_enabled:
        return {"summary": rb_summary, "threats": rb_threats, "actions": rb_actions, "is_ai": False}

    prompt_ctx = json.dumps({
        "workspace": workspace,
        "period_days": period_days,
        "sentinel_score": score,
        "grade": grade,
        "score_delta": delta,
        "avg_dmarc_compliance_pct": dmarc_comp,
        "total_domains": total_domains,
        "domains_at_reject": reject_count,
        "domains_no_dmarc": none_count,
        "impersonation_attempts": threat_attempts,
        "attempts_blocked_pct": threat_blocked_pct,
        "cert_alerts": cert_alerts,
    })

    system = """You are ZoneProof, an email security intelligence platform. Write an executive narrative for an IT security report.

Rules:
- Output ONLY valid JSON: {"summary": "...", "threats": "...", "actions": "..."}
- Each value is exactly 1-2 sentences. Plain English. No bullet points. No markdown.
- summary: overall posture and score context
- threats: what was detected or not detected this period
- actions: the single most important next step
- Use numbers from the context. Do not invent facts.
- Tone: professional, direct. Audience: a non-technical business decision-maker."""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{settings.advisor_llm_url}/api/chat",
                json={
                    "model": settings.advisor_llm_model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": f"Security data: {prompt_ctx}\n\nWrite the executive narrative JSON."},
                    ],
                    "stream": False,
                    "options": {"temperature": 0},
                },
            )
            resp.raise_for_status()
            content = _strip_thinking(resp.json()["message"]["content"])
            start = content.find("{")
            end = content.rfind("}") + 1
            parsed = json.loads(content[start:end])
            return {
                "summary": str(parsed.get("summary", rb_summary)),
                "threats": str(parsed.get("threats", rb_threats)),
                "actions": str(parsed.get("actions", rb_actions)),
                "is_ai": True,
            }
    except Exception as e:
        log.warning("Narrative LLM failed (%s), using rule-based fallback", e)
        return {"summary": rb_summary, "threats": rb_threats, "actions": rb_actions, "is_ai": False}


async def generate_sender_recommendation(
    source_org: str,
    source_ip: str | None,
    domain_name: str,
    dkim_result: str | None,
    spf_result: str | None,
    total_count: int,
    pass_count: int,
) -> dict:
    """
    Classify a new DMARC sending source and recommend a DNS fix.
    Returns { classification, recommendation, dns_fix, is_ai }.
    """
    pass_rate = (pass_count / total_count * 100) if total_count > 0 else 0.0

    KNOWN_ESPS = {
        "google", "gmail", "googlemail", "google.com",
        "microsoft", "outlook", "hotmail", "office365",
        "sendgrid", "twilio sendgrid",
        "mailchimp", "mandrill",
        "amazon ses", "amazonses", "amazon",
        "mailgun",
        "postmark",
        "sparkpost", "messagebird",
        "zendesk",
        "hubspot",
        "salesforce",
        "zoho",
        "fastmail",
    }

    org_lower = source_org.lower()
    is_known = any(esp in org_lower for esp in KNOWN_ESPS)

    if is_known:
        rb_class = "known_esp"
        rb_rec = (
            f"{source_org} is a recognised email service provider. "
            f"Ensure your SPF record includes their sending range and that DKIM signing is configured "
            f"through their admin panel."
        )
        rb_fix = f"Add the {source_org} SPF include to your TXT record at {domain_name}, e.g. 'include:{org_lower.replace(' ', '')}.com'."
    elif pass_rate < 10 and total_count >= 5:
        rb_class = "suspicious"
        rb_rec = (
            f"{source_org} sent {total_count} messages from {domain_name} with only {pass_rate:.0f}% passing DMARC. "
            f"This pattern may indicate spoofing — investigate whether you authorised this source."
        )
        rb_fix = (
            f"If {source_org} is not an authorised sender, ensure DMARC is at p=quarantine or p=reject "
            f"to block these messages. Do not add them to your SPF record."
        )
    else:
        rb_class = "unknown"
        rb_rec = (
            f"{source_org} is an unrecognised sending source for {domain_name} "
            f"({pass_rate:.0f}% DMARC pass rate). "
            f"If this is a legitimate service you use, add it to your SPF record and configure DKIM signing."
        )
        rb_fix = (
            f"Identify whether {source_org} is a vendor or service. "
            f"If legitimate, add their SPF include to {domain_name} and enable DKIM through their platform."
        )

    if not settings.advisor_enabled:
        return {"classification": rb_class, "recommendation": rb_rec, "dns_fix": rb_fix, "is_ai": False}

    prompt_ctx = json.dumps({
        "domain": domain_name,
        "source_org": source_org,
        "source_ip": source_ip,
        "dkim_result": dkim_result,
        "spf_result": spf_result,
        "total_messages": total_count,
        "dmarc_pass_count": pass_count,
        "dmarc_pass_rate_pct": round(pass_rate, 1),
    })

    system = """You are ZoneProof, an email security platform. Classify a new DMARC sending source for a domain.

Rules:
- Output ONLY valid JSON: {"classification": "...", "recommendation": "...", "dns_fix": "..."}
- classification must be one of: known_esp, unknown, suspicious
  - known_esp: a recognised email service provider (Google, Microsoft, SendGrid, Mailchimp, etc.)
  - suspicious: low pass rate (<20%) with meaningful volume suggesting potential spoofing
  - unknown: unrecognised source that may be a legitimate vendor needing SPF/DKIM setup
- recommendation: 1-2 sentences. Plain English. What this source is and what the admin should do.
- dns_fix: 1 sentence. The exact DNS action to take, if any. E.g. "Add 'include:sendgrid.net' to your SPF record."
- Do not invent facts. Use only what is provided.
- Audience: IT administrator."""

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{settings.advisor_llm_url}/api/chat",
                json={
                    "model": settings.advisor_llm_model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": f"Sender data: {prompt_ctx}\n\nClassify this sender."},
                    ],
                    "stream": False,
                    "options": {"temperature": 0},
                },
            )
            resp.raise_for_status()
            content = _strip_thinking(resp.json()["message"]["content"])
            start = content.find("{")
            end = content.rfind("}") + 1
            parsed = json.loads(content[start:end])
            classification = parsed.get("classification", rb_class)
            if classification not in ("known_esp", "unknown", "suspicious"):
                classification = rb_class
            return {
                "classification": classification,
                "recommendation": str(parsed.get("recommendation", rb_rec)),
                "dns_fix": str(parsed.get("dns_fix", rb_fix)),
                "is_ai": True,
            }
    except Exception as e:
        log.warning("Sender recommendation LLM failed (%s), using rule-based fallback", e)
        return {"classification": rb_class, "recommendation": rb_rec, "dns_fix": rb_fix, "is_ai": False}


# ── TLS failure recommendations ──────────────────────────────────────────────
# Extends the DMARC sender-recommendation pipeline above to TLS failures —
# GUIDED_ONBOARDING_PLAN.md Part 2, item 3. Deliberately rule-based only
# (no AI elaboration call): TLS failure reasons are a fixed, well-understood
# RFC 8460 enum, unlike DMARC sending sources which need judgment about
# whether an unfamiliar org is legitimate. Reuses SenderRecommendation's
# existing storage/dismiss machinery untouched — no migration, no new table.

_TLS_FIX_ACTIONS: dict[str, str] = {
    "starttls-not-supported":    "Check from outside that your mail server offers STARTTLS. If only one sender sees this failure, compare with other senders before changing anything: the cause may be on the path to your server.",
    "certificate-host-mismatch": "Reissue the MX host's certificate with the correct hostname in its Subject/SAN fields.",
    "certificate-expired":       "Renew the MX host's TLS certificate immediately — this is actively blocking secure delivery.",
    "certificate-not-trusted":   "Replace the certificate with one signed by a publicly trusted CA (e.g. Let's Encrypt, DigiCert).",
    "validation-failure":       "Check the MX host's certificate chain and TLS configuration for misconfigurations.",
    "tlsa-invalid":              "Update the TLSA (DANE) record to match the certificate currently presented, or remove it if DANE isn't intentionally configured.",
    "dnssec-invalid":            "Fix DNSSEC signing for this domain — a broken DNSSEC chain invalidates any TLSA/DANE record relying on it.",
    "sts-policy-fetch-error":    "Confirm https://mta-sts.<domain>/.well-known/mta-sts.txt is reachable and returns the policy file over valid HTTPS.",
    "sts-policy-invalid":        "Check the MTA-STS policy file for syntax errors against RFC 8461.",
    "sts-webpki-invalid":        "Ensure the MX host's certificate is valid for WebPKI — self-signed or internal-CA certs fail MTA-STS validation.",
    "no-policy-found":          "Publish an MTA-STS policy for this domain if you intend to enforce TLS for inbound mail.",
}

# PAIN_POINT_RESOLUTION_PLAN.md Pain 5 — the MX Readiness Scorecard's "Fix
# this" button must NOT assume every TLS failure is a DNS-publishing
# problem. An expired/mismatched/untrusted certificate is almost always a
# mail-server or hosting-provider issue (Exchange, Postfix, cPanel mail
# config) — the registrar hand-holding pattern doesn't apply to it at all.
# Only the genuinely DNS-related codes route to that flow.
_TLS_FIX_CATEGORY: dict[str, str] = {
    "starttls-not-supported":    "server",
    "certificate-host-mismatch": "server",
    "certificate-expired":       "server",
    "certificate-not-trusted":   "server",
    "validation-failure":        "server",
    "tlsa-invalid":               "dns",
    "dnssec-invalid":             "dns",
    "sts-policy-fetch-error":     "dns",
    "sts-policy-invalid":         "dns",
    "sts-webpki-invalid":         "server",
    "no-policy-found":            "dns",
}


def generate_tls_recommendation(mx_host: str, result_type: str, failed_count: int) -> dict:
    """
    Rule-based explanation + fix for a TLS failure reason on a specific MX
    host. Mirrors generate_sender_recommendation()'s output shape so it
    slots into the same SenderRecommendation table and existing
    dismiss/display UI with classification="tls_issue".
    """
    from app.services.tls_service import explain_tls_failure

    explanation = explain_tls_failure(result_type)
    action = _TLS_FIX_ACTIONS.get(result_type, "Review RFC 8460 for this failure type and check the receiving MX host's TLS configuration.")
    recommendation = f"{mx_host}: {explanation} ({failed_count} failed session{'s' if failed_count != 1 else ''})."
    return {"classification": "tls_issue", "recommendation": recommendation, "dns_fix": action, "is_ai": False}


async def generate_cert_summary(certs: list[dict], domain_name: str | None = None) -> dict:
    """
    Generate a single-paragraph cert posture assessment.
    certs: list of { host, domain, status, days_remaining, host_type, tls_version, starttls_supported, hostname_valid }
    Returns { message, commend, is_ai }.
    """
    if not certs:
        return {
            "message": "No certificates have been probed yet. Click 'Probe all' to scan SMTP and HTTPS endpoints.",
            "commend": False,
            "is_ai": False,
            "model": "",
        }

    scope = domain_name or "your portfolio"
    total = len(certs)
    critical = [c for c in certs if c.get("status") in ("critical", "expired")]
    expiring  = [c for c in certs if c.get("status") == "expiring_soon"]
    healthy   = [c for c in certs if c.get("status") == "ok"]
    errors    = [c for c in certs if c.get("status") == "error"]
    min_days  = min((c["days_remaining"] for c in certs if c.get("days_remaining") is not None), default=None)
    tls_old   = [c for c in certs if c.get("tls_version") and c["tls_version"] in ("TLSv1", "TLSv1.1")]
    no_starttls = [c for c in certs if c.get("host_type") == "smtp" and c.get("starttls_supported") is False]
    hostname_mismatch = [c for c in certs if c.get("hostname_valid") is False]

    # Rule-based fallback
    if critical:
        worst = sorted(critical, key=lambda c: c.get("days_remaining") or -1)[0]
        worst_days = "expired" if worst["status"] == "expired" else f"{worst['days_remaining']}d remaining"
        rb_msg = (
            f"{len(critical)} certificate{'s' if len(critical) > 1 else ''} on {scope} "
            f"{'are' if len(critical) > 1 else 'is'} critical or expired — "
            f"starting with <b>{worst['host']}</b> ({worst_days}). "
            f"Renew {'these' if len(critical) > 1 else 'it'} immediately to avoid TLS delivery failures."
        )
        rb_commend = False
    elif expiring:
        soonest = sorted(expiring, key=lambda c: c.get("days_remaining") or 999)[0]
        issues = []
        if tls_old: issues.append(f"{len(tls_old)} host(s) using deprecated TLS (v1.0/1.1)")
        if no_starttls: issues.append(f"{len(no_starttls)} SMTP host(s) without STARTTLS")
        extra = ". Also: " + "; ".join(issues) + "." if issues else "."
        rb_msg = (
            f"{len(expiring)} certificate{'s' if len(expiring) > 1 else ''} on {scope} "
            f"expire{'s' if len(expiring) == 1 else ''} within 30 days — "
            f"<b>{soonest['host']}</b> in {soonest['days_remaining']} days{extra} "
            f"Schedule renewals before expiry to avoid MTA-STS delivery failures."
        )
        rb_commend = False
    elif tls_old or no_starttls or hostname_mismatch:
        issues = []
        if tls_old: issues.append(f"{len(tls_old)} host(s) running deprecated TLS 1.0/1.1")
        if no_starttls: issues.append(f"{len(no_starttls)} SMTP host(s) without STARTTLS")
        if hostname_mismatch: issues.append(f"{len(hostname_mismatch)} hostname mismatch(es)")
        rb_msg = (
            f"All {total} certificates on {scope} are valid (earliest expiry: {min_days}d). "
            f"However: {'; '.join(issues)}. "
            f"Upgrade TLS versions and enable STARTTLS to harden inbound mail security."
        )
        rb_commend = False
    elif healthy == certs:
        rb_msg = (
            f"All {total} certificate{'s' if total != 1 else ''} on {scope} are healthy — "
            f"earliest expiry in {min_days} day{'s' if min_days != 1 else ''}. "
            f"No action required; continue monitoring for renewals."
        )
        rb_commend = True
    else:
        rb_msg = (
            f"{len(healthy)} of {total} certificates on {scope} are healthy. "
            f"{len(errors)} probe error(s) — re-probe those hosts to get current status."
        )
        rb_commend = False

    if not settings.advisor_enabled:
        return {"message": rb_msg, "commend": rb_commend, "is_ai": False, "model": ""}

    # Build cert summary for the LLM
    cert_lines = []
    for c in sorted(certs, key=lambda x: (x.get("days_remaining") is None, x.get("days_remaining") or 0)):
        host = c.get("host", "?")
        status = c.get("status", "?")
        days = c.get("days_remaining")
        tls = c.get("tls_version", "?")
        starttls = c.get("starttls_supported")
        hn_valid = c.get("hostname_valid")
        line = f"  - {host}: status={status}, days_remaining={days}, tls={tls}"
        if starttls is not None:
            line += f", starttls={'yes' if starttls else 'NO'}"
        if hn_valid is False:
            line += ", hostname=MISMATCH"
        cert_lines.append(line)

    prompt_ctx = (
        f"Scope: {scope}\n"
        f"Total certificates: {total}\n"
        f"Summary: {len(critical)} critical/expired, {len(expiring)} expiring soon, {len(healthy)} healthy, {len(errors)} errors\n"
        f"Certificates (sorted by urgency):\n" + "\n".join(cert_lines[:20])
    )

    system = """You are ZoneProof Advisor acting as a TLS certificate health specialist for email infrastructure. You know that in MTA-STS enforce mode, an expired or hostname-mismatched certificate on an MX host will silently reject inbound mail.
Output ONLY valid JSON: {"message": "...", "commend": false}

Rules:
- message: 2-3 sentences. Plain English. No bullet points. Use <b>host</b> tags to highlight specific hostnames.
- commend: true only if all certs are healthy with >30 days remaining and no TLS or STARTTLS issues.
- Lead with the most urgent issue. Be specific: name the host, quote the days remaining.
- If deprecated TLS (v1.0/1.1): flag as compliance and interoperability risk — modern SMTP peers may refuse connections.
- If STARTTLS missing: mail arrives in plaintext regardless of MTA-STS policy.
- If hostname mismatch: MTA-STS strict validation will fail and break delivery.
- Do not invent facts. Use only the data provided."""

    try:
        if settings.advisor_provider == "claude" and settings.anthropic_api_key:
            client = _anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
            response = await client.messages.create(
                model=settings.advisor_claude_model,
                max_tokens=400,
                system=system,
                messages=[{"role": "user", "content": f"Certificate data:\n{prompt_ctx}\n\nWrite the advisory JSON."}],
            )
            content = response.content[0].text.strip()
            model_name = settings.advisor_claude_model
        else:
            async with httpx.AsyncClient(timeout=18) as client:
                resp = await client.post(
                    f"{settings.advisor_llm_url}/api/chat",
                    json={
                        "model": settings.advisor_llm_model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": f"Certificate data:\n{prompt_ctx}\n\nWrite the advisory JSON."},
                        ],
                        "stream": False,
                        "options": {"temperature": 0},
                    },
                )
                resp.raise_for_status()
                content = _strip_thinking(resp.json()["message"]["content"])
                model_name = settings.advisor_llm_model
        start = content.find("{")
        end = content.rfind("}") + 1
        parsed = json.loads(content[start:end])
        return {
            "message": str(parsed.get("message", rb_msg)),
            "commend": bool(parsed.get("commend", rb_commend)),
            "is_ai": True,
            "model": model_name,
        }
    except Exception as e:
        log.warning("Cert summary LLM failed (%s), using rule-based fallback", e)
        return {"message": rb_msg, "commend": rb_commend, "is_ai": False, "model": ""}


async def chat_with_context(
    user_message: str,
    history: list[dict],   # [{ role: "user"|"assistant", content: str }, ...]
    context: dict,         # live security data from DB
) -> dict:
    """
    Conversational chat grounded on the tenant's live security data AND the
    structured knowledge layer (app/knowledge/) — protocol facts selected
    deterministically by select_facts(), not retrieved by the model from
    its own training data. history is capped to last 6 turns.

    citations in the return value are the fact ids actually injected into
    this prompt — ground truth because we chose them, not something parsed
    back out of the model's free-text reply (which would be a guess).
    """
    from app.knowledge import select_facts, format_facts_block
    from app.knowledge.transcripts import TRANSCRIPTS

    screen = context.get("screen", "overview")
    selected_facts = select_facts(screen, user_message)
    facts_block = format_facts_block(selected_facts)
    citations = [f.id for f in selected_facts]
    workspace = context.get("workspace_name", "your organisation")
    total_domains = context.get("total_domains", 0)
    score = context.get("score")
    grade = context.get("grade")
    dmarc_reject = context.get("dmarc_reject_count", 0)
    dmarc_none = context.get("dmarc_none_count", 0)
    dmarc_monitor = context.get("dmarc_monitor_count", 0)
    dmarc_quarantine = context.get("dmarc_quarantine_count", 0)
    avg_comp = context.get("avg_dmarc_comp")
    tls_enforce = context.get("tls_enforce_count", 0)
    tls_testing = context.get("tls_testing_count", 0)
    cert_alerts = context.get("cert_alerts", 0)
    fail_sources = context.get("fail_sources", [])
    domain_name = context.get("domain_name")
    dmarc_stage = context.get("dmarc_stage")
    tls_stage = context.get("tls_stage")
    dmarc_comp = context.get("dmarc_comp")

    # Build a concise security data block for the system prompt
    if domain_name:
        data_block = (
            f"Domain: {domain_name}\n"
            f"DMARC stage: {dmarc_stage or 'none'}\n"
            f"DMARC compliance: {f'{dmarc_comp:.1f}%' if dmarc_comp is not None else 'no data'}\n"
            f"MTA-STS stage: {tls_stage or 'none'}\n"
            f"Failing sources: {', '.join(fail_sources) if fail_sources else 'none'}\n"
            f"Certificate alerts: {cert_alerts}\n"
        )
    else:
        data_block = (
            f"Workspace: {workspace}\n"
            f"ZoneProof Score: {score}/100 (Grade {grade})\n"
            f"Total domains: {total_domains}\n"
            f"DMARC — reject: {dmarc_reject}, quarantine: {dmarc_quarantine}, "
            f"monitor: {dmarc_monitor}, none: {dmarc_none}\n"
            f"Avg DMARC compliance: {f'{avg_comp:.1f}%' if avg_comp is not None else 'no data'}\n"
            f"MTA-STS — enforce: {tls_enforce}, testing: {tls_testing}\n"
            f"Certificate alerts: {cert_alerts}\n"
            f"Failing sources: {', '.join(fail_sources) if fail_sources else 'none'}\n"
        )

    knowledge_section = (
        f"\nGROUNDED PROTOCOL KNOWLEDGE (cite by id in parentheses when you use one, e.g. \"(dmarc.tree_walk)\"):\n{facts_block}\n"
        if facts_block else ""
    )

    system = f"""You are ZoneProof AI, an email security assistant embedded in the ZoneProof platform.
You have access to live security data for this workspace. Use it to give specific, grounded answers.

LIVE SECURITY DATA (current, from the platform):
{data_block}
Current screen: {screen}
{knowledge_section}
Rules:
- Answer in plain English. Max 3 sentences unless a list is genuinely clearer.
- Only use facts from the security data above or the grounded protocol knowledge above.
- Never invent numbers, domains, configurations, or protocol claims not present above.
- When you state a protocol fact from the grounded knowledge, cite its id in parentheses.
- If asked something you cannot answer from the data or knowledge given, say so briefly and redirect.
- Do not use markdown headers. Prose or short bullet lists only.
- Be direct. You are talking to an IT administrator."""

    # Rule-based fallback (no Ollama)
    def _rule_fallback() -> str:
        msg_lower = user_message.lower()
        if "compliance" in msg_lower or "passing" in msg_lower:
            if avg_comp is not None:
                return f"Average DMARC compliance across your portfolio is {avg_comp:.1f}%. {'This is strong.' if avg_comp >= 90 else 'Focus on aligning the failing sources listed in your DMARC analytics.'}"
            return "No DMARC compliance data is available yet — reports haven't been received."
        if "next" in msg_lower or "do" in msg_lower or "recommend" in msg_lower:
            if dmarc_none > 0:
                return f"{dmarc_none} domain{'s have' if dmarc_none > 1 else ' has'} no DMARC record. Publishing a p=none monitoring record is your highest-impact next step."
            if dmarc_monitor > 0 or dmarc_quarantine > 0:
                return f"You have {dmarc_monitor + dmarc_quarantine} domain(s) not yet at full enforcement. Advance them to p=reject once compliance is stable above 95%."
            if cert_alerts > 0:
                return f"All domains are at p=reject — focus on renewing the {cert_alerts} certificate{'s' if cert_alerts > 1 else ''} flagged in the Certificates view."
            return "Your portfolio looks healthy. Keep monitoring for new sending sources and certificate renewals."
        if "spf" in msg_lower:
            return "SPF authorises which servers can send email as your domain. Failing SPF means the sending IP isn't in your SPF record — add the relevant 'include:' or IP range."
        if "dkim" in msg_lower:
            return "DKIM signs outbound messages with a private key. Failing DKIM usually means the service hasn't been configured to sign with your domain's selector, or the DNS key is missing."
        if "mta-sts" in msg_lower or "tls" in msg_lower:
            return f"MTA-STS enforces TLS on inbound mail. You have {tls_enforce} domain(s) enforcing and {tls_testing} in testing mode. Move testing domains to enforce once you've confirmed no delivery failures."
        if "score" in msg_lower:
            if score is not None:
                return f"Your ZoneProof Score is {score}/100 (Grade {grade}). It's a weighted combination of DMARC enforcement, MTA-STS posture, and certificate health across all domains."
            return "Your ZoneProof Score is calculated from DMARC enforcement, MTA-STS posture, and certificate health."
        return "I can help with DMARC, SPF, DKIM, MTA-STS, certificates, and your overall email security posture. What would you like to know?"

    if not settings.advisor_enabled:
        return {"reply": _rule_fallback(), "model": "", "citations": []}

    # Cap history to last 6 turns to keep the context window manageable
    recent_history = history[-6:] if len(history) > 6 else history
    # Few-shot transcripts go first — they're prior-turn examples that bias
    # tone/reasoning style, not instructions. Real conversation history
    # follows so the model still treats this conversation as primary.
    chat_messages = [dict(t) for t in TRANSCRIPTS]
    for turn in recent_history:
        if turn.get("role") in ("user", "assistant") and turn.get("content"):
            chat_messages.append({"role": turn["role"], "content": turn["content"]})
    chat_messages.append({"role": "user", "content": user_message})

    try:
        if settings.advisor_provider == "claude" and settings.anthropic_api_key:
            client = _anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
            response = await client.messages.create(
                model=settings.advisor_claude_model,
                max_tokens=600,
                system=system,
                messages=chat_messages,
            )
            return {
                "reply": response.content[0].text.strip(),
                "model": settings.advisor_claude_model,
                "citations": citations,
            }
        else:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.post(
                    f"{settings.advisor_llm_url}/api/chat",
                    json={
                        "model": settings.advisor_llm_model,
                        "messages": [{"role": "system", "content": system}] + chat_messages,
                        "stream": False,
                        "options": {"temperature": 0},
                    },
                )
                resp.raise_for_status()
                return {
                    "reply": resp.json()["message"]["content"].strip(),
                    "model": settings.advisor_llm_model,
                    "citations": citations,
                }
    except Exception as e:
        log.warning("Chat LLM failed (%s), using rule-based fallback", e)
        return {"reply": _rule_fallback(), "model": "", "citations": []}


# In-memory advisor cache: key = "tenant_id:screen:domain_id_or_all"
_advisor_cache: dict[str, dict] = {}


def _cache_key(tenant_id: str, screen: str, domain_id_or_name: str | None) -> str:
    return f"{tenant_id}:{screen}:{domain_id_or_name or '__all__'}"


# ── API-usage guard ───────────────────────────────────────────────────────
# Every "background refresh" call (advisor banner, cert summary, dns
# summary) used to hit Claude/Ollama unconditionally on every page visit,
# even when nothing in the account had changed since the last call. This
# fingerprints the exact data that would go into the prompt and skips the
# LLM call entirely when it's identical to last time — the cached result
# from the last *real* change is still accurate, so there's nothing new to
# narrate. Chat (chat_with_context) is deliberately NOT gated this way —
# it's a live, user-initiated question, not a periodic refresh, so there's
# no "unchanged" case to detect.
_advisor_fingerprints: dict[str, str] = {}


def compute_fingerprint(payload: Any) -> str:
    """Stable hash of whatever data would be fed into the prompt."""
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def is_unchanged(key: str, fingerprint: str) -> bool:
    return _advisor_fingerprints.get(key) == fingerprint


def remember_fingerprint(key: str, fingerprint: str) -> None:
    _advisor_fingerprints[key] = fingerprint


# Short-term chat memory: key = "user_id:screen:domain_id_or_all" -> last
# few turns. Per-user (not per-tenant) since two admins on the same tenant
# asking different questions on the same screen shouldn't see each other's
# conversation. This is what lets AskFollowUp.vue (frontend) remember
# context across a remount/page switch without the frontend having to
# persist anything itself — the server already has it.
_chat_memory: dict[str, list[dict]] = {}
_CHAT_MEMORY_MAX_TURNS = 6


def _chat_memory_key(user_id: str, screen: str, domain_id: str | None) -> str:
    return f"{user_id}:{screen}:{domain_id or '__all__'}"


def get_chat_memory(user_id: str, screen: str, domain_id: str | None) -> list[dict]:
    return list(_chat_memory.get(_chat_memory_key(user_id, screen, domain_id), []))


def save_chat_turn(user_id: str, screen: str, domain_id: str | None, user_message: str, reply: str) -> None:
    key = _chat_memory_key(user_id, screen, domain_id)
    turns = _chat_memory.setdefault(key, [])
    turns.append({"role": "user", "content": user_message})
    turns.append({"role": "assistant", "content": reply})
    del turns[: max(0, len(turns) - _CHAT_MEMORY_MAX_TURNS)]


def _commend_from_ctx(ctx: AdvisorContext) -> bool:
    """Deterministic commend flag — don't trust the LLM for booleans."""
    if ctx.domain_name:
        return (
            ctx.dmarc_stage == "reject"
            and ctx.tls_stage == "enforce"
            and (ctx.dmarc_comp or 0) >= 98
        )
    # Portfolio: all domains at reject
    return ctx.reject_count == ctx.all_domains_count and ctx.all_domains_count > 0


async def _call_claude(ctx: AdvisorContext) -> dict:
    client = _anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    response = await client.messages.create(
        model=settings.advisor_claude_model,
        max_tokens=450,
        system=_get_system_prompt(ctx.screen),
        messages=[{"role": "user", "content": _build_prompt(ctx)}],
    )
    content = response.content[0].text.strip()
    start = content.find("{")
    end = content.rfind("}") + 1
    parsed = json.loads(content[start:end])
    return {
        "message": str(parsed.get("message", "")).strip(),
        "commend": _commend_from_ctx(ctx),
        "citations": list(parsed.get("citations", [])),
        "is_ai": True,
        "model": settings.advisor_claude_model,
    }


async def generate_dns_summary(
    domain_name: str | None,
    total: int,
    alert_count: int,
    warning_count: int,
    added_count: int,
    removed_count: int,
    modified_count: int,
    recent_alerts: list[dict],
) -> dict:
    scope = domain_name or "your portfolio"

    # Rule-based fallback
    if total == 0:
        rb_msg = f"No DNS changes recorded for {scope} yet. Run a sync to capture the current state."
        rb_commend = False
    elif alert_count > 0:
        alert_desc = "; ".join(
            f"{a['type']} on {a['host']}" + (f" — {a['summary']}" if a["summary"] else "")
            for a in recent_alerts[:2]
        )
        rb_msg = (
            f"{alert_count} critical DNS change{'s' if alert_count > 1 else ''} detected on {scope} "
            f"({alert_desc}). Review {'these changes' if alert_count > 1 else 'this change'} immediately — "
            f"unauthorised record modifications can redirect mail or break DMARC enforcement."
        )
        rb_commend = False
    elif warning_count > 0:
        rb_msg = (
            f"{warning_count} DNS warning{'s' if warning_count > 1 else ''} logged for {scope} "
            f"across {total} total change events. "
            f"Review the flagged records to confirm they were intentional."
        )
        rb_commend = False
    elif total > 0:
        rb_msg = (
            f"{total} DNS change{'s' if total > 1 else ''} recorded for {scope} — "
            f"{added_count} added, {modified_count} modified, {removed_count} removed. "
            f"No security alerts detected."
        )
        rb_commend = True
    else:
        rb_msg = f"DNS change log for {scope} is clean — no alerts or warnings."
        rb_commend = True

    if not settings.advisor_enabled:
        return {"message": rb_msg, "commend": rb_commend, "is_ai": False, "model": ""}

    system = """You are ZoneProof Advisor acting as a DNS security auditor. Output ONLY valid JSON:
{"message": "...", "commend": false, "citations": []}

Rules:
- message: 2-3 plain English sentences. Lead with the most urgent finding. Use exact numbers.
- commend: true only if no alerts or warnings exist.
- Critical alerts (DMARC/SPF removal or policy downgrade) indicate a potential security incident — say so and recommend immediate review against change records.
- If clean: confirm and note the value of regular DNS audits for catching accidental misconfigs and tampering early.
- Never invent data. Only use what is provided."""

    prompt = (
        f"DNS timeline scope: {scope}\n"
        f"Total change events: {total}\n"
        f"Critical security alerts: {alert_count}\n"
        f"Warnings: {warning_count}\n"
        f"Records added: {added_count}, modified: {modified_count}, removed: {removed_count}\n"
    )
    if recent_alerts:
        prompt += "Recent critical changes:\n" + "\n".join(
            f"  - {a['type']} on {a['host']}: {a['summary']}" for a in recent_alerts
        )
    prompt += "\n\nProvide advisor output JSON."

    try:
        if settings.advisor_provider == "claude" and settings.anthropic_api_key:
            client = _anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
            response = await client.messages.create(
                model=settings.advisor_claude_model,
                max_tokens=350,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            content = response.content[0].text.strip()
            model_name = settings.advisor_claude_model
        else:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{settings.advisor_llm_url}/api/chat",
                    json={
                        "model": settings.advisor_llm_model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": prompt},
                        ],
                        "stream": False,
                        "options": {"temperature": 0},
                    },
                )
                resp.raise_for_status()
                content = _strip_thinking(resp.json()["message"]["content"])
                model_name = settings.advisor_llm_model
        start = content.find("{")
        end = content.rfind("}") + 1
        parsed = json.loads(content[start:end])
        return {
            "message": str(parsed.get("message", rb_msg)).strip(),
            "commend": bool(parsed.get("commend", rb_commend)),
            "citations": list(parsed.get("citations", [])),
            "is_ai": True,
            "model": model_name,
        }
    except Exception as e:
        log.warning("DNS summary LLM failed (%s), using rule-based fallback", e)
        return {"message": rb_msg, "commend": rb_commend, "is_ai": False, "model": ""}


async def generate_graph_insight(
    node_count: int,
    edge_count: int,
    open_path_count: int,
    targets: list[dict],
    chokepoint: dict | None,
) -> dict:
    """Pathproof's Attack Path Graph "AI Analyst" (Phase 39c) — same
    rule-based-fallback-first, degrade-honestly discipline as
    generate_dns_summary/generate_cert_summary, reusing this file's own
    Claude/Ollama call pattern rather than a new LLM integration. Every
    fact the LLM is allowed to reference is injected into the prompt from
    real graph data (targets/chokepoint, both computed in
    graph_service.py) — the system prompt explicitly forbids inventing a
    policy name, ARN, or remediation step not present in the briefing."""
    # Rule-based fallback
    if open_path_count == 0:
        rb_msg = (
            "No open privilege-escalation paths detected — the attack graph is currently clear."
            if node_count > 0 else
            "No privilege-escalation paths discovered yet. Connect and scan an AWS account to populate this."
        )
        rb_commend = True
    elif chokepoint:
        policy_label = chokepoint.get("policy_name") or chokepoint["policy_arn"].rsplit("/", 1)[-1]
        rb_msg = (
            f"{chokepoint['closes_count']} of {chokepoint['total_open_count']} verified paths route through one "
            f"policy — patch \"{policy_label}\" and re-scan to confirm closure on the rest."
        )
        rb_commend = False
    else:
        rb_msg = (
            f"{open_path_count} open privilege-escalation path{'s' if open_path_count != 1 else ''} detected, "
            f"each on a distinct policy — no single fix closes more than one."
        )
        rb_commend = False

    if not settings.advisor_enabled:
        return {"message": rb_msg, "commend": rb_commend, "is_ai": False, "model": ""}

    system = """You are the Pathproof Attack Path Analyst — a cloud IAM security engineer reviewing a real privilege-escalation graph. Output ONLY valid JSON:
{"message": "...", "citations": []}

Rules:
- message: 2-3 plain English sentences. Lead with the single highest-impact action.
- Never invent a policy name, ARN, CVE, or remediation step that is not present in the briefing below — every fact must be traceable to the data given. If you are not given a chokepoint, do not invent one.
- If a chokepoint policy is present in the briefing, lead with it: name it exactly as given, state exactly how many paths close if it is fixed.
- If no chokepoint exists, say so plainly and recommend fixing the open paths individually.
- If there are zero open paths, say the graph is clear — this is a good outcome, not something to manufacture urgency about."""

    prompt_lines = [
        f"Open privilege-escalation paths: {open_path_count}",
        f"Total graph nodes: {node_count}, edges: {edge_count}",
    ]
    if chokepoint:
        prompt_lines.append(
            f"Chokepoint policy: {chokepoint.get('policy_name') or '(unnamed policy)'} ({chokepoint['policy_arn']}) — "
            f"fixing it closes {chokepoint['closes_count']} of {chokepoint['total_open_count']} open paths."
        )
    else:
        prompt_lines.append("No single policy is shared by more than one open path — no chokepoint exists.")
    if targets:
        target_lines = "; ".join(
            f"{t['node_id']}: {t['open_path_count']} open path(s), worst severity {t['worst_severity'] or 'none (contained)'}"
            for t in targets[:5]
        )
        prompt_lines.append(f"Targets reached: {target_lines}")
    prompt = "\n".join(prompt_lines) + "\n\nProvide the analyst JSON."

    try:
        if settings.advisor_provider == "claude" and settings.anthropic_api_key:
            client = _anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
            response = await client.messages.create(
                model=settings.advisor_claude_model,
                max_tokens=300,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            content = response.content[0].text.strip()
            model_name = settings.advisor_claude_model
        else:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{settings.advisor_llm_url}/api/chat",
                    json={
                        "model": settings.advisor_llm_model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": prompt},
                        ],
                        "stream": False,
                        "options": {"temperature": 0},
                    },
                )
                resp.raise_for_status()
                content = _strip_thinking(resp.json()["message"]["content"])
                model_name = settings.advisor_llm_model
        start = content.find("{")
        end = content.rfind("}") + 1
        parsed = json.loads(content[start:end])
        return {
            "message": str(parsed.get("message", rb_msg)).strip(),
            "commend": rb_commend,
            "citations": list(parsed.get("citations", [])),
            "is_ai": True,
            "model": model_name,
        }
    except Exception as e:
        log.warning("Graph insight LLM failed (%s), using rule-based fallback", e)
        return {"message": rb_msg, "commend": rb_commend, "is_ai": False, "model": ""}


async def generate_kill_chain_narrative(kill_chains: list[dict]) -> dict:
    """The Kill Chain Narrative — synthesizes graph_service.py's own
    _compute_kill_chains() output (real, ordered entry-to-outcome hop
    sequences) into one compelling, true story, same rule-based-fallback-
    first discipline as generate_graph_insight above. One deliberate fix
    over that function's own known gap: citations here are built
    DETERMINISTICALLY from the real hop data the caller already computed,
    never parsed out of the LLM's own free-text output — every citation is
    independently verifiable against the input, not just plausible-looking
    text the model produced."""
    if not kill_chains:
        rb_msg = (
            "No real, connected kill chain currently exists from the internet to a crown-jewel "
            "target — the proven entry point and the escalation/data-access paths haven't landed "
            "on the same principal yet."
        )
    else:
        chain_phrases = [
            f"in {len(chain['hops'])} real hop{'s' if len(chain['hops']) != 1 else ''}, reach {chain['outcome']}"
            for chain in kill_chains
        ]
        rb_msg = "An attacker starting from the internet can " + "; and separately, ".join(chain_phrases) + "."

    # Deterministic, real, independently-verifiable — never dependent on
    # anything the LLM generates.
    citations = [
        f"{hop['edge_type']}: {hop['source_label']} → {hop['target_label']} ({hop['severity']})"
        for chain in kill_chains
        for hop in chain["hops"]
    ]

    if not settings.advisor_enabled or not kill_chains:
        return {"message": rb_msg, "citations": citations, "is_ai": False, "model": ""}

    system = """You are the Pathproof Attack Path Analyst — a cloud security engineer narrating a real, proven multi-hop attack chain for a non-technical executive audience. Output ONLY valid JSON:
{"message": "..."}

Rules:
- message: 2-4 plain English sentences telling the full story as one narrative — start from the internet-facing entry point, walk through each real hop, and end with the concrete outcome (what an attacker actually gains).
- Never invent a resource name, port, role, policy, or outcome not present in the briefing below — every fact must be traceable to the data given.
- Be concrete and compelling, but never overstate: this is a proven, real chain from real scan data, not a hypothetical — say so with confidence, but never claim anything beyond what the hops actually show.
- If multiple chains are given, narrate the shared entry point once, then branch into each real outcome."""

    prompt_lines: list[str] = []
    for chain in kill_chains:
        prompt_lines.append(
            f"Chain to {chain['target_label']} (outcome: {chain['outcome']}, severity: {chain['chain_severity']}):"
        )
        for i, hop in enumerate(chain["hops"], 1):
            prompt_lines.append(
                f"  Hop {i} ({hop['edge_type']}, severity {hop['severity']}): {hop['source_label']} -> {hop['target_label']}"
            )
    prompt = "\n".join(prompt_lines) + "\n\nNarrate this as one compelling, true story."

    try:
        if settings.advisor_provider == "claude" and settings.anthropic_api_key:
            client = _anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
            response = await client.messages.create(
                model=settings.advisor_claude_model,
                max_tokens=400,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            content = response.content[0].text.strip()
            model_name = settings.advisor_claude_model
        else:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{settings.advisor_llm_url}/api/chat",
                    json={
                        "model": settings.advisor_llm_model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": prompt},
                        ],
                        "stream": False,
                        "options": {"temperature": 0},
                    },
                )
                resp.raise_for_status()
                content = _strip_thinking(resp.json()["message"]["content"])
                model_name = settings.advisor_llm_model
        start = content.find("{")
        end = content.rfind("}") + 1
        parsed = json.loads(content[start:end])
        return {
            "message": str(parsed.get("message", rb_msg)).strip(),
            "citations": citations,
            "is_ai": True,
            "model": model_name,
        }
    except Exception as e:
        log.warning("Kill chain narrative LLM failed (%s), using rule-based fallback", e)
        return {"message": rb_msg, "citations": citations, "is_ai": False, "model": ""}


async def generate_fix_verification_summary(verifications: list[dict]) -> dict:
    """Simulate-the-Fix's "verified closed" narrative — deliberately the
    mirror image of generate_graph_insight's role split: the WHETHER a path
    is closed is pure mechanical re-scan data (CloudPrivEscPath.status/
    closed_at, computed in graph_service._compute_fix_verifications, never
    touched by this function), and this function only ever narrates that
    already-settled fact — it cannot make a path "more closed" or invent
    one. Same rule-based-fallback-first discipline as every other advisor
    function; the fallback alone is already a complete, correct, citable
    sentence, the LLM call only makes it read richer."""
    if not verifications:
        # Nothing to narrate — skip the LLM call entirely rather than risk
        # it inventing something to say about zero real data.
        return {"message": "No fixes have been verified closed by a re-scan yet.", "is_ai": False, "model": ""}

    total_closed = sum(v["closed_count"] for v in verifications)
    fully = [v for v in verifications if v["fully_closed"]]
    partial = [v for v in verifications if not v["fully_closed"]]
    top = verifications[0]
    top_label = top["policy_name"] or (top["policy_arn"].rsplit("/", 1)[-1] if top["policy_arn"] else "a path with no shared policy")
    rb_msg = (
        f"{total_closed} path{'s' if total_closed != 1 else ''} verified closed by re-scan across "
        f"{len(verifications)} group{'s' if len(verifications) != 1 else ''}, largest being \"{top_label}\" "
        f"({top['closed_count']} closed). "
    )
    if partial:
        if len(partial) == 1:
            rb_msg += "That group still has an open path remaining under the same policy — not fully remediated yet."
        else:
            rb_msg += f"{len(partial)} of those groups still have an open path remaining under the same policy — not fully remediated yet."
    else:
        rb_msg += "Every group is fully closed — no open path remains under any of these policies."

    return await _fix_verification_llm(rb_msg, verifications)


async def _fix_verification_llm(rb_msg: str, verifications: list[dict]) -> dict:
    if not settings.advisor_enabled:
        return {"message": rb_msg, "is_ai": False, "model": ""}

    system = """You are the Pathproof Fix Verification Analyst — a cloud IAM security engineer confirming which privilege-escalation paths a re-scan has verified closed. Output ONLY valid JSON:
{"message": "...", "citations": []}

Rules:
- message: 2-3 plain English sentences, confirming what has been verified fixed and by what mechanism (a re-scan found the path no longer present).
- Never invent a policy name, ARN, date, or count that is not present in the briefing below — every fact must be traceable to the data given.
- If a group is only partially closed (still_open_count > 0), say so explicitly — never imply a policy is fully fixed when it is not.
- Do not use hedging language ("might be", "could indicate") about whether a path is closed — status is a settled, re-scan-verified fact, state it plainly."""

    prompt_lines = [f"{v['closed_count']} closed, {v['still_open_count']} still open under policy \"{v['policy_name'] or v['policy_arn'] or '(no shared policy)'}\", fully_closed={v['fully_closed']}, latest verified at {v['latest_closed_at']}" for v in verifications[:8]]
    prompt = "\n".join(prompt_lines) + "\n\nProvide the analyst JSON."

    try:
        if settings.advisor_provider == "claude" and settings.anthropic_api_key:
            client = _anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
            response = await client.messages.create(
                model=settings.advisor_claude_model,
                max_tokens=300,
                system=system,
                messages=[{"role": "user", "content": prompt}],
            )
            content = response.content[0].text.strip()
            model_name = settings.advisor_claude_model
        else:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{settings.advisor_llm_url}/api/chat",
                    json={
                        "model": settings.advisor_llm_model,
                        "messages": [
                            {"role": "system", "content": system},
                            {"role": "user", "content": prompt},
                        ],
                        "stream": False,
                        "options": {"temperature": 0},
                    },
                )
                resp.raise_for_status()
                content = _strip_thinking(resp.json()["message"]["content"])
                model_name = settings.advisor_llm_model
        start = content.find("{")
        end = content.rfind("}") + 1
        parsed = json.loads(content[start:end])
        return {
            "message": str(parsed.get("message", rb_msg)).strip(),
            "citations": list(parsed.get("citations", [])),
            "is_ai": True,
            "model": model_name,
        }
    except Exception as e:
        log.warning("Fix verification LLM failed (%s), using rule-based fallback", e)
        return {"message": rb_msg, "is_ai": False, "model": ""}


async def get_advisor_message(
    ctx: AdvisorContext,
    tenant_id: str = "",
    cached_only: bool = False,
    force: bool = False,
) -> dict:
    """
    force=True bypasses the unchanged-data guard below — used only by the
    explicit Regenerate button, which should always produce a fresh take
    even if nothing changed, distinct from the passive background refresh
    that fires after every cached page load and should NOT spend an API
    call when there's nothing new to say.
    """
    key = _cache_key(tenant_id, ctx.screen, ctx.domain_name)

    if cached_only:
        cached = _advisor_cache.get(key)
        if cached:
            return cached
        return {**_rule_based(ctx), "is_ai": False}

    if not settings.advisor_enabled:
        result = {**_rule_based(ctx), "is_ai": False}
        if tenant_id:
            _advisor_cache[key] = result
        return result

    # Skip the LLM call entirely if nothing about this domain/portfolio has
    # changed since the last time we actually generated a message — the
    # cached result is still an accurate narration of the current state.
    # force=True (explicit Regenerate click) always bypasses this.
    fingerprint = compute_fingerprint(asdict(ctx))
    if tenant_id and not force and is_unchanged(key, fingerprint):
        cached = _advisor_cache.get(key)
        if cached:
            return cached

    try:
        if settings.advisor_provider == "claude" and settings.anthropic_api_key:
            result = await _call_claude(ctx)
        else:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    f"{settings.advisor_llm_url}/api/chat",
                    json={
                        "model": settings.advisor_llm_model,
                        "messages": [
                            {"role": "system", "content": _get_system_prompt(ctx.screen)},
                            {"role": "user", "content": _build_prompt(ctx)},
                        ],
                        "stream": False,
                        "options": {"temperature": 0},
                    },
                )
                resp.raise_for_status()
                content = _strip_thinking(resp.json()["message"]["content"])
                start = content.find("{")
                end = content.rfind("}") + 1
                parsed = json.loads(content[start:end])
                result = {
                    "message": str(parsed.get("message", "")).strip(),
                    "commend": _commend_from_ctx(ctx),
                    "citations": list(parsed.get("citations", [])),
                    "is_ai": True,
                    "model": settings.advisor_llm_model,
                }
        if tenant_id:
            _advisor_cache[key] = result
            remember_fingerprint(key, fingerprint)
        return result
    except Exception as e:
        log.warning("Advisor LLM failed (%s), using rule-based fallback", e)
        result = {**_rule_based(ctx), "is_ai": False}
        if tenant_id:
            _advisor_cache[key] = result
        return result
