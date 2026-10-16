# Phishing Platform Gap Analysis — KnowBe4 & Mimecast Benchmark

Status: **analysis only, no code written.** Ground-truthed against the real
repos (both `backend` and `frontend`) on 2026-09-20, not against memory of
earlier sessions — every claim about what exists today is cited to a real
file and line. The KnowBe4 and Mimecast sections use the same nine
categories so they're directly comparable, and the two benchmarks
deliberately don't agree with each other everywhere — where they diverge,
that divergence is itself information about what kind of platform each
competitor actually is, and it's called out rather than flattened into one
generic "gap."

## Where the module already stands on its own

Before the gaps: what's built today is a genuinely good **simulation +
evidence engine**, not a placeholder. DMARC-grounded lure content, a real
two-tier recon/attack split (Tier A never touches a real person, Tier B is
fully ROE-gated), pseudonymization-by-construction with an audited unmask
flow that cross-references cloud privilege-escalation blast radius, a
dwell-time signal, and a Human Risk score feeding the platform's broader
composite score. None of that is what's below — this document is
specifically about the four layers that are thin or missing: **training
content, admin/settings, real-threat operations, and
automation/smart-targeting.**

---

## Combined priority backlog

Priority reflects both benchmarks together, not just whichever competitor
looks worse on a given row.

| Priority | Gap | Why |
|---|---|---|
| **P0** | No Settings surface for the module at all | Blocks almost everything else below from having a home; sending identity is hardcoded read-only, no branding, no whitelisting guidance, no role gating beyond admin-vs-everyone |
| **P0** | No real training/LMS layer | One micro-lesson, 4 of 10 lure categories even have bespoke content; this is the retention lever for *both* competitors, just executed differently by each |
| **P0** | No granular roles/approval workflow | Any authenticated tenant user can launch a real campaign against real employees — a genuine exposure, not just missing polish |
| **P1** | No scheduled/exec reporting | Dashboard exists and is honest, but nothing is emailed, no PDF, no manager rollups — mostly a delivery gap, not a data gap, so likely the fastest P1 to close |
| **P1** | No dynamic/smart targeting | Target lists are 100% static and manually maintained |
| **P1 vs KnowBe4 / structurally different vs Mimecast** | No real-threat report & triage workflow | See the dedicated section below — this is not the same gap against each competitor |
| **P2** | No smishing/vishing/QR/USB | Real gap vs KnowBe4 specifically; not a gap vs Mimecast, which is also email-only |
| **P2** | No SSO/SCIM/HRIS integration | Matters most once selling into orgs with real IT/HR systems of record |

---

## 1. Settings

**Sentinel today:** doesn't exist. Sending identity is a read-only computed
string (`phishing.py:57`), no whitelisting guidance, no landing-page
branding, no blackout/holiday calendar, no default-training-assignment
config.

**KnowBe4:** dedicated admin console — sending domains with DKIM setup,
mail-gateway whitelisting instructions per major gateway (O365/Google/
Proofpoint/Mimecast itself), branded landing pages, default training
assignment rules.

**Mimecast:** same expectation, but as one tab inside the unified Mimecast
console alongside the actual Secure Email Gateway config — whitelisting a
Mimecast-run phishing simulation is arguably *less* of a customer problem
for Mimecast than for either KnowBe4 or Sentinel, since Mimecast already
owns the customer's inbound mail flow and can self-authorize its own
simulated sends without the customer configuring an allowlist at all. That
"we already sit in the mail path so we don't need to ask" advantage is not
something Sentinel can replicate without becoming a mail gateway — worth
naming honestly rather than treating as a closable gap.

**Recommended IA fix (unchanged from the KnowBe4 pass):** a **Settings**
tab in the Phishing nav — Sending & domain, Landing page branding,
Approval & roles, Training defaults, Data & retention, Integrations.

## 2. Training & remediation

**Sentinel today:** one HTML micro-lesson per click/credential event
(`phishing_lesson_content.py`), non-scored single reflection question, 6
of 10 lure categories fall back to generic content. No course concept, no
video, no certificate, no standalone assignment independent of a phishing
failure.

**KnowBe4:** the deepest content library in the category — hundreds of
courses/videos, SCORM/AICC export, quizzes, certificates, compliance
tracks (HIPAA/PCI/GDPR).

**Mimecast:** smaller library than KnowBe4's, but a real, differentiated
one — short-form, professionally produced, comedic/story-driven video
episodes with recurring characters, explicitly designed against "training
fatigue" rather than for library breadth. SCORM export to a customer's own
LMS is supported for orgs that want centralized training records outside
Mimecast. The design philosophy is "fewer, better, more-watched minutes"
rather than "biggest catalog" — a different bar to clear than KnowBe4's.

**Gap:** against KnowBe4 this is a breadth gap; against Mimecast it's a
*production-quality* gap as much as a breadth gap — a handful of genuinely
well-made short modules would close more relative ground against Mimecast
than a large library of mediocre ones would. Scope suggestion stands from
the first pass: 5-10 short assignable modules, independent of a phishing
event, feeding the existing Human Risk score, before worrying about
catalog size.

## 3. Roles & approval

**Sentinel today:** only `halt`, `resume`, and `unmask` check
`role == admin`. Creating an engagement, requesting signature, launching a
real campaign, revoking, and editing schedule are open to any
authenticated tenant user.

**KnowBe4:** account owner / full admin / group-scoped admin /
reports-only roles.

**Mimecast:** same granular-roles expectation, and typically a stricter
default posture than KnowBe4 — Mimecast customers are usually enterprise
IT/security teams already used to tightly scoped admin roles across the
rest of the Mimecast console (mail routing, DLP, archiving), so a
phishing-simulation feature with looser role gating than the rest of their
own console would read as a regression to that buyer specifically.

**Gap:** identical conclusion against both — this belongs in
Settings → Approval & roles, and is closer to a security exposure than a
UX nicety.

## 4. Real-threat report & triage — not the same gap against each competitor

**Sentinel today:** the "Report" link only exists inside simulated
phishing emails and records a `reported` event on that simulated campaign.
No mechanism for an employee to report a real suspicious email, no triage
queue.

**KnowBe4 (PhishER / PhishER Plus):** KnowBe4 is a *training-only* vendor
with no mail gateway of its own — PhishER exists specifically to fill that
gap: a Phish Alert Button employees use on real inbox mail, a triage
queue, threat-intel enrichment, and org-wide auto-removal (PhishRIP). It's
a genuinely separate, purpose-built product bolted onto a platform that
otherwise has zero visibility into real mail flow.

**Mimecast:** doesn't need a PhishER-equivalent in the same form, because
Mimecast *is* the mail gateway — real malicious mail is already scanned,
scored, and frequently quarantined server-side before it reaches an
inbox, and Mimecast's own threat-intelligence/incident console (part of
the core Email Security product, not the awareness-training add-on)
already functions as the triage surface. Mimecast's differentiated
capability here is **"just-in-time" training**: because the same vendor
sees both the simulated campaigns *and* real detected threats, it can
trigger a training assignment automatically the moment a real user clicks
something dangerous — no employee-initiated report step required at all.

**Gap, stated honestly:** against KnowBe4, closing this gap means building
a triage inbox — a real, scoped, buildable feature (forwarding address or
mail-plugin ingestion + a queue UI). Against Mimecast, the equivalent
capability (auto-triggered training off *real* malicious mail) is
**structurally unavailable to Sentinel without becoming a mail gateway**
— Sentinel doesn't sit in the mail path and has no visibility into
messages it didn't send itself. This isn't a backlog item so much as a
platform-category boundary worth being upfront about with prospects who
come from a Mimecast background and will ask about it directly.

## 5. Smart/dynamic targeting

**Sentinel today:** `PhishingTargetList.entries` is a static JSONB array,
explicitly "never auto-populated." Every list is manually typed or pasted.

**KnowBe4:** Smart Groups — auto-updating groups by AD/HRIS attribute or
risk score.

**Mimecast:** directory-sync-driven group membership is standard, backed
by the same enterprise-directory integrations the rest of the Mimecast
console already requires for mail routing/archiving policy — so for a
Mimecast customer, dynamic targeting isn't an extra integration to set up,
it's an extension of directory sync they've already done for other
reasons.

**Gap:** same underlying gap against both, but Mimecast's version is
"free" for their customer because the directory integration already
exists elsewhere in their stack — a reason to prioritize this once
Sentinel has any SSO/SCIM story at all, since the marginal cost of dynamic
targeting drops sharply once directory sync exists for any other reason.

## 6. Reporting & analytics

**Sentinel today:** a real, honest Dashboard (Human Risk score, component
rates, department breakdown) and per-campaign CSV export. Nothing
scheduled, no PDF, no manager rollups, benchmark block deliberately left
empty rather than faked.

**KnowBe4:** 25+ canned reports, scheduled email/PDF delivery, executive
summaries, manager rollups, real industry benchmarking (large enough
customer base to make the comparison honest).

**Mimecast:** reporting lives inside the same unified console as email
security reporting, so a security leader sees phishing-simulation risk
trend lines alongside real-threat volume from the gateway in one place —
the differentiator isn't report *count*, it's that the report already
sits next to the data that gives it context.

**Gap:** against KnowBe4 this is mostly a delivery-mechanism gap (the
aggregation functions already exist). Against Mimecast, matching the
"context in one place" advantage isn't realistic short-term since Sentinel
isn't unifying with a mail gateway's own threat data — but Sentinel
already does something adjacent and real: campaign evidence is tied to
actual DMARC-aggregate and spoof-test data (`phishing_evidence_service.py`)
from elsewhere in the product. That's worth leaning on explicitly in the
UI/report copy rather than trying to imitate Mimecast's version of
"unified context."

## 7. Channel coverage

**Sentinel today:** email only.

**KnowBe4:** SMS (smishing), voice (vishing callback numbers), QR-code
lures, USB-drop kits — the broadest multi-channel offering in the
category.

**Mimecast:** also overwhelmingly email-centric. No comparable
smishing/vishing/USB program that's a first-class part of their offering
to my knowledge — this is a real relative weakness of Mimecast against
KnowBe4, not just against Sentinel.

**Gap:** real vs. KnowBe4, **not a gap vs. Mimecast at all** — this is the
clearest example in this document of why a flat feature checklist across
competitors would mislead. Lowest-priority build given team size; if it
gets picked up, QR-code lures are the cheapest first move since they reuse
the existing email-sending pipeline.

## 8. Integrations

**Sentinel today:** SendGrid (send + bounce webhook) and Dropbox Sign
(ROE) only. Nothing feeds target lists or roles automatically.

**KnowBe4:** SSO/SAML, SCIM, HRIS sync, SIEM export.

**Mimecast:** same integration surface expected, generally assumed
present by default for an enterprise buyer since it's table stakes for
the rest of the Mimecast console they're already running.

**Gap:** identical against both; sequencing note unchanged — this matters
most once selling into orgs with real IT/HR systems of record, consistent
with the MSP-first, SMB-wedge stage the product is at now.

## 9. Template depth

**Sentinel today:** 10 built-ins + tenant custom templates. `difficulty`
and `include_attachments` exist as fields on the custom-template model but
are explicitly non-functional metadata, not wired into anything. No
WYSIWYG editor.

**KnowBe4:** thousands of templates, difficulty rating that actually
affects simulated sophistication, 35+ languages, WYSIWYG builder.

**Mimecast:** a smaller, curated template set relative to KnowBe4 (again
the "fewer, better" philosophy that shows up in their training content
too), with strong localization for the regions they're strongest in
enterprise-wise.

**Gap:** smaller than it looks for both — the `difficulty` field already
exists in the schema and is the cheapest of these to make real, by gating
which templates a campaign can pick based on a target's training history.

---

## Process note carried over from the first pass

Several files reference "PHISHING_DESIGN.md Section 3.2" etc. in code
comments, but no such file exists anywhere in either repo, tracked or
untracked — confirmed via `git ls-files` and a full recursive filename
search. Neither does `ITDR_DESIGN.md` or `OAUTH_APP_RISK_DESIGN.md`,
despite being referenced elsewhere as written deliverables. The existing
`*_PLAN.md` docs all live at the `V1` repo root, which is why this
document was placed there too, matching that convention rather than
inventing a new location.
