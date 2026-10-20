# Foundation Security Labs platform — complete feature list

One console, three modules, one shared core:

- **ZoneProof — outside.** Your domains, email and brand as the world sees them.
- **PathProof — inside.** How an attacker could actually reach what matters.
- **PactProof — between.** You and the suppliers, partners and customers you trust.

Status, from the code and from `ECOSYSTEM_PROJECT_BRIEF.md` / `ZONEPROOF_FEATURE_MAP.md` as of 19 Oct 2026:

| Tag | Meaning |
|---|---|
| **Built** | Works in code today |
| **Partial** | Built in part, built but not released, or built in one app only |
| **Planned** | Designed (brief, prototype or plan) but not built |

---

## 1. Platform core (shared by every module)

### 1.1 Sign-in and access
| Feature | Status | Notes |
|---|---|---|
| One login for all modules | Planned | Today: two sessions (`sentinel_token`, `command_token`) joined by a handoff code |
| Email and password sign-in, reset, email verification | Built | |
| Two-factor sign-in (TOTP) | Built | |
| Session revocation on password/2FA change | Built | `token_version` |
| Team members: invite, role, revoke | Partial | API built; UI only in part |
| Role matrix (owner, admin, analyst, approver, bookkeeper, IT) | Partial | `ZONEPROOF_ROLE_MATRIX.md`; one role model across modules planned |
| SAML single sign-on, just-in-time provisioning | Planned | Schema groundwork done |

### 1.2 Tenants and MSP
| Feature | Status | Notes |
|---|---|---|
| Multi-tenant isolation | Built | |
| MSP portfolio across client tenants | Partial | Built separately in each app; one org switcher planned |
| Bulk client onboarding | Built | |
| White-label reports | Built | |
| Delegated work within an authorised client only | Planned | PactProof journey J8 |

### 1.3 Modules, plans and billing
| Feature | Status | Notes |
|---|---|---|
| Stripe checkout, webhooks, portal | Built | Live status, VAT, refunds unknown |
| Plan limits | Partial | ZoneProof only; PathProof has none |
| Per-module entitlements (switch modules on per tenant) | Planned | `require_module(...)` guard |
| Module catalogue: unbought modules shown locked with "Add module" | Planned | In Settings and billing only |
| Unbought modules shown inside the work, not as greyed menus ("this case would be richer with PactProof") | Planned | Approved 19 Oct 2026 |
| Bundles (e.g. Protect / Verify / Complete) and MSP à la carte | Planned | |

### 1.4 Home
| Feature | Status | Notes |
|---|---|---|
| ZoneProof Score and grade | Built | |
| Composite score across modules | Partial | PathProof overview shows it |
| One home: outside · inside · between, one card per module | Planned | |

### 1.5 Inventory (one list of everything that represents the organisation)
| Feature | Status | Notes |
|---|---|---|
| Domains and subdomains | Built | ZoneProof |
| Cloud accounts and resources | Built | PathProof |
| Hosts and containers | Built | PathProof |
| OAuth / SaaS applications | Built | PathProof |
| Official identities: social profiles, WhatsApp/phone, apps | Planned | PactProof registry |
| Suppliers and partners | Planned | PactProof |
| One combined inventory view | Planned | |
| One page per person, domain and supplier, combining signals from every module | Planned | Approved 19 Oct 2026; the combined inventory opens into these |

### 1.6 Alerts and notifications
| Feature | Status | Notes |
|---|---|---|
| Alerts and alert menu | Built | |
| Channels: email, Slack, Teams, webhook | Built | |
| SIEM export | Built | |
| One alert feed across modules | Planned | |
| Weekly "what we handled" summary | Planned | Approved 19 Oct 2026; email first, WhatsApp possible |

### 1.7 Cases and investigations
| Feature | Status | Notes |
|---|---|---|
| Investigations | Built | `investigation` model |
| Brand Guard cases with owner and SLA | Built | |
| Evidence packs with hash | Built | |
| One case per incident, visible from every module | Planned | Brief principle "one incident, many views" |
| Case stages: Discover → Understand → Verify → Decide → Protect → Prove | Planned | From the prototype |
| Evidence states: observed, inferred, declared, verified, conflicted, unassessed, stale | Planned | Decisions locked while evidence is unassessed |
| Related signals join one open case, and the case says so ("we linked this to last week's look-alike") | Planned | Approved 19 Oct 2026 |

### 1.8 Approvals and governance
| Feature | Status | Notes |
|---|---|---|
| Audit log | Built | Both apps |
| Approval roles for phishing campaigns | Built | |
| Rules-of-engagement e-signature (Dropbox Sign) | Built | |
| Second-person approval for money, DNS and access changes | Planned | Pre-flight checks, rollback, SLA, delegate |
| Automation levels with hard limits (suggest → draft → act once approved → act with receipt) | Planned | From the prototype |
| Response mode per tenant: ask me first, act after hours only, act always | Planned | Approved 19 Oct 2026; sits on top of the automation levels |
| Data export and erasure log | Built | |

### 1.9 Reports
| Feature | Status | Notes |
|---|---|---|
| PDF reports: board-ready, white-label, scheduled | Built | ZoneProof |
| PathProof report PDF | Built | |
| Cross-module report builder | Planned | |
| Report lifecycle: draft → review → issued → superseded → revoked | Planned | PactProof journey J6 |

### 1.10 AI assistant
| Feature | Status | Notes |
|---|---|---|
| Advisor that explains deterministic decisions | Built | The LLM explains; it never decides |
| One assistant across modules, citing records | Planned | |

### 1.11 Integrations and data sources
| Feature | Status | Notes |
|---|---|---|
| DMARC/TLS report ingestion (IMAP) | Built | |
| Certificate Transparency, new-registration feed | Built | |
| AWS (Prowler, Cloudsplaining, Inspector) | Built | Inspector read permission unconfirmed on a real account |
| SSH host scanning (Lynis) | Built | |
| Microsoft 365 | Partial | OAuth risk built; scan has no button on its own page |
| Email telemetry framework | Partial | Backend only. Read-only through APIs, never in the mail path (decided 20 Oct 2026) |
| Source health page | Built | |
| Google Workspace | Planned | |
| Breach credentials (HIBP) | Partial | Waits on API key |
| Accounting / ERP for payment checks | Planned | PactProof |

### 1.12 Onboarding, help and growth
| Feature | Status | Notes |
|---|---|---|
| First-run onboarding wizards | Built | Both apps |
| In-app docs, glossary, concept cards | Built | |
| Public no-login domain scanner | Built | |
| Prospect assessment | Built | PathProof |
| Help centre and per-DNS-host guides | Planned | |
| First-run report: top 4 risks within 24 hours, tied to POPIA | Planned | Approved 19 Oct 2026; doubles as onboarding and sales |

### 1.13 Platform operations
| Feature | Status | Notes |
|---|---|---|
| Background job history, leader lock | Built | |
| Secrets from a managed store, production start-up guard | Built | |
| Backups and disaster recovery job | Planned | Policy written, no job |

---

## 2. ZoneProof — outside

### 2.1 Email authentication
| Feature | Status |
|---|---|
| DMARC aggregate ingestion and analyser (source → IP → result) | Built |
| Senders and platform health (declared vs detected) | Built |
| SPF composition builder (lookup count, flatten warning) | Built |
| DKIM failure diagnosis | Built |
| Enforcement roadmap per domain, readiness gates, impact simulation | Built |
| BIMI as the final roadmap step | Partial (guidance only; no record builder or check) |

### 2.2 Mail transport
| Feature | Status |
|---|---|
| MTA-STS, including managed policy hosting | Built |
| TLS-RPT failure analysis and trend | Built |
| MX readiness scorecard | Built |

### 2.3 Certificates and DNS
| Feature | Status |
|---|---|
| Certificate inventory, expiry alerts, re-probe | Built |
| DNS change timeline with plain-language summaries | Built |
| "Is it live yet?" check after a DNS change | Built |
| Subdomain discovery with accept / ignore | Built |
| Passive DNS | Planned (terms check done) |

### 2.4 Brand Guard
| Feature | Status |
|---|---|
| Look-alike discovery: permutations, new registrations, Certificate Transparency | Partial (built, not released) |
| Per-candidate scoring with a plain-language "why" | Partial (built, not released) |
| Campaign clustering | Partial (built, not released) |
| Cases with owner, SLA, evidence pack | Partial (built, not released) |
| Takedown drafts routed to the right contact (a person sends) | Partial (built, not released) |
| Blocklist exports (M365, DNS RPZ, Chrome), defensive-registration advice | Partial (built, not released) |
| MSP roll-up, brand exposure in the score | Partial (built, not released) |
| Page rendering and visual similarity | Partial (side-by-side screenshots work when the render worker is on) |
| Learning loop, accuracy calibration, cross-customer intelligence | Planned (founder decision gate) |

### 2.5 Score and guidance
| Feature | Status |
|---|---|
| ZoneProof Score and pillars | Built |
| Deterministic recommendation engine | Built |
| Ownership proof via reporting address | Built |

---

## 3. PathProof — inside

### 3.1 Attack paths
| Feature | Status |
|---|---|
| Simulation Engine: attack-path graph, entry → foothold → crown jewel | Built |
| Kill-chain narrative and fix priority | Built |
| Simulate the fix (live, on the graph) | Built |
| Detection-coverage overlay | Built |
| Coverage map of 11 capabilities | Built |

### 3.2 Cloud and hosts
| Feature | Status |
|---|---|
| Cloud misconfiguration (Prowler) | Built |
| IAM privilege-escalation paths (Cloudsplaining) | Built |
| Resource inventory and graph edges (runs-as, internet exposure with open ports, lateral movement, data access) | Built |
| Exploitability scoring | Built |
| Amazon Inspector and Lynis-over-SSH host scanning, Docker inventory | Built |
| Infrastructure-as-code scanning | Planned |

### 3.3 Identity and SaaS
| Feature | Status |
|---|---|
| Microsoft 365 OAuth app risk | Built |
| Google Workspace | Planned |

### 3.4 People (human risk)
| Feature | Status |
|---|---|
| Person and team risk view: clicks, reports, training, MFA, breached passwords | Planned |
| Phishing simulation: Spoof Proof and human simulation | Built |
| Template library, landing pages, QR lures | Built |
| Training courses and completion tracking | Built |
| Just-in-time training: a 2-minute lesson on the exact lure clicked or received | Planned |
| Reported-mail triage | Built |
| Campaign approvals, scheduled reports, dashboards | Built |
| MFA and password audit (moved from 3.3) | Built |
| Breach-credential monitoring (moved from 3.3) | Partial |
| High-risk roles: accounts payable, payroll, executive support get tougher tests, targeted training, extra weight in checks | Planned |
| Executive impersonation: VIP list (executives, finance leads, anyone who can move money) | Planned |
| Executive impersonation: email using a VIP's name from an outside address | Planned (needs the Microsoft 365 email feed) |
| Executive impersonation: fake social profiles and WhatsApp numbers using a VIP's name | Planned (Brand Guard engine and PactProof registry) |
| Executive impersonation: "our CEO will never ask you to…" policy staff can check | Planned |
| Payroll diversion check: salary bank-change requests verified by call back and second approver | Planned (reuses the Trust Check flow, 4.4) |

### 3.5 Engagements
| Feature | Status |
|---|---|
| Rules of engagement, e-signed before any scan | Built |
| What changed (timeline of findings) | Built |

---

## 4. PactProof — between (all Planned; prototype and brief exist)

### 4.1 Identity registry
| Feature | Status |
|---|---|
| Declare official domains, social profiles, phone/WhatsApp, apps | Planned |
| Verify a specific claim with method, date and expiry | Planned |
| Choose which verified claims are public | Planned |

### 4.2 Relationships
| Feature | Status |
|---|---|
| Supplier and partner records with criticality and owner | Planned |
| Approved channels and authorised contacts per relationship | Planned |
| Two-way email assurance (A → B and B → A), built on ZoneProof data | Planned |
| Watch suppliers' domains for look-alikes (Brand Guard engine) | Planned |

### 4.3 Trust Handshake
| Feature | Status |
|---|---|
| Invite a partner; tracked states (sent, opened, accepted, bounced, expired) | Planned |
| Free partner portal: the partner confirms its own identities and channels | Planned |
| Scoped sharing: no private data crosses tenants | Planned |

### 4.4 Trust Check
| Feature | Status |
|---|---|
| Check a sensitive request (bank details, contact change) against the verified record | Planned |
| Call back on the number already on file, with a script and recorded outcome | Planned |
| Decision receipt: claim, approver, evidence, policy, validity | Planned |
| Hold the linked payment until decided | Planned |
| Spot bank-change requests in Microsoft 365 mail and open a check automatically | Planned |
| Notify the real supplier when a fake request uses its name | Planned |

### 4.5 Payment protection
| Feature | Status |
|---|---|
| Payment run checked against verified bank records and per-supplier 7-day totals | Planned |
| Bank-change wizard: request → call back → verify account → approve → watch | Planned |

### 4.6 Trust Passport and public Verify
| Feature | Status |
|---|---|
| Passport: scoped, time-bound claims a business can share | Planned |
| Public Verify page: anyone checks an official channel | Planned |
| Public "report a suspicious channel" creating a candidate finding | Planned |

### 4.7 Recovery
| Feature | Status |
|---|---|
| Identity recovery: suspend claims, recover, re-verify, republish (J7) | Planned |

### 4.8 Signals PactProof uses from the other modules
| Signal | From |
|---|---|
| Look-alike domains (yours and your suppliers'), Brand Guard hits, a supplier's DMARC posture | ZoneProof |
| OAuth grants between organisations, phishing results, high-risk roles, who can approve payments | PathProof |
| Bank-change emails detected in Microsoft 365 mail | Microsoft 365 email feed (core) |

---

## 5. Overlaps to settle before building (one owner each)

| Capability | Exists in | Proposal |
|---|---|---|
| Cases | Brand Guard cases, investigations, PactProof case rail | One case system in the core (1.7) |
| Reported suspicious mail | PathProof triage; prototype "Messages" | Core alert feed, triaged in PathProof |
| Executive impersonation | Prototype "Executive trust" | **Decided 19 Oct 2026:** PathProof People (3.4) |
| Public verification | Brand Guard; PactProof Verify | PactProof owns the public page |
| MSP portfolio | Both apps | Core org switcher (1.2) |
| Scores | ZoneProof Score; composite | ZoneProof Score per module; composite on Home |

---

## 6. Counts

| Area | Built | Partial | Planned |
|---|---|---|---|
| Platform core | 36 | 8 | 29 |
| ZoneProof | 15 | 9 | 2 |
| PathProof | 19 | 1 | 10 |
| PactProof | 0 | 0 | 22 |
| **Total** | **70** | **18** | **63** |

151 features. Was 134 before the 19 Oct 2026 decisions below.

---

## 7. Decisions log

### 19 Oct 2026 — approved by the founder
- **People (3.4):** executive impersonation moves here (settles the overlap in section 5). MFA and password audit and breach credentials move here from 3.3. New: payroll diversion check, high-risk roles, person and team risk view, just-in-time training.
- **Suppliers and payments (4.2, 4.4):** spot bank-change emails in Microsoft 365 mail, notify the real supplier, watch suppliers' domains for look-alikes.
- **How the product is arranged (core):** one page per person, domain and supplier; cases that merge and say so; weekly "what we handled" summary; response mode (ask first, after hours, always); first-run top-4-risks report; unbought modules shown inside the work instead of greyed menus.
- **Status corrections:** BIMI Built → Partial (guidance only). Page rendering and visual similarity Planned → Partial (works when the render worker is on).

### 20 Oct 2026 — approved by the founder
- **Mail access scope: we read mail, we never carry it.** Mail is read after delivery through APIs (Microsoft 365 Graph first, Google Workspace later), headers and body, only for the mailboxes the customer chooses. We never sit in the MX path, hold mail inline, manage queues or detonate links in a sandbox. Settles the open "mail access scope" question.
- **Why:** mail checks are one of our senses, not our product. Each check is a clue for stories (executive impersonation, bank-change requests, supplier look-alikes) and evidence for confidence. Specialists' verdicts (Microsoft Defender, reputation services) are inputs, not competitors. Staying out of the mail path avoids uptime and lost-mail liability.
- **Design consequence:** the prototype's mail-queue screen is vision only, not planned. Link checks stop at reputation lookups. Mail signals sit beside executive impersonation in People (3.4), and one message taken apart is the evidence view a story opens. No feature count changes.

### Open — not yet decided
- **"Money protected" figure on Home** (e.g. "R1.2M in payments verified this quarter"). Founder: "not sure but perhaps". Not in the feature list until decided.
