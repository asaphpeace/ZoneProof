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
| Module catalogue: unbought modules shown locked with "Add module" | Planned | |
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

### 1.6 Alerts and notifications
| Feature | Status | Notes |
|---|---|---|
| Alerts and alert menu | Built | |
| Channels: email, Slack, Teams, webhook | Built | |
| SIEM export | Built | |
| One alert feed across modules | Planned | |

### 1.7 Cases and investigations
| Feature | Status | Notes |
|---|---|---|
| Investigations | Built | `investigation` model |
| Brand Guard cases with owner and SLA | Built | |
| Evidence packs with hash | Built | |
| One case per incident, visible from every module | Planned | Brief principle "one incident, many views" |
| Case stages: Discover → Understand → Verify → Decide → Protect → Prove | Planned | From the prototype |
| Evidence states: observed, inferred, declared, verified, conflicted, unassessed, stale | Planned | Decisions locked while evidence is unassessed |

### 1.8 Approvals and governance
| Feature | Status | Notes |
|---|---|---|
| Audit log | Built | Both apps |
| Approval roles for phishing campaigns | Built | |
| Rules-of-engagement e-signature (Dropbox Sign) | Built | |
| Second-person approval for money, DNS and access changes | Planned | Pre-flight checks, rollback, SLA, delegate |
| Automation levels with hard limits (suggest → draft → act once approved → act with receipt) | Planned | From the prototype |
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
| Email telemetry framework | Partial | Backend only |
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
| BIMI as the final roadmap step | Built |

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
| Page rendering and visual similarity | Planned |
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
| MFA and password audit | Built |
| Google Workspace | Planned |
| Breach-credential monitoring | Partial |

### 3.4 Human risk
| Feature | Status |
|---|---|
| Phishing simulation: Spoof Proof and human simulation | Built |
| Template library, landing pages, QR lures | Built |
| Training courses and completion tracking | Built |
| Reported-mail triage | Built |
| Campaign approvals, scheduled reports, dashboards | Built |

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
| Look-alike domains, Brand Guard hits, a supplier's DMARC posture | ZoneProof |
| OAuth grants between organisations, phishing results | PathProof |

---

## 5. Overlaps to settle before building (one owner each)

| Capability | Exists in | Proposal |
|---|---|---|
| Cases | Brand Guard cases, investigations, PactProof case rail | One case system in the core (1.7) |
| Reported suspicious mail | PathProof triage; prototype "Messages" | Core alert feed, triaged in PathProof |
| Executive impersonation | Prototype "Executive trust" | PathProof human risk |
| Public verification | Brand Guard; PactProof Verify | PactProof owns the public page |
| MSP portfolio | Both apps | Core org switcher (1.2) |
| Scores | ZoneProof Score; composite | ZoneProof Score per module; composite on Home |

---

## 6. Counts

| Area | Built | Partial | Planned |
|---|---|---|---|
| Platform core | 36 | 8 | 23 |
| ZoneProof | 16 | 7 | 3 |
| PathProof | 19 | 1 | 2 |
| PactProof | 0 | 0 | 19 |
| **Total** | **71** | **16** | **47** |
