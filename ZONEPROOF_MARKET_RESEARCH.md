# ZoneProof: how others solve payer / operator / owner, and what we should take

Date: 2026-10-11. Companion to `ZONEPROOF_ROLE_MATRIX.md` and `ZONEPROOF_REDESIGN_PLAN.md`.

## How to trust this

- **Sources.** Public web pages only: vendor marketing, help centres and forums. I did not use trial accounts, so I have **not seen any competitor's actual screens**. Where a claim comes from a vendor's own marketing or from a competitor's comparison page, it is marked *(vendor)*.
- **No SMB data.** I found no survey of what South African SMBs buy or why. The demand evidence below is directional.
- **Gaps are stated as gaps.** "I found no evidence of X" is not "X does not exist".

## 1. What the email-authentication competitors do

| Question | What I found | Source quality |
|---|---|---|
| Do clients of an MSP get a login? | **Split.** dmarcian's MSP programme does not allow clients to have accounts; reports are emailed instead. Sendmarc offers a co-branded customer portal and lets the partner manage clients or give them access, with customizable permissions. EasyDMARC lists multi-tenant with per-client permissions and white-label reports. | dmarcian: help page. Sendmarc, EasyDMARC: *(vendor)* |
| What is the MSP's first screen? | A multi-client table. PowerDMARC has a Domain Overview and a Customer Overview for MSSP owners and admins. dmarcian's Domain Overview has a seven-day summary, a status table and **Tasks and Issues** tabs that suggest work items. | Help pages |
| How do they reduce the work per fix? | **Delegation.** Sendmarc publishes DMARC as a CNAME to a record it hosts, and uses an SPF redirect, so policy changes need no DNS edit. Valimail markets automated SPF. | Help page, *(vendor)* |
| How do they find MSPs and owners? | Sendmarc's partner portal has a scoring widget, a browser extension, an impersonation demo tool and lead tools. PSA integrations (ConnectWise, Acronis, HaloPSA, Autotask) can open tickets automatically. | *(vendor)* |
| How is triage presented? | Red Sift's Brand Trust has AI triage of look-alikes with a similarity score. Unknown senders are classed Asset, Threat or Forwarder, with reasoning the user can confirm or change. | Release notes |
| What drives demand? | Fraud and impersonation, deliverability (Google and Yahoo sender rules), and insurers. Insurance applications commonly ask about SPF, DKIM and DMARC, and some treat enforcement as a condition; they want dated evidence such as report data, record snapshots and change logs. In South Africa, one study found 64% of large companies with no DMARC; 18 of 35 insurers had a policy. Managed service is how SMEs buy. | *(vendor)* throughout |

**What I did not find in any of them:** an approval inbox for the business owner, or a monthly "what we did for you" view for the person who pays. That may be a real gap, or it may be that I could not see behind the logins. Worth checking in a trial.

## 2. Models from other SaaS that map to our problem

| Product | The model | What it teaches us |
|---|---|---|
| **Shopify** (collaborator access) | The partner requests access and picks the sections it needs. The owner approves. The owner can change or revoke permissions later. Requests expire after seven days. An optional request code. | **The owner holds the account; the partner asks.** Scoped, revocable, expiring. |
| **Xero** (advisor) | An advisor is a user with a role inside the owner's organisation. The subscription belongs to whoever pays, and can be **transferred** at the end of the engagement; partners are expected to cooperate on exit. There is no firm-level invite, so firms invite each staff member. | Billing and data follow the owner. **Firm-level access is a real pain** when staff change. |
| **Microsoft GDAP** | The customer must grant a partner least-privilege roles. Access is time-bound (reported as 1 to 730 days). Either side can end it. Pending and expiring relationships are reported. | **Time-bound, least-privilege, mutual termination.** |
| **Google Search Console** | Verified owner, delegated owner, full user, restricted user. A property needs at least one verified owner. "Associates" can act but cannot see data. | A clear four-step role ladder that maps to our ownership verification. |
| **Vanta Trust Center** | A public or access-controlled page. An admin chooses to show only passing controls, or all. | The **verifier page** exists and works as a sales asset. Control over what is shown matters. |
| **SecurityScorecard** | Any company can see its own rating free, with advice. A buyer invites a vendor. The vendor can comment that it is remediating. | **Free claim and invite** is an acquisition loop. |
| **Coalition Control** | Free to policyholders. Critical alerts at the top. Alerts go to the policyholder and designated IT contacts. A high, medium or low risk level. | **An insurer is a distribution channel**, and the owner view can be free. |
| **Microsoft Secure Score** | A percentage and points. A ranked list of actions, each with how much it would improve the score. Planned and achievable views, history and benchmark. | Show **what each fix is worth**. Our design already does ("would bring it to about 90"). |
| **Huntress, NinjaOne** | The MSP sees every alert; the customer sees only its own environment. Huntress partners ask for client access to the portal and for per-client permissions. | The **demand for an owner view exists** among MSPs. |

## 3. What the pattern says

Across these products the same structure repeats:

1. **The owner holds the account and the relationship.** Partners are delegated, never the other way round.
2. **The partner's access is scoped, expiring and revocable**, and the owner can see and end it.
3. **The partner works in a multi-client workspace** with a queue, not a set of topic pages.
4. **The owner sees outcomes and approvals**, not mechanisms.
5. **A third party sees an attestation**, and the owner decides what it shows.

That is the role-lens model in the matrix. It is the common pattern across products that have a payer, a worker and a beneficiary.

## 4. Where we are already strong (use it harder)

| Capability we have | Where it is today | How to use it fully |
|---|---|---|
| **Managed MTA-STS hosting** (one CNAME) | A step inside Encryption | The model competitors sell for DMARC. Make it the default owner path: "we host it, one record, then nothing to maintain". |
| **Impact simulation, readiness gates, enforcement check** | Work › Roadmap, technician only | Make the result the standard content of every approval the owner sees: "14 clean days, no sender affected". This is what turns "approve" into a one-minute decision. |
| **Evidence pack (hash, JSON / PDF), DNS change log with before and after, audit log** | Three separate places | Together they are what insurers ask for: dated evidence of configuration and enforcement changes. Offer them as one **attestation pack** from the shareable proof page. |
| **Coverage statement and source health** (Brand) | Hidden behind a health dot | The honest source for a proof-of-value line: what we checked, what we found. Better than invented totals. |
| **Passive, consent-free posture check** (`prospect_assessment_service`) | Backend and API only, authenticated, 3 per minute, no ZoneProof screen | It already produces an honest partial score. It is the engine for a free domain check, for the MSP's prospect scan and for a shareable result. |
| **AI advisor and concept glossary** | Assistant panel | The plain-language layer for the owner lens. |
| **Service API** (`/service/v1` overview, alerts, audit log) | For other products | A base for PSA tickets, insurer feeds and a score widget. |
| **Slack, Teams, webhook and SIEM channels** (Brand notifications) | Brand only | Extend to DMARC and certificate alerts, then add ticket creation. |

## 5. Forgotten or missing, and how strongly I would flag each

Rated **Must** (the redesign does not work without it), **Should** (competitors have it, or it unlocks a role), **Later**.

| # | Capability | Rating | Evidence | Note |
|---|---|---|---|---|
| F1 | **Approval requests**: an object the owner can approve, decline or question, with an expiry and a notification | **Must** | Shopify, GDAP; nothing in our backend | "Needs your yes" is the owner's first screen and has no data model today. |
| F2 | **Partner access with scope and expiry**, owner-approved, revocable, listed | **Must** | Shopify, GDAP, Xero, Search Console | Matrix H9. Includes who owns the account and the bill, and transfer on exit (Xero). |
| F3 | **Proof of value from real records**: who fixed what, what was stopped | **Must** | The renewal test; our own gap C4 | The audit log and change log may already hold most of it. Needs checking before any figure is shown. |
| F4 | **Shareable attestation page** with owner-chosen content, built on the evidence pack | **Should**, cheap | Vanta, Coalition, insurer questionnaires | Matrix H8. No competitor surface found in the DMARC space. |
| F5 | **Free public domain check** | **Should** | Sendmarc widget, SecurityScorecard | Engine exists. Needs an unauthenticated, rate-limited, passive-only endpoint. **Decision:** scanning arbitrary domains with no login has abuse and consent questions. |
| F6 | **Hosted DMARC and SPF (delegation)** | **Should**, decision | Sendmarc, Valimail | Makes an approval one click with no DNS edit. Cost: we sit in the customer's DNS path and take on its reliability. We already do this for MTA-STS. |
| F7 | **PSA ticket creation** (ConnectWise, Autotask, HaloPSA) | **Should** (MSP) | Sendmarc, EasyDMARC *(vendor)* | Start with a generic webhook that opens a ticket. |
| F8 | **SSO** (Microsoft, Google) for MSP staff | **Should** | Sendmarc *(vendor)* | We have two-factor only. |
| F9 | **Per-client technician assignment**, firm-level team | **Should** | Huntress requests, Xero pain | The MSP "roles" row exists; per-client scope needs checking. |
| F10 | **Insurer or broker channel** | **Later**, strategic | Coalition | Distribution, not a feature. Worth one conversation before building anything. |

## 6. What I would not copy

- **dmarcian's "no client logins."** It protects the MSP's relationship, but it removes the owner as a user. Our alternative protects the MSP differently: the MSP decides whether and what the owner sees, and keeps white-label control.
- **Vendor-claimed outcomes** ("enforcement in 45 days", "73% fewer claims"). None are independently verified. We should measure our own.

## Sources

- Sendmarc: [partner platform summary](https://sendmarc.com/products/dmarc-platform-for-partners), [partner portal guides](https://help.sendmarc.com/partner-portal-guides), [DNS delegation](https://help.sendmarc.com/dns-record-delegation), [ConnectWise listing](https://marketplace.connectwise.com/sendmarc)
- EasyDMARC: [DMARC for MSPs](https://easydmarc.com/dmarc-for-msps)
- PowerDMARC: [MSSP Domain Overview](https://support.powerdmarc.com/support/solutions/articles/60001600582-centralized-dashboard-for-mssps-new-domain-overview-page)
- dmarcian: [Domain Overview](https://dmarcian.com/domain-overview/), [reports for clients](https://dmarcian.com/create-dmarcian-reports/), [cyber insurance](https://dmarcian.com/cyber-insurance/)
- Red Sift: [Fall 2024 release](https://redsift.com/blog/red-sifts-fall-2024-quarterly-product-release)
- Vanta: [Trust Center](https://help.vanta.com/en/articles/11345469-vanta-trust-center)
- Shopify: [collaborator accounts](https://www.shopify.com/partners/blog/shopify-collaborator-account)
- Xero: [Partner code of conduct (South Africa)](https://www.xero.com/za/legal/terms/partner-code-of-conduct), [advisor invite guide](https://brandfolder.xero.com/8HSCTPAX/as/g4n4vw59hhshwjhvw6nsfr4m/Invite_your_Advisor_into_your_Xero_Organisation), [firm-level access request](https://productideas.xero.com/forums/940636-for-accountants-bookkeepers/suggestions/48216971-user-access-option-to-provide-practice-access-wh)
- Microsoft: [GDAP](https://learn.microsoft.com/partner-center/customers/gdap-introduction), [Secure Score](https://learn.microsoft.com/defender-xdr/microsoft-secure-score)
- Google: [Search Console users and owners](https://support.google.com/webmasters/answer/7687615)
- Coalition: [Control overview](https://help.coalitioninc.com/hc/en-us/articles/7687332367259-Coalition-Control-Overview)
- SecurityScorecard: [free account](https://support.securityscorecard.com/hc/en-us/articles/360059534171-How-do-I-create-a-free-SecurityScorecard-account)
- Huntress: [co-management request](https://feedback.huntress.com/account-organization-user-management/p/co-management-for-msp), [client access request](https://feedback.huntress.com/feature-requests/p/client-access-to-their-account-on-msp-portal)
- South Africa: [PowerDMARC](https://powerdmarc.com/dmarc-south-africa/), [EasyDMARC on financial institutions](https://easydmarc.com/blog/dmarc-and-south-african-financial-institutions-2/), [ITWeb](https://itweb.co.za/article/lack-of-dmarc-protocol-weakens-already-fragile-e-mail-security/4r1ly7R9DDRvpmda)
- Insurance: [Palisade](https://www.palisade.email/learning/how-does-dmarc-affect-cyber-insurance)

## Decisions (2026-10-11)

- **F1 to F6: yes.** F1 approval requests, F2 partner access with scope and expiry, F3 proof of value from real records, F4 shareable attestation page, F5 free public domain check, F6 hosted DMARC and SPF delegation.
- **F7 to F9: revisit later** (PSA tickets, SSO for MSP staff, per-client technician scope).
- **Guardrails recorded with the yes:**
  - F5 is passive lookups only, rate-limited, and never does what the product gates behind ownership verification.
  - F6 puts us in the customer's DNS path. It needs a rollback story and an uptime commitment before it is offered, and starts with the managed MTA-STS pattern we already run.
- **Account, expiry and scopes (matrix questions 6 to 8)** are resolved in `ZONEPROOF_ROLE_MATRIX.md`.
