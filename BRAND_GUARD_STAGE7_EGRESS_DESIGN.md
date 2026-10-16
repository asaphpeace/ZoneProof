# Stage 7.1 decision brief: how ZoneProof touches a suspect host

Status: DECISION NEEDED. Nothing in Stage 7 is built or wired until this is approved. Written 2026-10-06.

## Why this is a gate
Until now Brand Guard has been passive: DNS, certificate transparency, public blocklists, registration data. Stage 7 means our servers connect to a host an attacker controls (probes in 7.2, a real browser in 7.3). That changes the risk, so it needs a deliberate design rather than a code change.

## What goes wrong if we just do it from the app server
1. **Our own server is exposed.** A page we load can try to reach internal addresses (SSRF), serve malware to the browser, or attack the renderer. The app server holds the database and customer data.
2. **Hosting terms.** The ARCHITECTURE.md notes AWS, GCP and Azure prohibit scanning-style traffic in their acceptable-use policies and flag it automatically. Probing hundreds of hostile hosts from the product's own host risks the product's account.
3. **We tip the attacker off.** The probe comes from an address that is ours. Phishing kits commonly hide from known security scanners (cloaking), so the page we see may be a decoy, or the attacker learns they were found.
4. **Third-party data.** A screenshot of a live phishing page can contain other victims' data or a brand's imagery, and is stored on our side.

## What already exists and is reused
`app/services/safe_fetch.py` already does SSRF-safe fetching for the customer's own homepage: public addresses only, the connection pinned to the validated IP (no DNS rebinding), at most 3 manually-validated redirects, certificate verification against the real name, size and time caps. Stage 7 probes reuse it unchanged as the guard layer; the isolation below is a second layer, not a replacement.

## Options

### A. A dedicated egress worker (recommended)
A small separate machine (or two) on a provider whose terms allow security research, in its own network range, with:
- **No database, no secrets, no customer data.** It pulls jobs ("probe this host, with this job id") over HTTPS from the API, signed with a key that can do nothing else, and posts back only the result (headers, redirect chain, certificate, hashes).
- **Outbound only to the public internet**, with private, link-local and metadata ranges blocked at the firewall as well as in code.
- **Renderer (7.3) in a throwaway container per job**: no persistent profile, downloads off, no credentials, time and memory limits, destroyed after every job. Nothing on a page is ever submitted: no forms are filled, no passwords typed.
- **Rate limits and a per-host politeness delay**, so we never look like an attack.
- Cost: a small VPS (order of single-digit to low double-digit US dollars a month) plus the time to run it. Scales by adding workers.
Trade-offs: one more thing to operate and monitor; the worker's address is still identifiable to a determined attacker (see "Cloaking" below).

### B. Third-party scanning service (e.g. a hosted URL-scan API)
No infrastructure for us, and their address ranges are already used to scanning. But: customer look-alike lists go to a third party (privacy, terms, and POPIA need review), results are theirs to interpret, there is a per-scan cost, and their scans are public by default on some services.

### C. Do it from the app host with only the code guards
Cheapest, and not recommended: it fails points 1 and 2 above.

### D. Stay passive (do not build Stage 7)
Brand Guard already scores without it. Stage 7 adds page-level evidence (a cloned login form is the strongest single sign of phishing) and screenshots for takedowns; it is not required for the product to work.

## Decisions that apply whichever option is chosen
- **Identify ourselves or not.** Honest user agent (`ZoneProof-Probe/1`, with a contact page) is more transparent and easier for a host to allow; a generic browser agent sees fewer decoys but is less honest. Recommendation: identify, and accept some cloaking. Cloaked results are labelled "page may differ for real visitors", never treated as clean.
- **No interaction.** Read-only: GET and HEAD, load the page, take the screenshot. Never submit a form, never enter any credential, never click a download, never execute anything outside the browser.
- **Retention.** Screenshots and page text kept 30 days unless attached to a case, then deleted. Never shown to another tenant. Stored encrypted.
- **Scope.** Probe only look-alikes a person has not dismissed and that are live (resolving), at most once a day per host, with a per-tenant daily cap.
- **A kill switch.** One setting turns all probing off immediately.
- **Malware.** A page may try to deliver a file. Downloads are blocked and the worker only records that a download was attempted.

## What can be built now without any egress (and what waits)
- **Now (no network):** the analysis logic that reads probe results: redirect-chain scoring, favicon-hash matching against the customer's own favicon (hashing already exists), certificate-versus-CT comparison, the form and page-text classifiers, evidence lines and drawer sections, all tested on recorded fixtures.
- **Waits for approval:** the worker, the job queue, the signed job protocol, the renderer container, and anything that makes a real request to a suspect host.

## Recommended path
Approve **A**, with the decisions above as written. Build order after approval: (1) worker protocol and kill switch, (2) 7.2 light probes with fixtures, (3) 7.3 renderer in a container, (4) 7.4 similarity as a feature, never a verdict. Each step stays behind the kill switch until you switch it on.
