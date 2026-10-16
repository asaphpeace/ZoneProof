# Stage 4.4 decision brief: cross-tenant intelligence and the shared graph core

Status: NOTHING cross-tenant is built. This is the decision gate. Written 2026-10-02.

## What exists (4.1 to 4.3)
- `brand_graph_nodes` / `brand_graph_edges`: generic, kind-typed, **scoped to one tenant's brand profile**. Edges are only what an observation proves (shared certificate, address, nameservers, mail host, registration batch). Registrars never link.
- Link weight falls with how many look-alikes share the thing (`base / (1 + ln(degree-1))`); a thing shared by more than 25 is ignored as a hub.
- Guilt flows from known-bad look-alikes (confirmed by a person, or listed by URLhaus/PhishHunt) to linked ones, decaying 0.6 per hop, 3 hops max, 45-day half-life, worth up to 30 abuse points as one labelled signal. The path is shown, never hidden.
- Campaigns UI draws the graph and marks known-bad and linked members.

## Decision 1: should indicators from one tenant inform another tenant's view?
What it would add: a "seen targeting other brands" badge, and guilt that crosses brands (an operator who hit Brand A is likelier hitting Brand B).

Risks to weigh:
- **POPIA / privacy.** Look-alike domains and infrastructure are not personal data in themselves, but WHOIS-derived registrant data, and the fact a tenant is being impersonated, can be. Tenant identity must never leak.
- **Poisoning.** One tenant confirming a false positive would taint others. Needs reviewed-only seeds and a minimum number of independent tenants.
- **Commercial.** Tenants may not want even anonymous signals derived from their reviews.

Recommended shape if approved: indicator-only (domain, address, nameserver, certificate hash), no tenant id or brand name, only from human-confirmed or feed-listed seeds, shown only as "also seen targeting N other brands" (N >= 2 tenants), opt-out per tenant, written into the terms of service.

Steps before building: (1) POPIA review by someone qualified (not an engineering call), (2) terms-of-service wording, (3) your go/no-go. Until then tables stay per-tenant.

## Decision 2: share a graph core with PathProof?
The existing Attack Path Graph (`routers/graph.py`, `graph_service.py`, `CloudAsset`, `CloudPrivEscPath`) is domain-specific and assembled on read, with no generic persisted store. Brand Guard therefore got its own generic tables; conventions were reused (provable edges, honest labels, ATT&CK tags, BFS kill-chain shape), code was not. Converging both onto one core is a larger refactor of a product on the same backend and database: recommend deferring until PathProof's own roadmap needs persisted edges.

## Assumptions that are expert-set, not measured
class_prior 20 points; guilt 30 points; link base weights (certificate 0.9, address 0.7, nameserver 0.5, mail host 0.5, batch 0.3); decay 0.6; half-life 45 days; taxonomy word lists and ATT&CK tag mapping. All are labelled as assumptions in the product and should be revisited once real outcome labels exist (Stage 1/3.2).
