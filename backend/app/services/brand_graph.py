"""
Brand Guard — the evidence graph, clusters and guilt propagation (plan steps 4.1 and 4.2).

NODES are things look-alikes can share: the look-alike itself, a server address, a nameserver, a mail host, a certificate, a registrar, a
registration batch. EDGES are relationships the stored observations show (an edge is something observed, never assumed). The pure
functions below turn the candidates' stored facts into that graph; `sync` (bottom) persists it.

Two ideas on top of it:

  Links between look-alikes.  Two domains are linked when they share an infrastructure node. How strong the link is depends on HOW
      MANY domains share the node: a certificate on two names is a strong link, a nameserver pair on 600 names is everybody's
      infrastructure. So a link's weight shrinks with the node's degree (1 / (1 + ln(degree - 1))) and a node shared by more than
      HUB_LIMIT domains is not a link at all. No hand-kept list of "big shared hosts" is needed for this; it falls out of the data.
      Registrars are recorded but never link (too many unrelated domains use one registrar).

  Guilt propagation.  Some look-alikes are KNOWN BAD (a person confirmed them, a public feed lists them, a reported email was confirmed
      malicious). Their suspicion flows to linked look-alikes, multiplied by the link weight and a per-hop decay, for at most MAX_HOPS
      hops, and the seed's own strength fades with age (half-life HALF_LIFE_DAYS), so an old listing stops mattering. The result is a
      number in [0, 1] with the PATH that produced it, shown to the analyst; it is one more piece of evidence, never a verdict.

The base weights per node kind, the decay and the half-life are hand-set assumptions (nothing measures them yet); the evidence line says so.
"""
from __future__ import annotations

import math
import uuid
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

# kind of shared node -> (edge kind from the domain, how much suspicion it carries before the degree discount)
LINK_KINDS = {
    "certificate": ("covered_by", 0.9),
    "ip": ("resolves_to", 0.7),
    "nameserver": ("uses_nameserver", 0.5),
    "mail_host": ("mails_via", 0.5),
    "batch": ("in_batch", 0.3),
}
CONTEXT_KINDS = {"registrar": "registered_via"}            # recorded, never a link
HUB_LIMIT = 25                                              # a node shared by more domains than this is infrastructure for everybody
DECAY_PER_HOP = 0.6
MAX_HOPS = 3
HALF_LIFE_DAYS = 45.0
GUILT_POINTS = 30.0                                         # expert-set: abuse points at guilt 1.0 (see the linked_to_known_bad signal)
MAX_PER_KIND = {"ip": 5, "nameserver": 6, "mail_host": 4, "certificate": 5}
HARMLESS_STATUSES = frozenset({"customer_owned", "partner", "false_positive", "benign", "ignored", "removed"})


def _lower(x) -> str:
    return str(x).strip().lower().rstrip(".")


def extract(candidates: list[dict]) -> tuple[dict[tuple[str, str], dict], list[tuple[tuple[str, str], tuple[str, str], str, dict]]]:
    """candidates: [{"domain", "enrichment"}]. Returns ({(kind, key): {"label", "attrs"}}, [(src_node, dst_node, edge_kind, attrs)])."""
    nodes: dict[tuple[str, str], dict] = {}
    edges: list[tuple[tuple[str, str], tuple[str, str], str, dict]] = []
    for c in candidates:
        d, e = c["domain"], c.get("enrichment") or {}
        me = ("domain", d)
        nodes.setdefault(me, {"label": d, "attrs": {}})

        def link(kind: str, key: str, label: str | None = None, **attrs) -> None:
            node = (kind, key)
            nodes.setdefault(node, {"label": label or key, "attrs": {}})
            edge_kind = LINK_KINDS.get(kind, (CONTEXT_KINDS.get(kind),))[0] or CONTEXT_KINDS[kind]
            edges.append((me, node, edge_kind, attrs))

        for ip in sorted({_lower(x) for x in e.get("a") or [] if x})[:MAX_PER_KIND["ip"]]:
            link("ip", ip)
        for ns in sorted({_lower(x) for x in e.get("ns") or [] if x})[:MAX_PER_KIND["nameserver"]]:
            link("nameserver", ns)
        for mx in sorted({_lower(x) for x in e.get("mx") or [] if x})[:MAX_PER_KIND["mail_host"]]:
            link("mail_host", mx)
        for cid in sorted({str(x) for x in e.get("cert_ids") or [] if x})[:MAX_PER_KIND["certificate"]]:
            link("certificate", cid, label=f"certificate {cid[:12]}", issuer=e.get("cert_issuer"))
        registrar = (e.get("registration") or {}).get("registrar")
        if registrar:
            link("registrar", _lower(registrar), label=str(registrar)[:120])
        for hint in e.get("clusters") or []:
            if (hint.get("data") or {}).get("kind") == "registration_batch" or hint.get("kind") == "registration_batch":
                group = sorted([d, *(hint.get("siblings") or [])])
                link("batch", "batch:" + group[0], label=f"registered together with {group[0]}")
    return nodes, edges


def link_weights(edges) -> tuple[dict[tuple[str, str], list[str]], dict[tuple[str, str], float]]:
    """({shared node: [domains]}, {shared node: link weight}) for nodes that can link at all (>= 2 domains, no more than HUB_LIMIT)."""
    members: dict[tuple[str, str], set[str]] = {}
    for src, dst, _, _ in edges:
        if dst[0] in LINK_KINDS:
            members.setdefault(dst, set()).add(src[1])
    usable = {n: sorted(m) for n, m in members.items() if 2 <= len(m) <= HUB_LIMIT}
    weights = {n: LINK_KINDS[n[0]][1] / (1.0 + math.log(len(m) - 1)) if len(m) > 1 else 0.0 for n, m in usable.items()}
    return usable, weights


def subgraph(edges, domains: set[str]) -> dict:
    """The part of the graph that explains a group: its members, the infrastructure that links at least two of them, and which member
    uses which. {"domains": [...], "shared": [{"id","kind","label","members","weight","degree"}], "links": [{"domain","node","kind"}]}."""
    usable, weights = link_weights([e for e in edges if e[0][1] in domains])
    shared, links = [], []
    for (kind, key), members in sorted(usable.items(), key=lambda kv: (-weights[kv[0]], kv[0])):
        inside = [m for m in members if m in domains]
        if len(inside) < 2:
            continue
        nid = f"{kind}:{key}"
        shared.append({"id": nid, "kind": kind, "label": key if kind != "batch" else "registered together", "members": inside, "weight": round(weights[(kind, key)], 2), "degree": len(members)})
        links.extend({"domain": m, "node": nid, "kind": LINK_KINDS[kind][0]} for m in inside)
    return {"domains": sorted(domains), "shared": shared, "links": links}


def seed_strength(*, status: str, reviewed: bool, feeds: list[dict] | None, reported: list[dict] | None) -> float:
    """How sure we are this look-alike IS bad: a person's confirmation is strongest, a public feed listing next, an unconfirmed report least."""
    if reviewed and status in ("confirmed", "takedown", "removed"):
        return 1.0
    if any(r.get("disposition") == "confirmed_malicious" for r in reported or []):
        return 1.0
    if any(f.get("feed") in ("phishunt", "urlhaus") and not f.get("same_site") for f in feeds or []):
        return 0.8
    if reported:
        return 0.4
    return 0.0


def decayed(strength: float, age_days: float) -> float:
    return strength * 0.5 ** (max(age_days, 0.0) / HALF_LIFE_DAYS)


def propagate_guilt(seeds: dict[str, float], edges, eligible: set[str]) -> dict[str, dict]:
    """{domain: {"score", "seed", "hops", "path": [{"from","to","via_kind","via","via_label"}]}} for every eligible, non-seed domain reached.
    `seeds` are already age-decayed. Best path wins (the product of seed strength, link weights and per-hop decay)."""
    usable, weights = link_weights([e for e in edges if e[0][1] in eligible])
    neighbours: dict[str, list[tuple[str, float, tuple[str, str]]]] = {}
    for node, doms in usable.items():
        for a in doms:
            for b in doms:
                if a != b:
                    neighbours.setdefault(a, []).append((b, weights[node], node))
    best: dict[str, dict] = {d: {"score": s, "seed": d, "hops": 0, "path": []} for d, s in seeds.items() if d in eligible and s > 0}
    frontier = set(best)
    for hop in range(1, MAX_HOPS + 1):
        updates: dict[str, dict] = {}
        for u in frontier:
            for v, w, node in neighbours.get(u, []):
                if v in seeds:
                    continue
                score = best[u]["score"] * w * DECAY_PER_HOP
                cur = updates.get(v) or best.get(v)
                if score > (cur["score"] if cur else 0.0) + 1e-9:
                    updates[v] = {"score": score, "seed": best[u]["seed"], "hops": hop,
                                  "path": best[u]["path"] + [{"from": u, "to": v, "via_kind": node[0], "via": node[1], "via_label": node[1] if node[0] != "batch" else "a registration batch"}]}
        best.update(updates)
        frontier = set(updates)
        if not frontier:
            break
    return {d: {**g, "score": round(g["score"], 3)} for d, g in best.items() if g["hops"] > 0 and g["score"] >= 0.01}


def guilt_signal(guilt: dict | None) -> dict | None:
    """The evidence line for a candidate that guilt has reached, or None. An ASSUMPTION-weighted line (see GUILT_POINTS)."""
    if not guilt or not guilt.get("score"):
        return None
    last = guilt["path"][-1] if guilt.get("path") else {}
    how = " then ".join(f"{p['to']} shares {p['via_label']} with {p['from']}" for p in guilt.get("path", [])[:3]) or "linked through shared infrastructure"
    return {"signal": "linked_to_known_bad", "weight": round(GUILT_POINTS * guilt["score"], 1),
            "summary": (f"Linked to {guilt['seed']}, a look-alike known to be bad, {guilt['hops']} step(s) away ({how}). Suspicion fades with distance and with age. "
                        "The strength is an assumption, not a measurement."),
            "data": {"seed": guilt["seed"], "hops": guilt["hops"], "score": guilt["score"], "path": guilt.get("path", []), "basis": "expert", "last_kind": last.get("via_kind")}}


# ── persistence ──────────────────────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


async def sync(db: AsyncSession, profile) -> dict:
    """Rebuild one brand's graph from its candidates and refresh every candidate's `guilt`. Idempotent; never raises into a scan (the
    caller wraps it). Returns counts."""
    from app.models import BrandCandidate, BrandGraphEdge, BrandGraphNode

    rows = (await db.execute(select(BrandCandidate).where(BrandCandidate.profile_id == profile.id))).scalars().all()
    eligible_rows = [r for r in rows if r.status not in HARMLESS_STATUSES]
    eligible = {r.candidate_domain for r in eligible_rows}
    nodes, edges = extract([{"domain": r.candidate_domain, "enrichment": r.enrichment} for r in eligible_rows])

    existing_nodes = {(n.kind, n.key): n for n in (await db.execute(select(BrandGraphNode).where(BrandGraphNode.profile_id == profile.id))).scalars().all()}
    now = _now()
    for key, meta in nodes.items():
        n = existing_nodes.get(key)
        if n is None:
            n = BrandGraphNode(id=uuid.uuid4(), tenant_id=profile.tenant_id, profile_id=profile.id, kind=key[0], key=key[1], label=meta["label"], attrs=meta["attrs"], first_seen_at=now, last_seen_at=now)
            db.add(n)
            existing_nodes[key] = n
        else:
            n.label, n.last_seen_at = meta["label"], now
    await db.flush()

    existing_edges = {(e.src_id, e.dst_id, e.kind): e for e in (await db.execute(select(BrandGraphEdge).where(BrandGraphEdge.profile_id == profile.id))).scalars().all()}
    wanted: set[tuple[uuid.UUID, uuid.UUID, str]] = set()
    for src, dst, kind, attrs in edges:
        k = (existing_nodes[src].id, existing_nodes[dst].id, kind)
        wanted.add(k)
        e = existing_edges.get(k)
        if e is None:
            db.add(BrandGraphEdge(id=uuid.uuid4(), tenant_id=profile.tenant_id, profile_id=profile.id, src_id=k[0], dst_id=k[1], kind=kind, attrs=attrs, first_seen_at=now, last_seen_at=now))
        else:
            e.last_seen_at = now
    stale = [e.id for k, e in existing_edges.items() if k not in wanted]
    if stale:
        await db.execute(delete(BrandGraphEdge).where(BrandGraphEdge.id.in_(stale)))
    await db.flush()
    orphans = [n.id for key, n in existing_nodes.items() if key not in nodes]       # things no candidate shows any more (a look-alike with no links stays)
    if orphans:
        await db.execute(delete(BrandGraphNode).where(BrandGraphNode.id.in_(orphans)))

    seeds: dict[str, float] = {}
    for r in eligible_rows:
        e = r.enrichment or {}
        s = seed_strength(status=r.status, reviewed=r.reviewed_at is not None, feeds=e.get("feeds"), reported=e.get("reported_emails"))
        if s > 0:
            since = r.reviewed_at if (r.reviewed_at and s == 1.0) else r.first_seen_at
            age = (now - since).total_seconds() / 86400 if since else 0.0
            seeds[r.candidate_domain] = decayed(s, age)
    guilt = propagate_guilt(seeds, edges, eligible)
    changed = 0
    for r in rows:
        e = dict(r.enrichment or {})
        g = guilt.get(r.candidate_domain) if r.status not in HARMLESS_STATUSES else None
        if g:
            if e.get("guilt") != g:
                e["guilt"] = g
                r.enrichment = e
                changed += 1
        elif "guilt" in e:
            e.pop("guilt")
            r.enrichment = e
            changed += 1
    await db.flush()
    return {"nodes": len(nodes), "edges": len(wanted), "seeds": len(seeds), "guilty": len(guilt), "changed": changed}
