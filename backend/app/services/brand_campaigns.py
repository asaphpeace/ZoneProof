"""
Brand Guard — campaigns: look-alikes that appear to share an operator (UI slice 2).

The evidence already exists per candidate: `enrichment["clusters"]` holds the cluster hints from plan step 2.4 (registered in the
same batch, one certificate over several names, the same nameservers, the same server address), each naming its siblings. This
module turns those pairwise links into stored GROUPS so an analyst can act on one operator instead of one domain at a time.

Rules, stated plainly because they are shown to the customer:
  * a group is a connected set of at least two look-alikes of the same brand linked by cluster hints;
  * the verdict counts DISTINCT kinds of shared fact: 3 or more = likely one actor, 2 = possibly related, 1 = not enough evidence
    (for example only the registration date matches, which defending owners produce too);
  * if any member sits on the customer's own infrastructure the group is labelled "may be your own" and counts for nothing;
  * a candidate a person has marked not-a-threat, ignored, or removed from the group never belongs to one;
  * rebuilt after every scan and after every decision, so a new look-alike that shares these facts joins by itself.

Pure functions (`build_groups`, `name_for`, `verdict_for`) plus one database step (`sync`). Nothing here reaches the network.
"""
from __future__ import annotations

import logging
import re
import uuid
from collections import Counter
from datetime import datetime, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

log = logging.getLogger(__name__)

KIND_LABEL = {
    "registration_batch": "Registered together", "shared_certificate": "Same certificate",
    "shared_nameservers": "Same nameservers", "shared_server": "Same server address",
}
VERDICT = {
    "likely_one_actor": {"label": "Likely one actor", "tone": "red"},
    "possibly_related": {"label": "Possibly related", "tone": "amber"},
    "not_enough": {"label": "Not enough evidence", "tone": "slate"},
    "probably_yours": {"label": "May be your own", "tone": "green"},
}
# A decided-harmless or removed candidate is not part of an actor's campaign.
LEFT_OUT_STATUSES = frozenset({"customer_owned", "partner", "false_positive", "benign", "ignored", "removed"})
MAX_MEMBERS = 60


def verdict_for(kinds: set[str], benign: bool) -> str:
    if benign:
        return "probably_yours"
    if len(kinds) >= 3:
        return "likely_one_actor"
    if len(kinds) == 2:
        return "possibly_related"
    return "not_enough"


def why_for(verdict: str, facts: list[dict], size: int) -> str:
    """One plain sentence for the list: what ties them together."""
    if verdict == "probably_yours":
        return "At least one of these sits on your own infrastructure, so this may be your own defensive batch."
    if not facts:
        return f"{size} look-alikes appear related."
    parts = [f["label"].lower() for f in facts]
    shared = ", ".join(dict.fromkeys(parts))
    if verdict == "not_enough":
        return f"Only one thing links them ({shared}). Kept together, but not enough to call it one operator."
    return f"{size} look-alikes share these: {shared}."


def build_groups(members: list[dict]) -> list[dict]:
    """members: [{"domain", "clusters": [hint,...], "registered_at": iso|None, "first_seen_at": datetime|None, "eligible": bool}].
    Returns [{"domains": [...], "facts": [...], "verdict": key, "kinds": [...], "first_seen_at"}], largest first."""
    eligible = {m["domain"]: m for m in members if m.get("eligible", True)}
    parent: dict[str, str] = {d: d for d in eligible}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[max(ra, rb)] = min(ra, rb)          # deterministic root

    for d, m in eligible.items():
        for hint in m.get("clusters") or []:
            for sib in hint.get("siblings") or []:
                if sib in eligible:
                    union(d, sib)

    comps: dict[str, list[str]] = {}
    for d in eligible:
        comps.setdefault(find(d), []).append(d)

    out: list[dict] = []
    for domains in comps.values():
        if len(domains) < 2:
            continue
        domains = sorted(domains)[:MAX_MEMBERS]
        inside = set(domains)
        facts, kinds, benign = _facts(domains, eligible, inside)
        if not kinds and not benign:
            continue                                        # linked only by a sibling that fell outside the group
        v = verdict_for(kinds, benign)
        seen = [eligible[d]["first_seen_at"] for d in domains if eligible[d].get("first_seen_at")]
        out.append({"domains": domains, "facts": facts, "verdict": v, "kinds": sorted(kinds),
                    "first_seen_at": min(seen) if seen else None})
    out.sort(key=lambda g: (-len(g["domains"]), g["domains"][0]))
    return out


def _facts(domains: list[str], eligible: dict, inside: set[str]) -> tuple[list[dict], set[str], bool]:
    """The facts shared INSIDE the group: one entry per (kind, value), with how many of the members have it."""
    by_key: dict[tuple, set[str]] = {}
    values: dict[tuple, object] = {}
    benign = False
    for d in domains:
        for hint in eligible[d].get("clusters") or []:
            if not any(s in inside for s in hint.get("siblings") or []):
                continue                                    # this hint only links to names outside the group
            if hint.get("weight", 1) == 0:
                benign = True
            kind = (hint.get("data") or {}).get("kind") or hint.get("kind")
            value = (hint.get("data") or {}).get("value")
            key = (kind, "" if kind == "registration_batch" else str(value))
            by_key.setdefault(key, set()).add(d)
            values.setdefault(key, value)
    facts: list[dict] = []
    for key, have in sorted(by_key.items(), key=lambda kv: (-len(kv[1]), str(kv[0]))):
        kind = key[0]
        value = values.get(key)
        if kind == "registration_batch":
            dates = sorted(eligible[d]["registered_at"] for d in have if eligible[d].get("registered_at"))
            value = {"from": dates[0], "to": dates[-1]} if dates else None
        facts.append({"kind": kind, "label": KIND_LABEL.get(kind, kind), "value": value, "count": len(have), "of": len(domains)})
    kinds = {f["kind"] for f in facts}
    return facts, kinds, benign


def name_for(domains: list[str], brand_tokens: list[str]) -> str:
    """A readable name: the brand plus the word most of the members add to it ("acme-login cluster")."""
    brand = next((t for t in brand_tokens if t and len(t) >= 3), "brand")
    words: Counter[str] = Counter()
    for d in domains:
        label = d.split(".")[0]
        # numbered batches (name711, name714) are one word: the trailing digits are dropped
        parts = {p for p in (re.sub(r"\d+$", "", w) for w in re.split(r"[^a-z0-9]+", label.lower())) if len(p) >= 3}
        for p in parts:
            if not any(t and (t in p or p in t) for t in brand_tokens if len(t) >= 3):
                words[p] += 1
    word, n = (words.most_common(1) or [("", 0)])[0]
    if word and n >= 2:
        return f"{brand}-{word} cluster"[:160]
    return f"{brand} cluster"[:160]


async def sync(db: AsyncSession, profile, brand_tokens: list[str]) -> dict:
    """Rebuild the stored campaigns of one brand from its candidates. Never raises into a scan: the caller wraps it."""
    from app.models import BrandCampaign, BrandCandidate

    rows = (await db.execute(select(BrandCandidate).where(BrandCandidate.profile_id == profile.id))).scalars().all()
    by_domain = {r.candidate_domain: r for r in rows}
    members = [{
        "domain": r.candidate_domain, "clusters": (r.enrichment or {}).get("clusters") or [],
        "registered_at": (r.enrichment or {}).get("registered_at"), "first_seen_at": r.first_seen_at,
        "eligible": r.status not in LEFT_OUT_STATUSES and not r.campaign_locked,
    } for r in rows]
    groups = build_groups(members)

    existing = {c.id: c for c in (await db.execute(select(BrandCampaign).where(BrandCampaign.profile_id == profile.id))).scalars().all()}
    used_names = {c.name for c in existing.values()}
    kept: set[uuid.UUID] = set()
    for g in groups:
        rows_in = [by_domain[d] for d in g["domains"]]
        prior = sorted({r.campaign_id for r in rows_in if r.campaign_id in existing}, key=lambda i: (existing[i].created_at or datetime.min.replace(tzinfo=timezone.utc), str(i)))
        if prior:
            camp = existing[prior[0]]                      # the oldest campaign survives a merge
        else:
            name = name_for(g["domains"], brand_tokens)
            base, n = name, 1
            while name in used_names:
                n += 1
                name = f"{base} {n}"
            used_names.add(name)
            camp = BrandCampaign(id=uuid.uuid4(), tenant_id=profile.tenant_id, profile_id=profile.id, name=name,
                                 created_at=datetime.now(timezone.utc))
            db.add(camp)
            await db.flush()
            existing[camp.id] = camp
        camp.verdict, camp.facts, camp.member_count = g["verdict"], g["facts"], len(g["domains"])
        if g["first_seen_at"]:
            camp.first_seen_at = g["first_seen_at"]
        kept.add(camp.id)
        for r in rows_in:
            r.campaign_id = camp.id
    grouped = {d for g in groups for d in g["domains"]}
    for r in rows:
        if r.candidate_domain not in grouped and r.campaign_id is not None:
            r.campaign_id = None
    await db.flush()
    gone = [cid for cid in existing if cid not in kept]
    if gone:
        await db.execute(delete(BrandCampaign).where(BrandCampaign.id.in_(gone)))
    await db.flush()
    return {"campaigns": len(groups), "removed": len(gone)}
