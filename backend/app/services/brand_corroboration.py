"""
Brand Guard — corroboration and benign explainers (plan step 2.5; pure functions, no network).

Evidence that comes from OUTSIDE the name and the DNS, in both directions:

  against   popular_site     the look-alike is itself a top-100,000 site (an unrelated, well-known business)   -25 / -15
            parked           its nameservers are a domain-parking service (a for-sale or ad-monetised name)     -8
            (and the infrastructure explainers of step 2.0: same nameservers / same server as the customer)
  for       on_phishing_feed listed by a public abuse feed — phishunt.io (automated phishing detection) or
                             abuse.ch URLhaus (malware distribution)                                          +30..+40

Weights are hand-set heuristics (abuse scoring cannot be measured offline; Stage 3 calibrates). Two safety rules:
  * a popularity discount applies only to a name that IS a registered domain — never to a host that is a subdomain of one
    (abused popular platforms are exactly where subdomain abuse lives; see brand_popularity);
  * a parked domain is still a brand nuisance and can be re-pointed, so it is discounted lightly and said to be watched.

Not here, on purpose: DNS blocklists (Spamhaus DBL / SURBL / URIBL) and Web Risk / VirusTotal need licences or paid keys
that are a product decision (plan decision gate); redirect-to-brand needs a web request (Stage 7).
"""
from __future__ import annotations

from app.services import brand_popularity
from app.services.brand_reasoning import points_for

POPULAR_TOP_WEIGHT = -25.0       # rank <= 10,000
POPULAR_WEIGHT = -15.0           # rank <= 100,000
PARKED_WEIGHT = -8.0
FEED_PHISHUNT_WEIGHT = 30.0
FEED_PHISHUNT_CORROBORATED_WEIGHT = 35.0   # phishunt also reports that other services flag the URL
FEED_URLHAUS_WEIGHT = 30.0
FEED_POSITIVE_CAP = 40.0

# Nameserver fragments of domain-parking / domain-sale services (hand-curated).
PARKING_NS = (
    ("sedoparking.com", "Sedo"), ("parkingcrew.net", "ParkingCrew"), ("bodis.com", "Bodis"), ("dns-parking.com", "Hostinger parking"),
    ("above.com", "Above.com"), ("parklogic.com", "ParkLogic"), ("domainsponsor.com", "DomainSponsor"), ("hugedomains.com", "HugeDomains"),
    ("dan.com", "Dan.com"), ("afternic.com", "Afternic"), ("fabulous.com", "Fabulous"),
)

SIGNALS = frozenset({"popular_site", "parked", "on_phishing_feed"})


def parking_service(ns: list[str] | None) -> str | None:
    for host in ns or []:
        h = host.lower().rstrip(".")
        for fragment, name in PARKING_NS:
            if h == fragment or h.endswith("." + fragment):
                return name
    return None


def popularity_finding(candidate_domain: str, registrable: str, *, on_platform: bool = False) -> dict | None:
    """A discount for a registered look-alike that is itself a well-known site. Subdomain hosts and names under hosting
    platforms never qualify (see the module docstring)."""
    if on_platform or candidate_domain != registrable:
        return None
    rank = brand_popularity.rank_of(registrable)
    if rank is None:
        return None
    weight = POPULAR_TOP_WEIGHT if rank <= brand_popularity.TOP_10K else POPULAR_WEIGHT
    return {"signal": "popular_site", "weight": weight, "data": {"rank": rank},
            "summary": f"{registrable} is itself a well-known site (about #{rank:,} on the web) — almost certainly a legitimate business, not an impersonator. It may even be yours: if so, add it to your official domains."}


def parking_finding(ns: list[str] | None) -> dict | None:
    service = parking_service(ns)
    if not service:
        return None
    return {"signal": "parked", "weight": points_for("parked", PARKED_WEIGHT), "data": {"service": service},
            "summary": f"Its nameservers belong to a domain-parking service ({service}) — a for-sale or ad-monetised name, not an active attack. Still a brand nuisance, and a parked name can be re-pointed, so it stays on watch."}


def feed_findings(entries: list[dict] | None) -> list[dict]:
    """Evidence from public abuse feeds. `entries` are what brand_feeds recorded for the candidate:
    {"feed": "phishunt"|"urlhaus", "label", "first_seen", "same_site": bool, "detail": {...}}."""
    out: list[dict] = []
    for e in entries or []:
        where = "this exact host" if not e.get("same_site") else "another host on the same registered domain"
        when = f" (first seen {str(e['first_seen'])[:10]})" if e.get("first_seen") else ""
        if e.get("feed") == "phishunt":
            others = int((e.get("detail") or {}).get("other_flags", 0))
            weight = FEED_PHISHUNT_CORROBORATED_WEIGHT if others else FEED_PHISHUNT_WEIGHT
            extra = f"; {others} other service(s) also flag it" if others else ""
            out.append({"signal": "on_phishing_feed", "weight": weight, "data": {"feed": "phishunt", "same_site": bool(e.get("same_site")), "other_flags": others},
                        "summary": f"Listed by phishunt.io as a suspected phishing site — {where}{when}{extra}. phishunt is automated detection, not human-verified."})
        elif e.get("feed") == "urlhaus":
            out.append({"signal": "on_phishing_feed", "weight": FEED_URLHAUS_WEIGHT, "data": {"feed": "urlhaus", "same_site": bool(e.get("same_site"))},
                        "summary": f"Listed by abuse.ch URLhaus as distributing malware — {where}{when}."})
    positive = sum(f["weight"] for f in out if f["weight"] > 0)
    if positive > FEED_POSITIVE_CAP:
        scale = FEED_POSITIVE_CAP / positive
        for f in out:
            f["weight"] = round(f["weight"] * scale, 1)
    return out


_BADGES = (
    ("on_phishing_feed", "blocklist", "On a blocklist"),
    ("reported_by_employee", "reported", "Reported by your team"),
    ("same_network_as_spoofer", "spoofer", "Same network as a spoofer"),
    ("popular_site", "popular", "Popular site"),
    ("parked", "parked", "Parked"),
    ("same_nameservers", "yours", "Your infrastructure"),
    ("same_hosting_ip", "yours", "Your infrastructure"),
    ("defensive_mail_posture", "parked", "Locked down"),
)


def badges_from_signals(signals) -> list[dict]:
    """The short corroboration chips shown in the candidate list, derived from the assessment's evidence (so the list never
    disagrees with the drawer). [{"kind", "label"}], de-duplicated, in a fixed order."""
    names = {s.signal for s in signals}
    out: list[dict] = []
    for signal, kind, label in _BADGES:
        if signal in names and not any(b["label"] == label for b in out):
            out.append({"kind": kind, "label": label})
    return out
