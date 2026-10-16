"""Defensive-registration advisor (plan step 8.6): which look-alike names are worth buying first.

The learned generator and discriminator (Stage 5) are not built, so this ranking is a STATED PRIOR, not a measurement: an expert-set weight per
kind of look-alike and per suffix, raised when the same kind of name is already being used against this brand. It says "worth considering
first", never "an attacker will register this". Availability is an indication only (the name did not resolve in DNS); a registrar has the last
word, and that check is not made here.

Pure functions. The network step (checking DNS for the shortlist) lives in the router."""
from __future__ import annotations

from collections import Counter

# How plausible each kind of look-alike is as an attack name, 0..1. Expert-set. Visually identical names first: nobody can spot them.
CLASS_PRIOR = {
    "homoglyph": 1.0, "idn_homograph": 1.0, "typo": 0.8, "omission": 0.8, "transposition": 0.75, "bitsquat": 0.4, "tld_swap": 0.7, "combosquat": 0.7,
    "hyphenation": 0.6, "repetition": 0.55, "keyboard": 0.55, "sound_alike": 0.5, "cctld_mimic": 0.6, "subdomain_abuse": 0.0,
}
DEFAULT_CLASS = 0.4
# Suffixes people actually type, then the cheap ones phishing leans on. Expert-set.
TLD_PRIOR = {"com": 1.0, "co.za": 0.95, "net": 0.7, "org": 0.6, "co": 0.55, "info": 0.45, "online": 0.4, "xyz": 0.4, "top": 0.4, "io": 0.35}
DEFAULT_TLD = 0.3
OBSERVED_CLASS_BOOST = 0.25         # per hostile look-alike of the same kind already seen against this brand, capped
OBSERVED_TLD_BOOST = 0.2
BOOST_CAP = 0.5
SHORTLIST = 60                      # names whose DNS is checked per request
LIMIT = 15                          # names shown


def _tld(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) > 2 and f"{parts[-2]}.{parts[-1]}" in TLD_PRIOR else parts[-1]


def score(domain: str, klass: str | None, own_tld: str, hostile_classes: Counter, hostile_tlds: Counter) -> tuple[float, list[str]]:
    """0..1.5ish: the prior for this kind of name and suffix, plus a capped boost for what is already being used against the brand."""
    base_class = CLASS_PRIOR.get(klass or "", DEFAULT_CLASS)
    tld = _tld(domain)
    base_tld = TLD_PRIOR.get(tld, DEFAULT_TLD)
    if tld == own_tld:
        base_tld = max(base_tld, 1.0)                          # the suffix the brand itself uses is the one people mistype onto
    reasons = [f"{(klass or 'this kind of name').replace('_', ' ')}: a plausible way to impersonate the brand", f".{tld}: {'the same suffix as the brand' if tld == own_tld else 'a suffix often used for look-alikes'}"]
    boost = 0.0
    if klass and hostile_classes.get(klass):
        boost += min(OBSERVED_CLASS_BOOST * hostile_classes[klass], BOOST_CAP)
        reasons.append(f"{hostile_classes[klass]} {klass.replace('_', ' ')} look-alike(s) of this brand are already flagged as hostile")
    if hostile_tlds.get(tld):
        boost += min(OBSERVED_TLD_BOOST * hostile_tlds[tld], BOOST_CAP)
        reasons.append(f"{hostile_tlds[tld]} hostile look-alike(s) already use .{tld}")
    return round(base_class * base_tld + min(boost, BOOST_CAP), 3), reasons


def shortlist(generated: dict[str, str], already_known: set[str], own_tld: str, hostile: list[tuple[str, str | None]], limit: int = SHORTLIST) -> list[dict]:
    """Rank the generated names we do not already track (a tracked name is registered by someone). `hostile` = (domain, class) of candidates flagged hostile."""
    hc = Counter(k for _, k in hostile if k)
    ht = Counter(_tld(d) for d, _ in hostile)
    rows = []
    for d, klass in generated.items():
        if d in already_known or CLASS_PRIOR.get(klass, DEFAULT_CLASS) <= 0:
            continue
        s, why = score(d, klass, own_tld, hc, ht)
        rows.append({"domain": d, "class": klass, "score": s, "reasons": why})
    rows.sort(key=lambda r: (-r["score"], r["domain"]))
    return rows[:limit]


def advise(ranked: list[dict], registered: dict[str, bool | None], limit: int = LIMIT) -> dict:
    """Keep the shortlist names DNS says are not registered, best first. `registered[d]` is True / False / None (DNS could not say)."""
    free = [r for r in ranked if registered.get(r["domain"]) is False][:limit]
    return {
        "names": [{**r, "availability": "appears unregistered: confirm with your registrar"} for r in free],
        "checked": len(ranked),
        "taken": sum(1 for r in ranked if registered.get(r["domain"]) is True),
        "unknown": sum(1 for r in ranked if registered.get(r["domain"]) is None),
        "basis": "A stated prior, not a measurement: kinds of look-alike and suffixes are weighted by judgement, then raised when the same kind is already used against this brand.",
    }
