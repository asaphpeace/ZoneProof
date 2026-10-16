"""
Brand Guard — the evidence-ratio combiner (plan step 3.1). Pure functions; no database, no network.

The additive 0-100 abuse score adds hand-set points. Points are not probabilities, they double-count signals that always arrive
together, and nothing says whether a point value is justified. This module recomputes the same evidence as a NAKED LIKELIHOOD RATIO:

    evidence ratio  =  P(this evidence | a known-bad young domain)  /  P(this evidence | a new registration in general)

combined across INDEPENDENT families of evidence (signals of one family are correlated, so they are damped, not simply added).
Every contribution carries its provenance:

    measured  the ratio comes from `brand_eval.abuse_lr` run on real data; the CONSERVATIVE end of its 95% interval is used, and a
              signal whose interval includes 1 contributes nothing (it did not survive measurement)
    expert    nobody has measured it yet; its old point value is converted at a fixed, labelled rate (EXPERT_POINTS_PER_NEPER). Shown
              as assumed, and never mixed into the "measured" figure.

What this deliberately does NOT produce: a probability. A posterior needs a prior (how common abuse is among look-alikes of a given
brand), and no data we have measures that. The honest output is "how much stronger than ordinary new registrations", a band, and an
abstain state; Stage 3.2 turns a ratio into a probability only when real labels exist (analyst decisions, Stage 9).
"""
from __future__ import annotations

import json
import math
from pathlib import Path

from app.services.brand_verdict import FAMILY

TABLE_PATH = Path(__file__).resolve().parent.parent / "data" / "signal_ratios.json"
EXPERT_POINTS_PER_NEPER = 10.0        # assumed: +10 points = a likelihood ratio of e (~2.7); labelled "expert" wherever it is used
LN10 = math.log(10)
DAMPING = (1.0, 0.5, 0.25)            # within a family: the strongest signal counts fully, the next half, then a quarter, then nothing
BANDS = ((2.0, "strong"), (1.0, "moderate"), (0.3, "weak"))      # log10 of the evidence ratio, positive side
EXPLAINED = -0.7                      # log10 ratio at or below which the evidence leans harmless
CONFLICT = 0.7                        # both sides at least this strong (log10) = the evidence conflicts: abstain

STATE_TEXT = {
    "strong": "Strong evidence", "moderate": "Moderate evidence", "weak": "Weak evidence", "insufficient": "Not enough evidence",
    "conflicting": "Conflicting evidence", "harmless_leaning": "Leans harmless",
}

_cached: dict | None = None


def load_table(path: Path | None = None) -> dict:
    """{"measured_on", "signals": {name: {"ln_lr", "basis", ...}}}; an empty table (nothing measured) if the file is absent."""
    global _cached
    if path is None and _cached is not None:
        return _cached
    p = path or TABLE_PATH
    try:
        table = json.loads(p.read_text(encoding="utf8"))
    except (OSError, ValueError):
        table = {"measured_on": None, "signals": {}}
    if path is None:
        _cached = table
    return table


def reset_cache() -> None:
    global _cached
    _cached = None


def _ln_lr(name: str, weight: float, table: dict) -> tuple[float, str, str] | None:
    """(ln ratio, basis, note) for one signal, or None when it carries no abuse-side evidence."""
    entry = (table.get("signals") or {}).get(name)
    if entry is not None:
        if entry.get("basis") == "measured":
            return float(entry["ln_lr"]), "measured", entry.get("note", "")
        return float(entry["ln_lr"]), "expert", entry.get("note", "")
    if weight == 0:
        return None
    return weight / EXPERT_POINTS_PER_NEPER, "expert", f"hand-set {weight:+g} points, converted at {EXPERT_POINTS_PER_NEPER:g} points per neper"


def points_for(signal: str, default: float, table: dict | None = None) -> float:
    """The weight (in the old 0-100 additive points) the scorer should use for `signal`: the MEASURED value when the signal has been
    measured (10 points per neper, from the conservative end of the interval; 0 when it measurably does not separate bad from ordinary),
    otherwise the hand-set default. One place, so the additive score and the evidence ratio can never disagree about a measured signal."""
    entry = ((table if table is not None else load_table()).get("signals") or {}).get(signal)
    if entry is not None and entry.get("basis") == "measured":
        return round(float(entry["ln_lr"]) * EXPERT_POINTS_PER_NEPER, 1)
    return default


def _damped(values: list[float]) -> float:
    ordered = sorted(values, key=abs, reverse=True)
    return sum(v * DAMPING[i] for i, v in enumerate(ordered[: len(DAMPING)]))


def combine(signals, table: dict | None = None) -> dict:
    """`signals`: objects with .signal/.dimension/.weight (or dicts with those keys); only ABUSE-dimension evidence is combined, since
    resemblance to the brand is the identity score's job. Returns:
      {"log10_total", "log10_measured", "ratio", "ratio_measured", "state", "label", "components": [...], "families": {...}, "notes": [...]}"""
    table = table if table is not None else load_table()
    comps: list[dict] = []
    for s in signals:
        name = s["signal"] if isinstance(s, dict) else s.signal
        dim = s["dimension"] if isinstance(s, dict) else s.dimension
        weight = float(s["weight"] if isinstance(s, dict) else s.weight)
        if dim != "abuse":
            continue
        got = _ln_lr(name, weight, table)
        if got is None or got[0] == 0:
            continue
        ln, basis, note = got
        comps.append({"signal": name, "family": FAMILY.get(name, "other"), "log10": ln / LN10, "basis": basis, "note": note})

    by_family: dict[str, list[dict]] = {}
    for c in comps:
        by_family.setdefault(c["family"], []).append(c)
    families: dict[str, dict] = {}
    total = measured = pos = neg = 0.0
    for fam, items in sorted(by_family.items()):
        both = _damped([c["log10"] for c in items])
        only_measured = _damped([c["log10"] for c in items if c["basis"] == "measured"])
        families[fam] = {"log10": both, "log10_measured": only_measured, "signals": [c["signal"] for c in items]}
        total += both
        measured += only_measured
        if both > 0:
            pos += both
        else:
            neg += -both

    if pos >= CONFLICT and neg >= CONFLICT:
        state = "conflicting"
    elif total <= EXPLAINED:
        state = "harmless_leaning"
    else:
        state = next((name for floor, name in BANDS if total >= floor), "insufficient")
    notes: list[str] = []
    expert_only = [c["signal"] for c in comps if c["basis"] == "expert" and c["log10"] > 0]
    if expert_only and abs(total - measured) >= 0.3:
        notes.append("Part of this rests on hand-set weights nobody has measured yet: " + ", ".join(sorted(set(expert_only))) + ".")
    return {
        "log10_total": round(total, 2), "log10_measured": round(measured, 2),
        "ratio": round(10 ** total, 1), "ratio_measured": round(10 ** measured, 1),
        "state": state, "label": STATE_TEXT[state], "components": comps, "families": families, "notes": notes,
        "measured_on": (table or {}).get("measured_on"),
    }
