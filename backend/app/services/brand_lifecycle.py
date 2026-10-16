"""
Brand Guard — candidate lifecycle model (plan step 2.1). Pure functions, no I/O.

A lookalike domain moves up a ladder as an attacker sets it up. Each rung leaves a public trace:

    unregistered -> registered -> resolving -> mail_enabled -> certified
                    (exists in    (A/AAAA      (MX records)    (TLS certificate seen
                     DNS)          answers)                     in CT logs)

(`serving` — an HTTP response — and `weaponized` — page content — are later rungs, plan Stage 7.)

The stage reached, and above all the *speed and pattern of progression*, are stronger signals than
any single feature: most lookalikes are registered and left dormant, and a dormant one that starts
resolving or sending mail is the moment that matters.

Honesty about time: we only know the state when we look. Every event therefore carries
`observed_at` (when we noticed) and `window_start` (the previous observation); the real change
happened somewhere in that window and is never presented as an exact time. Flags already true at
first observation form the *baseline* — they say nothing about how fast the attacker moved, so they
are never counted as progression.

State is a small JSON document kept on the candidate row; the full history is written separately
(observations when the state changes, plus at most one heartbeat a day).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

STAGES = ("unregistered", "registered", "resolving", "mail_enabled", "certified")
STAGE_RANK = {s: i for i, s in enumerate(STAGES)}
STAGE_LABEL = {
    "unregistered": "Not registered", "registered": "Registered", "resolving": "Resolving",
    "mail_enabled": "Mail-enabled", "certified": "Certificate issued",
}
FLAGS = ("registered", "resolving", "mail", "certified")
FLAG_STAGE = {"registered": "registered", "resolving": "resolving", "mail": "mail_enabled", "certified": "certified"}
HEARTBEAT = timedelta(hours=24)
DORMANT_ACTIVATION_DAYS = 14          # "sat dormant for a while, then woke up" threshold
FAST_PROGRESSION_WINDOW = timedelta(days=7)


@dataclass(frozen=True)
class Observation:
    at: datetime
    registered: bool | None          # None = DNS could not say (timeouts); never treated as "not registered"
    resolving: bool
    mail: bool
    certified: bool
    ns: tuple[str, ...] = ()
    registered_at: datetime | None = None   # registry creation date (RDAP), a fact about the domain, not an observation time


@dataclass
class Event:
    kind: str                         # first_observed | flag_gained | flag_lost | stage_changed | activated | ns_changed
    payload: dict
    observed_at: datetime
    window_start: datetime | None


@dataclass
class Advance:
    state: dict | None
    events: list[Event] = field(default_factory=list)
    write_observation: bool = False
    skipped: bool = False             # nothing could be concluded (all-unknown observation)

    @property
    def changed(self) -> bool:
        return bool(self.events)


def derive_stage(registered: bool | None, resolving: bool, mail: bool, certified: bool) -> str:
    if certified:
        return "certified"
    if mail:
        return "mail_enabled"
    if resolving:
        return "resolving"
    return "registered" if registered else "unregistered"


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat() if dt else None


def _dt(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def advance(prev: dict | None, obs: Observation) -> Advance:
    """Fold one observation into the candidate's lifecycle state; returns the new state, the
    transition events, and whether a history row should be written."""
    prev = prev or None
    resolving, mail = obs.resolving, obs.mail
    certified = obs.certified or bool(prev and prev.get("certified"))          # a certificate never un-issues
    anything_live = resolving or mail or certified
    registered = True if anything_live else (obs.registered if obs.registered is not None else (prev or {}).get("registered"))

    if registered is None:                     # first sighting and DNS could not answer: conclude nothing
        return Advance(prev, skipped=True)

    stage = derive_stage(registered, resolving, mail, certified)
    new_flags = {"registered": bool(registered), "resolving": resolving, "mail": mail, "certified": certified}
    ns = sorted(obs.ns)
    window_start = _dt(prev.get("last_obs_at")) if prev else None
    events: list[Event] = []

    if prev is None:
        present = [f for f in FLAGS if new_flags[f]]
        events.append(Event("first_observed", {"stage": stage, "flags": present}, obs.at, None))
        state = {
            **new_flags, "ns": ns, "stage": stage, "stage_changed_at": _iso(obs.at), "first_observed_at": _iso(obs.at),
            "first": {f: _iso(obs.at) for f in present}, "baseline": present,
            "last_obs_at": _iso(obs.at), "registered_at": _iso(obs.registered_at),
        }
        return Advance(state, events, write_observation=True)

    state = {**prev, **new_flags, "ns": ns, "stage": stage, "last_obs_at": _iso(obs.at)}
    state["registered_at"] = _iso(obs.registered_at) or prev.get("registered_at")
    state["first"] = dict(prev.get("first", {}))

    for flag in FLAGS:
        was, now = bool(prev.get(flag)), new_flags[flag]
        if now and not was:
            events.append(Event("flag_gained", {"flag": flag}, obs.at, window_start))
            state["first"].setdefault(flag, _iso(obs.at))
        elif was and not now and flag != "certified":
            events.append(Event("flag_lost", {"flag": flag}, obs.at, window_start))

    old_stage = prev.get("stage", "registered")
    if stage != old_stage:
        direction = "up" if STAGE_RANK[stage] > STAGE_RANK.get(old_stage, 0) else "down"
        events.append(Event("stage_changed", {"from": old_stage, "to": stage, "direction": direction}, obs.at, window_start))
        state["stage_changed_at"] = _iso(obs.at)
        if STAGE_RANK.get(old_stage, 0) <= STAGE_RANK["registered"] and STAGE_RANK[stage] >= STAGE_RANK["resolving"]:
            reference = _dt(state.get("registered_at")) or _dt(state["first"].get("registered")) or _dt(prev.get("first_observed_at"))
            days = max((obs.at - reference).days, 0) if reference else None
            events.append(Event("activated", {"days_dormant": days, "to": stage}, obs.at, window_start))

    if prev.get("ns") and ns and sorted(prev["ns"]) != ns:
        events.append(Event("ns_changed", {"from": sorted(prev["ns"]), "to": ns}, obs.at, window_start))

    last = _dt(prev.get("last_obs_at"))
    heartbeat_due = last is None or obs.at - last >= HEARTBEAT
    return Advance(state, events, write_observation=bool(events) or heartbeat_due)


def velocity(state: dict | None, now: datetime) -> dict:
    """Features describing HOW this candidate got to where it is. Derived purely from the state, so
    they can be recomputed at any time and tested without a database."""
    if not state:
        return {}
    first = {k: _dt(v) for k, v in (state.get("first") or {}).items()}
    baseline = set(state.get("baseline") or [])
    first_observed = _dt(state.get("first_observed_at"))
    registered_ref = _dt(state.get("registered_at")) or first.get("registered")
    stage = state.get("stage", "registered")

    gained_after = sorted(
        ((f, t) for f, t in first.items() if f not in baseline and f != "registered" and t and first_observed and t > first_observed),
        key=lambda x: x[1],
    )
    activation_times = [first[f] for f in ("resolving", "mail") if first.get(f) and f not in baseline]
    activated = bool(activation_times) and "registered" in (baseline | set(first))
    activated_at = min(activation_times) if activation_times else None
    dormant_before = (max((activated_at - registered_ref).days, 0) if (activated and registered_ref) else None)

    span = None
    if len(gained_after) >= 2:
        span = gained_after[-1][1] - gained_after[0][1]

    changed_at = _dt(state.get("stage_changed_at"))
    return {
        "stage": stage,
        "dormant": stage == "registered",
        "dormant_days": max((now - registered_ref).days, 0) if (stage == "registered" and registered_ref) else None,
        "activated": activated,
        "days_dormant_before_activation": dormant_before,
        "gained_after_discovery": [{"flag": f, "first_seen_at": _iso(t)} for f, t in gained_after],
        "progression_hours": round(span.total_seconds() / 3600, 1) if span is not None else None,
        "fast_progression": span is not None and span <= FAST_PROGRESSION_WINDOW,
        "age_in_stage_hours": round((now - changed_at).total_seconds() / 3600, 1) if changed_at else None,
        "registered_at": _iso(registered_ref),
    }


def ladder(state: dict | None) -> list[dict]:
    """The ladder for display: each rung with whether it was reached, when it was first seen, and
    whether that was only the baseline at discovery (so no timing is implied)."""
    state = state or {}
    first, baseline = state.get("first") or {}, set(state.get("baseline") or [])
    rows = []
    for flag in FLAGS:
        stage = FLAG_STAGE[flag]
        reached = bool(state.get(flag))
        rows.append({
            "stage": stage, "label": STAGE_LABEL[stage], "reached": reached,
            "first_seen_at": first.get(flag), "baseline": flag in baseline,
            "current": state.get("stage") == stage,
        })
    return rows


def describe_event(kind: str, payload: dict) -> str:
    """Plain-language line for the timeline. States what we observed, never an exact time of change."""
    label = lambda stage: STAGE_LABEL.get(stage, stage).lower()
    flag_label = {"registered": "registration", "resolving": "web address (A/AAAA) records", "mail": "mail (MX) records", "certified": "TLS certificate"}
    if kind == "first_observed":
        return f"First observed — {label(payload.get('stage', 'registered'))}"
    if kind == "flag_gained":
        return f"Detected {flag_label.get(payload.get('flag'), payload.get('flag'))}"
    if kind == "flag_lost":
        return f"No longer seeing {flag_label.get(payload.get('flag'), payload.get('flag'))}"
    if kind == "stage_changed":
        return f"Moved {payload.get('direction', 'up')} the ladder: {label(payload.get('from', ''))} → {label(payload.get('to', ''))}"
    if kind == "activated":
        days = payload.get("days_dormant")
        return "Went live" + (f" after sitting dormant for about {days} days" if days is not None else "") + f" ({label(payload.get('to', 'resolving'))})"
    if kind == "ns_changed":
        return "Nameservers changed"
    return kind

