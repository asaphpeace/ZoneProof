"""Case workflow for confirmed look-alikes (plan step 8.1): who owns it, how long they have, what happened, and when a closed case reopens.

Pure functions only. The router and the scan pipeline call these and persist the results.

SLA hours are an ASSUMPTION (expert-set, not measured): how fast a team should act on a confirmed look-alike, by how urgent it is.
They are a working target shown to the person, never used to change a verdict."""
from datetime import datetime, timedelta

SLA_HOURS = {"high": 4, "medium": 24, "low": 72}
DUE_SOON_FRACTION = 0.25                      # "due soon" = the last quarter of the allowed time

OPEN_CASE = ("confirmed", "takedown")         # statuses that start the clock
CLOSED_CASE = ("removed",)                    # statuses that stop it and are watched for a comeback
REOPEN_STAGES = ("resolving", "mail_enabled", "certified")


def sla_hours(urgency: str | None) -> int:
    return SLA_HOURS.get(urgency or "low", SLA_HOURS["low"])


def due_at(urgency: str | None, start: datetime) -> datetime:
    return start + timedelta(hours=sla_hours(urgency))


def sla_state(status: str, due: datetime | None, resolved_at: datetime | None, now: datetime, window_hours: float | None = None) -> dict:
    """{state, due_at, hours_left}. state: none | on_track | due_soon | breached | met."""
    if due is None:
        return {"state": "none", "due_at": None, "hours_left": None}
    if status in CLOSED_CASE and resolved_at is not None:
        return {"state": "met" if resolved_at <= due else "breached", "due_at": due.isoformat(), "hours_left": None}
    if status not in OPEN_CASE:
        return {"state": "none", "due_at": due.isoformat(), "hours_left": None}
    left = (due - now).total_seconds() / 3600
    if left <= 0:
        state = "breached"
    elif left <= DUE_SOON_FRACTION * (window_hours or 24):
        state = "due_soon"
    else:
        state = "on_track"
    return {"state": state, "due_at": due.isoformat(), "hours_left": round(left, 1)}


def start_clock(previous: str, new: str, current_due: datetime | None, urgency: str | None, now: datetime) -> datetime | None:
    """A case's clock starts when it first becomes confirmed and is not restarted by moving confirmed -> takedown."""
    if new in OPEN_CASE and current_due is None:
        return due_at(urgency, now)
    return current_due


def resolved_stamp(previous: str, new: str, current: datetime | None, now: datetime) -> datetime | None:
    if new in CLOSED_CASE and previous not in CLOSED_CASE:
        return now
    if new not in CLOSED_CASE:
        return None
    return current


def is_resurrection(status: str, reviewed: bool, new_stage: str, events: list[str]) -> bool:
    """A case a person closed (removed) that a later check finds live again. Only a person's closure counts."""
    return reviewed and status in CLOSED_CASE and new_stage in REOPEN_STAGES and any(k in ("activated", "stage_changed", "flag_gained") for k in events)


def describe(kind: str, payload: dict) -> str | None:
    """Timeline lines for case events; None when the kind is not a case event."""
    who = payload.get("by") or "someone"
    if kind == "status_changed":
        return f"{who} changed the decision: {payload.get('from', '?')} → {payload.get('to', '?')}" + (f" ({payload['note']})" if payload.get("note") else "")
    if kind == "assigned":
        return f"{who} assigned this to {payload['to']}" if payload.get("to") else f"{who} removed the assignee"
    if kind == "takedown":
        return f"{who} marked the takedown request to {payload.get('route', 'a provider')} as {payload.get('to', '?')}"
    if kind == "resurrected":
        return "Came back after being removed: it resolves again, so the case was reopened for monitoring"
    return None
