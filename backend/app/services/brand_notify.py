"""Notification channels for Brand Guard (plan step 8.7): email, Slack, Teams, a signed webhook, a daily digest, and a SIEM event export.

Pure functions plus one network helper. Customer-supplied URLs are the risk here (our server will POST to an address a customer typed), so:
a target must be https, Slack and Teams targets must be on those services' own hosts, and a generic webhook's host must resolve only to public
addresses at send time. Redirects are never followed. A webhook body is signed so the receiver can tell it came from ZoneProof.

Message text is built from fields we produced, and everything attacker-influenced (a look-alike's domain name) is escaped for the channel."""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import re
import socket
from datetime import datetime
from urllib.parse import urlparse

KINDS = ("email", "slack", "teams", "webhook")
SEVERITY_RANK = {"info": 0, "warn": 1, "critical": 2}
SLACK_HOSTS = ("hooks.slack.com",)
TEAMS_SUFFIXES = (".webhook.office.com", ".logic.azure.com", ".powerplatform.com", ".environment.api.powerplatform.com")
EMAIL_RE = re.compile(r"^[^@\s,;<>\"']{1,64}@[^@\s,;<>\"']{1,255}\.[^@\s,;<>\"']{2,63}$")


def validate_target(kind: str, target: str) -> str:
    """Normalised target, or ValueError with a message safe to show the person. Shape only; DNS is checked at send time."""
    t = (target or "").strip()
    if kind not in KINDS:
        raise ValueError("Unknown channel type")
    if kind == "email":
        if not EMAIL_RE.match(t):
            raise ValueError("That does not look like an email address")
        return t.lower()
    if len(t) > 2000:
        raise ValueError("That address is too long")
    u = urlparse(t)
    host = (u.hostname or "").lower()
    if u.scheme != "https" or not host:
        raise ValueError("The address must start with https://")
    if u.username or u.password:
        raise ValueError("The address must not contain a username or password")
    if u.port not in (None, 443):
        raise ValueError("Only the standard https port is allowed")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip:
        raise ValueError("Use a hostname, not an IP address")
    if kind == "slack" and host not in SLACK_HOSTS:
        raise ValueError("A Slack address must be an incoming-webhook URL on hooks.slack.com")
    if kind == "teams" and not any(host.endswith(s) for s in TEAMS_SUFFIXES):
        raise ValueError("A Teams address must be a Workflows or incoming-webhook URL on a Microsoft host")
    return t


def is_public_address(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


async def host_resolves_publicly(host: str) -> bool:
    """True only when the host resolves and EVERY address it resolves to is public (blocks internal targets a hostname might point at)."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        return False
    addrs = {i[4][0] for i in infos}
    return bool(addrs) and all(is_public_address(a) for a in addrs)


def passes(min_severity: str, severity: str) -> bool:
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(min_severity, 1)


def _esc_slack(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _short(text: str | None, n: int = 500) -> str:
    t = (text or "").strip()
    return t if len(t) <= n else t[: n - 1] + "…"


def slack_payload(alert: dict, link: str | None) -> dict:
    sev = {"critical": ":rotating_light:", "warn": ":warning:"}.get(alert["severity"], ":information_source:")
    lines = [f"{sev} *{_esc_slack(_short(alert['title'], 200))}*", _esc_slack(_short(alert["body"])), (f"_{_esc_slack(_short(alert['action'], 200))}_" if alert.get("action") else "")]
    if link:
        lines.append(f"<{link}|Open in ZoneProof>")
    return {"text": "\n".join(x for x in lines if x)}


def teams_payload(alert: dict, link: str | None) -> dict:
    """A MessageCard, accepted by Teams incoming webhooks and by Workflows 'post to channel' triggers."""
    card = {"@type": "MessageCard", "@context": "http://schema.org/extensions", "summary": _short(alert["title"], 150),
            "themeColor": {"critical": "FF4D6D", "warn": "F5C542"}.get(alert["severity"], "5B5CF0"), "title": _short(alert["title"], 200),
            "text": _short(alert["body"]) + (f"\n\n{_short(alert['action'], 200)}" if alert.get("action") else "")}
    if link:
        card["potentialAction"] = [{"@type": "OpenUri", "name": "Open in ZoneProof", "targets": [{"os": "default", "uri": link}]}]
    return card


def webhook_payload(alert: dict, link: str | None) -> dict:
    return {"source": "zoneproof", "type": "brand_guard.alert", "id": alert["id"], "severity": alert["severity"], "title": alert["title"], "body": alert["body"],
            "action": alert.get("action"), "created_at": alert["created_at"], "link": link}


def sign(body: bytes, secret: str, timestamp: str) -> str:
    """Header value for X-ZoneProof-Signature: HMAC-SHA256 over `timestamp.body`, so a receiver can verify origin and reject replays."""
    mac = hmac.new(secret.encode("utf-8"), timestamp.encode("utf-8") + b"." + body, hashlib.sha256).hexdigest()
    return f"sha256={mac}"


def verify(body: bytes, secret: str, timestamp: str, signature: str) -> bool:
    return hmac.compare_digest(sign(body, secret, timestamp), signature or "")


def email_parts(alert: dict, link: str | None) -> tuple[str, str, str]:
    """(subject, html body, text body). Text is what a plain client shows; HTML is escaped."""
    import html as h
    subject = f"[ZoneProof] {_short(alert['title'], 150)}"
    text = f"{alert['title']}\n\n{alert['body']}\n\n{alert.get('action') or ''}\n" + (f"\nOpen: {link}\n" if link else "")
    html = f"<p><b>{h.escape(alert['title'])}</b></p><p>{h.escape(alert['body'])}</p>" + (f"<p>{h.escape(alert['action'])}</p>" if alert.get("action") else "") + (f'<p><a href="{h.escape(link)}">Open in ZoneProof</a></p>' if link else "")
    return subject, html, text


def digest(*, brand: str, summary: dict, since: datetime) -> dict:
    """A short daily roll-up from the numbers the home screen already shows. Returns {title, lines}."""
    lines = [
        f"{summary.get('new_24h', 0)} new look-alike(s) in the last 24 hours",
        f"{summary.get('open_candidates', 0)} need a decision",
        f"{summary.get('confirmed', 0) + summary.get('takedown', 0)} open case(s)" + (f", {summary['overdue']} overdue" if summary.get("overdue") else ""),
    ]
    if "went_live_7d" in summary:
        lines.append(f"{summary['went_live_7d']} went live in the last 7 days")
    return {"title": f"ZoneProof daily summary for {brand}", "lines": lines, "since": since.isoformat()}


def digest_alert(d: dict) -> dict:
    """A digest rendered as an alert-shaped dict so the same channel senders can post it."""
    return {"id": "digest", "severity": "info", "title": d["title"], "body": "\n".join(f"- {x}" for x in d["lines"]), "action": None, "created_at": d["since"]}


def _cef_escape(v: str, header: bool = False) -> str:
    v = str(v).replace("\\", "\\\\").replace("\n", " ").replace("\r", " ")
    return v.replace("|", "\\|") if header else v.replace("=", "\\=")


def to_cef(ev: dict) -> str:
    """One event as ArcSight CEF, which most SIEMs ingest: CEF:0|vendor|product|version|signature|name|severity|extension."""
    sev = {"critical": 9, "warn": 6, "info": 3}.get(ev.get("severity", "info"), 3)
    ext = " ".join(f"{k}={_cef_escape(v)}" for k, v in (("rt", ev.get("at")), ("act", ev.get("action")), ("duser", ev.get("actor")), ("dhost", ev.get("target")), ("msg", ev.get("detail"))) if v)
    return f"CEF:0|ZoneProof|Brand Guard|1|{_cef_escape(ev['kind'], True)}|{_cef_escape(ev['name'], True)}|{sev}|{ext}"


def to_jsonl(events: list[dict]) -> str:
    return "".join(json.dumps(e, sort_keys=True, ensure_ascii=False, default=str) + "\n" for e in events)
