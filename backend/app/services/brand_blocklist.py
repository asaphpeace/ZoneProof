"""Blocklist exports and assisted reporting (plan step 8.5): turn confirmed look-alikes into rules a customer can load into their own mail,
web and DNS filters, usually long before a takedown lands.

Pure functions. Nothing here talks to a customer's systems or to a reporting service: the person downloads the file or opens the report page
and does the submitting. Only names a person confirmed (or took to takedown) are exported by default, because a blocklist built from a
guess blocks real mail and real sites."""
from __future__ import annotations

import json
import re
from datetime import datetime
from urllib.parse import quote

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+[a-z0-9-]{{2,63}}$")

# name -> (label, where a person reports a URL, how the address is passed in, what the service wants)
SERVICES = {
    "google_safe_browsing": ("Google Safe Browsing", "https://safebrowsing.google.com/safebrowsing/report_phish/", "url",
                             "Protects Chrome, Firefox and Safari users. It checks the live page, so a domain that serves nothing yet may be declined."),
    "microsoft": ("Microsoft SmartScreen", "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site", "",
                  "Protects Edge and Defender users. Paste the address into the form."),
    "netcraft": ("Netcraft", "https://report.netcraft.com/report", "",
                 "Feeds many browser and security products. Paste the address into the form."),
}
SUBMISSION_STATUSES = ("submitted", "listed", "declined")
SUBMISSION_NEXT = {"submitted": ("listed", "declined"), "listed": (), "declined": ("submitted",)}


def clean(domains: list[str]) -> list[str]:
    """Lower-cased, de-duplicated, sorted, and only valid hostnames (nothing that could break a config line or inject a rule)."""
    out = {d.strip().lower().rstrip(".") for d in domains if isinstance(d, str)}
    return sorted(d for d in out if len(d) <= 253 and DOMAIN_RE.match(d))


def plain(domains: list[str]) -> str:
    return "\n".join(clean(domains)) + "\n"


def csv(domains: list[str]) -> str:
    return "domain\n" + "\n".join(clean(domains)) + "\n"


def microsoft_365(domains: list[str], brand: str, when: datetime) -> str:
    """Exchange Online PowerShell for the Tenant Allow/Block List: blocks the names as URLs and as senders. The admin runs it."""
    names = clean(domains)
    quoted = ",".join(f'"{d}"' for d in names)
    note = f"ZoneProof look-alikes of {brand}, {when.strftime('%Y-%m-%d')}"
    if not names:
        return "# No confirmed look-alikes to block yet.\n"
    return (
        f"# Review before running. Needs Exchange Online PowerShell and the right admin role.\n"
        f"# {note}\n"
        f"New-TenantAllowBlockListItems -ListType Url -Block -Entries {quoted} -NoExpiration -Notes \"{note}\"\n"
        f"New-TenantAllowBlockListItems -ListType Sender -Block -Entries {quoted} -NoExpiration -Notes \"{note}\"\n"
    )


def rpz(domains: list[str], brand: str, when: datetime, serial: int | None = None) -> str:
    """A DNS Response Policy Zone that answers NXDOMAIN for each name and everything under it. Load it into BIND, Unbound or Knot."""
    serial = serial or int(when.strftime("%Y%m%d01"))
    lines = [
        f"; ZoneProof look-alikes of {brand}, generated {when.strftime('%Y-%m-%d')}. Review before loading.",
        "$TTL 300",
        f"@ IN SOA localhost. root.localhost. ({serial} 3600 600 86400 300)",
        "  IN NS localhost.",
    ]
    for d in clean(domains):
        lines += [f"{d} CNAME .", f"*.{d} CNAME ."]
    return "\n".join(lines) + "\n"


def chrome_policy(domains: list[str]) -> str:
    """Chrome / Edge enterprise policy: URLBlocklist."""
    return json.dumps({"URLBlocklist": clean(domains)}, indent=2) + "\n"


FORMATS = {
    "plain": ("Plain list", "text/plain", "txt"),
    "csv": ("CSV", "text/csv", "csv"),
    "m365": ("Microsoft 365 block list (PowerShell)", "text/plain", "ps1"),
    "rpz": ("DNS RPZ zone", "text/plain", "zone"),
    "chrome": ("Chrome / Edge policy (JSON)", "application/json", "json"),
}


def render(fmt: str, domains: list[str], brand: str, when: datetime) -> str:
    if fmt == "plain":
        return plain(domains)
    if fmt == "csv":
        return csv(domains)
    if fmt == "m365":
        return microsoft_365(domains, brand, when)
    if fmt == "rpz":
        return rpz(domains, brand, when)
    if fmt == "chrome":
        return chrome_policy(domains)
    raise ValueError(fmt)


def report_link(service: str, domain: str) -> dict:
    """Where to report `domain` to a reporting service. The address is prefilled only where the service documents a query parameter."""
    label, base, param, note = SERVICES[service]
    url = f"{base}?{param}={quote('http://' + domain, safe='')}" if param else base
    return {"service": service, "label": label, "url": url, "paste": f"http://{domain}", "note": note}


def can_move_submission(current: str, new: str) -> bool:
    return new in SUBMISSION_NEXT.get(current, ())
