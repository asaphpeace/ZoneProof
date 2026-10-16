"""Takedown assistant (plan step 8.3): who can remove a look-alike, how to ask, and a draft complaint a person reviews.

Nothing here sends anything. A draft is edited and approved by a person, and the person sends it themselves; ZoneProof records that it was
sent and what came back. Routes are labelled by how sure we are: `discovered` (read from a public registry record just now) or
`suggested` (a well-known route we cannot verify from here, so the person must confirm the current contact before relying on it)."""
from __future__ import annotations

import ipaddress
from datetime import datetime
from urllib.parse import quote

CLOUDFLARE_ABUSE_FORM = "https://abuse.cloudflare.com/"       # Cloudflare's public abuse report form
STATUSES = ("draft", "approved", "sent", "acknowledged", "removed", "rejected")
NEXT = {"draft": ("approved",), "approved": ("draft", "sent"), "sent": ("acknowledged", "removed", "rejected"), "acknowledged": ("removed", "rejected"), "removed": (), "rejected": ("draft",)}


def _vcard_values(entity: dict, key: str) -> list[str]:
    out = []
    for item in (entity.get("vcardArray") or [None, []])[1] or []:
        if isinstance(item, list) and len(item) >= 4 and item[0] == key and isinstance(item[3], str) and item[3].strip():
            out.append(item[3].strip().removeprefix("tel:"))
    return out


def _walk(entities):
    for e in entities or []:
        if isinstance(e, dict):
            yield e
            yield from _walk(e.get("entities"))


def abuse_contacts(rdap: dict) -> dict:
    """Pure: the abuse contact in an RDAP object (domain or IP), e.g. {'emails': [...], 'phones': [...], 'name': ...}. Tolerant of any shape."""
    emails: list[str] = []
    phones: list[str] = []
    for e in _walk(rdap.get("entities")):
        if "abuse" in [str(r).lower() for r in e.get("roles") or []]:
            emails += [v for v in _vcard_values(e, "email") if "@" in v]
            phones += _vcard_values(e, "tel")
    return {"emails": sorted(set(emails)), "phones": sorted(set(phones)), "name": rdap.get("name") or None}


def registrar_name(rdap: dict) -> str | None:
    for e in rdap.get("entities") or []:
        if isinstance(e, dict) and "registrar" in [str(r).lower() for r in e.get("roles") or []]:
            names = _vcard_values(e, "fn")
            if names:
                return names[0][:160]
    return None


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def uses_cloudflare(nameservers: list[str] | None) -> bool:
    return any(str(n).lower().rstrip(".").endswith(".ns.cloudflare.com") for n in nameservers or [])


def _label(prefix: str, name: str | None) -> str:
    return f"{prefix} ({name})" if name else prefix


def routes(*, domain: str, registrar: str | None, registrar_abuse: dict | None, host_abuse: dict | None, host_ip: str | None, nameservers: list[str] | None) -> list[dict]:
    """Ordered ways to get it removed, most direct first. Each: kind, label, how (email|form|manual), target, certainty (discovered|suggested), note."""
    out: list[dict] = []
    ra = registrar_abuse or {}
    if ra.get("emails"):
        out.append({"kind": "registrar", "label": _label("Registrar", registrar), "how": "email", "target": ra["emails"][0], "certainty": "discovered",
                    "note": "Read from the registry record. A registrar can suspend the name; they usually want evidence of abuse, not only a resemblance."})
    elif domain.endswith(".za"):
        out.append({"kind": "za_registry", "label": ".za registry and registrar", "how": "manual", "target": "", "certainty": "suggested",
                    "note": "The .za registry does not publish a registrar abuse contact in a machine-readable record. Look the domain up at the registry's WHOIS, contact the registrar it names, "
                            "and confirm the registry's current complaint process before sending. Hosting providers that are ISPA members also have a published take-down procedure."})
    else:
        out.append({"kind": "registrar", "label": _label("Registrar", registrar), "how": "manual", "target": "", "certainty": "suggested",
                    "note": "No abuse contact was published. ICANN-accredited registrars must publish one: check the registrar's website for its abuse page."})
    if uses_cloudflare(nameservers):
        out.append({"kind": "cdn", "label": "Cloudflare (fronts this site)", "how": "form", "target": CLOUDFLARE_ABUSE_FORM, "certainty": "discovered",
                    "note": "Its nameservers are Cloudflare's. Cloudflare forwards reports to the real host but does not remove content itself, so also contact the host and registrar."})
    ha = host_abuse or {}
    if ha.get("emails"):
        out.append({"kind": "host", "label": _label("Hosting network", ha.get("name")), "how": "email", "target": ha["emails"][0], "certainty": "discovered",
                    "note": f"Abuse contact of the network that owns {host_ip}. It may be a CDN or a reseller rather than the real host."})
    elif host_ip:
        out.append({"kind": "host", "label": "Hosting network", "how": "manual", "target": "", "certainty": "suggested", "note": f"No abuse contact was published for {host_ip}. Look the address up with its regional registry."})
    return out


# What a complaint to a registrar or host may state. Only facts a third party
# can check for itself: the name, public registration and certificate data, a
# public blocklist listing, and what was captured from the page. Anything
# internal to the customer (an employee's report, their own mail traffic) or
# inferred from a link to other domains (shared hosting, "linked to known bad",
# a cluster) is never put in a complaint: it would disclose private data to a
# stranger, or assert something nobody observed on this domain.
NAME_AND_REGISTRATION = frozenset({
    "domain_similarity", "homoglyph", "keyword_combo", "new_registration", "ct_certificate", "registrar", "cert_after_registration",
})
PAGE_AND_FEED = frozenset({
    "on_phishing_feed", "page_password_form", "page_form_after_scripts", "page_brand_favicon",
    "page_icon_lookalike", "page_copies_wording", "page_certificate_odd", "page_redirects_to_brand",
})
CLAIM_SIGNALS = NAME_AND_REGISTRATION | PAGE_AND_FEED


def claims(evidence: list[dict]) -> tuple[list[str], str]:
    """
    The statements a complaint may make, and how strong the basis is.
    Returns (observations, level) where level is 'page_evidence' when something
    was captured from the page or a public blocklist, else 'name_only'.
    Each line needs a summary and a time it was observed.
    """
    usable = [e for e in evidence if e.get("signal") in CLAIM_SIGNALS and e.get("summary") and e.get("observed_at")]
    # page and feed lines first: they are what a provider can act on
    usable.sort(key=lambda e: 0 if e["signal"] in PAGE_AND_FEED else 1)
    level = "page_evidence" if any(e["signal"] in PAGE_AND_FEED for e in usable) else "name_only"
    seen: list[str] = []
    for e in usable:
        if e["summary"] not in seen:
            seen.append(e["summary"])
    return seen[:8], level


def _third_person(text: str, brand: str) -> str:
    """Evidence lines are written to the brand owner ('your brand'); a registrar reading the complaint needs the brand's name instead."""
    for a, b in (("your own ", f"{brand}'s own "), ("your brand", f"the {brand} brand"), ("your domain", f"{brand}'s domain"), ("not yours", f"not {brand}'s"), ("your team", f"{brand}'s team"), ("your ", f"{brand}'s ")):
        text = text.replace(a, b)
    return text


def draft(*, domain: str, brand: str, official_domains: list[str], observations: list[str], pack_hash: str | None, route: dict, sender_name: str, generated_at: datetime) -> dict:
    """A plain, factual complaint. States what was observed and asks for review; never claims more than the evidence shows."""
    obs = "\n".join(f"  - {_third_person(o, brand)}" for o in observations[:8])
    who = {"registrar": "registrar", "host": "hosting provider", "cdn": "service provider", "za_registry": "registry or registrar"}.get(route["kind"], "provider")
    subject = f"Abuse report: {domain} impersonating {brand}"
    basis = (
        f"What we have observed (public data, as of {generated_at.strftime('%Y-%m-%d')} UTC):\n{obs}\n\n"
        if obs else
        "At the time of writing we have not captured the content of this site. This report is based on the domain name, which contains "
        f"or closely resembles the {brand} brand name, and on its public registration details.\n\n"
    )
    body = (
        f"Hello,\n\nI am writing on behalf of {brand} ({', '.join(official_domains)}) to report the domain {domain}, which appears to impersonate our brand.\n\n"
        + basis
        + "We ask that you review this domain against your acceptable-use and abuse policies and, if it breaches them, suspend it or remove the content. "
        + f"As the {who}, you are best placed to act. If you need more information, reply to this message.\n\n"
        + (f"An evidence pack (SHA-256 {pack_hash}) is available on request.\n\n" if pack_hash else "")
        + f"Regards,\n{sender_name}\n"
    )
    return {"subject": subject, "body": body}


def mailto(target: str, subject: str, body: str) -> str:
    return f"mailto:{target}?subject={quote(subject)}&body={quote(body)}"


def can_move(current: str, new: str) -> bool:
    return new in NEXT.get(current, ())
