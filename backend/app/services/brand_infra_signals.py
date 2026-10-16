"""
Brand Guard — registration, certificate, hosting and campaign signals (plan step 2.4; pure functions, no network).

Four families of evidence about a look-alike, none of which needs the page content:

  registration   RDAP facts beyond the creation date: the registrar (shown, never scored — large legitimate registrars
                 host abusers too), a RE-REGISTRATION event (a dropped name caught again), and a small prior for the
                 inexpensive suffixes attackers favour (tld_prior);
  certificate    how soon after registration a TLS certificate appeared (an automated set-up looks like minutes);
  hosting        the site's name is a CNAME to a free hosting platform;
  campaign       look-alikes of the SAME brand that share registration time, a certificate, nameservers or a server —
                 attackers register and set up in batches, so a cluster is stronger evidence than any member alone.

Everything here is a hand-set heuristic, to be calibrated in Stage 3 (abuse scoring cannot be measured offline). The one
exception is the suffix prior, checked against the evaluation corpus: cheap-suffix names were 15.3% of suspected phishing
hosts (17/111) against 7.2% of popular domains — roughly 2x, directionally supported, so it carries a small weight.

Cluster safety: owners defend a brand by registering many typos in one sitting, so a batch is NOT assumed hostile — if any
member sits on the customer's own infrastructure (or is parked-and-locked) the whole cluster scores nothing and says why.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# Inexpensive suffixes heavily used for throwaway infrastructure (the generator's list, kept in step with it).
HIGH_ABUSE_SUFFIXES = frozenset({
    "top", "icu", "cfd", "sbs", "click", "link", "live", "site", "shop", "store", "vip", "club", "cc", "xyz", "online", "info", "us",
})
TLD_PRIOR_WEIGHT = 5.0
REREGISTRATION_WEIGHT = 10.0
REREGISTRATION_WINDOW_DAYS = 180
CERT_AFTER_REGISTRATION_WEIGHT = 8.0
CERT_FAST_HOURS = 24
CERT_REGISTRATION_RECENT_DAYS = 90
FREE_PLATFORM_CNAME_WEIGHT = 5.0
# Free site builders and app hosts. NOT every hosting platform in the Public Suffix List: Akamai (edgekey.net), Azure
# (azurewebsites.net), CloudFront and Fastly are listed there too, but a registered domain whose www is a CNAME to a CDN is
# an ordinary large-company site. A live scan on dpd.com flagged DPD's own www.dpd.co.uk that way before this list existed.
FREE_SITE_HOSTS = frozenset({
    "pages.dev", "workers.dev", "github.io", "gitlab.io", "netlify.app", "vercel.app", "herokuapp.com", "glitch.me", "repl.co",
    "replit.dev", "onrender.com", "fly.dev", "web.app", "firebaseapp.com", "blogspot.com", "wixsite.com", "weebly.com",
    "weeblysite.com", "webflow.io", "framer.app", "carrd.co", "notion.site", "canva.site", "wordpress.com", "surge.sh",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "000webhostapp.com", "infinityfreeapp.com", "typedream.app",
    "gitbook.io", "bubbleapps.io", "softr.app", "edgeone.dev", "square.site", "godaddysites.com", "jimdofree.com",
    "mystrikingly.com", "site123.me", "webwave.me", "ukit.me", "rf.gd", "epizy.com", "byethost7.com", "tumblr.com",
    # free subdomain and dynamic-DNS services, common in phishing kits
    "eu.org", "de5.net", "dpdns.org", "us.kg", "pp.ua", "is-a.dev", "js.org", "duckdns.org", "no-ip.org", "ddns.net",
    "hopto.org", "zapto.org",
})

BATCH_WINDOW = timedelta(minutes=30)
CLUSTER_POSITIVE_CAP = 14.0
WEIGHT_BATCH_PAIR, WEIGHT_BATCH_MANY = 6.0, 10.0
WEIGHT_SHARED_CERT = 8.0
WEIGHT_SHARED_NS, WEIGHT_SHARED_SERVER = 6.0, 6.0
MIN_SHARED_NS_MEMBERS = MIN_SHARED_SERVER_MEMBERS = 3
_MAX_SIBLINGS = 8


def _dt(value) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def tld_prior(suffix: str | None) -> bool:
    """True for the inexpensive suffixes. Only the final label counts ('co.za' and 'com' are not on the list)."""
    return bool(suffix) and suffix.rsplit(".", 1)[-1].lower() in HIGH_ABUSE_SUFFIXES and "." not in suffix


def registration_findings(details: dict | None, suffix: str | None, now: datetime) -> list[dict]:
    """[{"signal","weight","summary","data"}] from RDAP details {registrar, reregistered_at, ...} and the suffix."""
    out: list[dict] = []
    details = details or {}
    if tld_prior(suffix):
        out.append({"signal": "high_abuse_suffix", "weight": TLD_PRIOR_WEIGHT, "data": {"suffix": suffix},
                    "summary": f"Registered under .{suffix}, an inexpensive suffix heavily used for throwaway infrastructure. A weak signal on its own: plenty of honest sites use it."})
    rereg = _dt(details.get("reregistered_at"))
    if rereg and (now - rereg).days <= REREGISTRATION_WINDOW_DAYS:
        out.append({"signal": "reregistered", "weight": REREGISTRATION_WEIGHT, "data": {"reregistered_at": rereg.isoformat()},
                    "summary": f"This name was dropped and registered again {max((now - rereg).days, 0)} day(s) ago — how attackers catch a lapsed domain that already has a history."})
    if details.get("registrar"):
        out.append({"signal": "registrar", "weight": 0.0, "data": {"registrar": details["registrar"]},
                    "summary": f"Registered through {details['registrar']} — where to send an abuse report. Shown for reference; it is not scored."})
    return out


def cert_timing_finding(registered_at, cert_issued_at, now: datetime, issuer: str | None = None) -> dict | None:
    """A TLS certificate within CERT_FAST_HOURS of a RECENT registration reads as an automated set-up."""
    reg, cert = _dt(registered_at), _dt(cert_issued_at)
    if not reg or not cert or cert < reg or (now - reg).days > CERT_REGISTRATION_RECENT_DAYS:
        return None
    hours = (cert - reg).total_seconds() / 3600
    if hours > CERT_FAST_HOURS:
        return None
    when = f"{round(hours * 60)} minute(s)" if hours < 2 else f"{round(hours)} hour(s)"
    return {"signal": "cert_after_registration", "weight": CERT_AFTER_REGISTRATION_WEIGHT, "data": {"hours": round(hours, 2), "issuer": issuer},
            "summary": f"A TLS certificate was issued {when} after the domain was registered — the pace of an automated set-up, not a site that grew over time."}


def hosting_finding(cname_target: str | None, platform_suffix: str | None) -> dict | None:
    """The look-alike's www name is a CNAME to a free site/app host (`platform_suffix` is the platform, resolved by the caller
    from the Public Suffix List's private section; only the FREE_SITE_HOSTS count — a CDN or cloud edge is not "free hosting")."""
    if not cname_target or platform_suffix not in FREE_SITE_HOSTS:
        return None
    return {"signal": "free_platform_cname", "weight": FREE_PLATFORM_CNAME_WEIGHT, "data": {"target": cname_target, "platform": platform_suffix},
            "summary": f"Its website is a CNAME to a free hosting platform ({platform_suffix}) — costs nothing to create and any takedown goes to the platform."}


@dataclass
class ClusterMember:
    registered_at: datetime | None = None
    ns: tuple = ()
    a: tuple = ()
    cert_ids: frozenset = frozenset()
    benign: bool = False          # on the customer's own infrastructure, or parked-and-locked
    shared_ns: bool = False       # nameservers are a shared DNS platform (parking, Cloudflare...) — proves little


def _benign_note(members: dict[str, ClusterMember], group: list[str]) -> str | None:
    friendly = [d for d in group if members[d].benign]
    if not friendly:
        return None
    return (f"{friendly[0]} sits on your own infrastructure (or is parked so nobody can send as it), so this may be your own defensive batch — not counted as evidence.")


def cluster_hints(members: dict[str, ClusterMember], *, shared_hosting_ips: frozenset = frozenset()) -> dict[str, list[dict]]:
    """For each member, the clusters it belongs to among look-alikes of the same brand:
    {domain: [{"signal","kind","weight","size","siblings","summary","data"}]}. `members` must already be limited to
    names that resemble the brand — clustering unrelated registered permutations would be noise."""
    hints: dict[str, list[dict]] = {d: [] for d in members}

    def emit(domain: str, group: list[str], signal: str, kind: str, weight: float, text: str, value=None) -> None:
        siblings = sorted(x for x in group if x != domain)
        note = _benign_note(members, group)
        hints[domain].append({
            "signal": signal, "kind": kind, "weight": 0.0 if note else weight, "size": len(group), "siblings": siblings[:_MAX_SIBLINGS],
            "summary": text.format(n=len(siblings)) + (f" {note}" if note else ""), "data": {"kind": kind, "size": len(group), "siblings": siblings[:_MAX_SIBLINGS], "value": value},
        })

    # registered in the same batch (time proximity, per member so a long chain is judged by its neighbours)
    timed = {d: m.registered_at for d, m in members.items() if m.registered_at}
    for d, when in timed.items():
        group = sorted(x for x, t in timed.items() if abs(t - when) <= BATCH_WINDOW)
        if len(group) >= 2:
            weight = WEIGHT_BATCH_MANY if len(group) >= 3 else WEIGHT_BATCH_PAIR
            emit(d, group, "batch_registered", "registration_batch", weight,
                 "Registered within 30 minutes of {n} other look-alike(s) of your brand — attackers register in batches. (Owners defending a brand do too.)")

    # one certificate covering several look-alikes
    by_cert: dict[str, list[str]] = {}
    for d, m in members.items():
        for cid in m.cert_ids:
            by_cert.setdefault(cid, []).append(d)
    for cid, group in by_cert.items():
        if len(group) >= 2:
            for d in group:
                emit(d, sorted(group), "shared_certificate", "shared_certificate", WEIGHT_SHARED_CERT,
                     "The same TLS certificate covers {n} other look-alike(s) of your brand — set up by one operator.", value=cid)

    # identical nameserver sets (not a shared DNS platform: parking and CDN pairs are shared by thousands of unrelated sites)
    by_ns: dict[tuple, list[str]] = {}
    for d, m in members.items():
        if m.ns and not m.shared_ns:
            by_ns.setdefault(tuple(sorted(m.ns)), []).append(d)
    for ns, group in by_ns.items():
        if len(group) >= MIN_SHARED_NS_MEMBERS:
            for d in group:
                emit(d, sorted(group), "shared_nameservers_cluster", "shared_nameservers", WEIGHT_SHARED_NS,
                     "{n} other look-alike(s) of your brand use the same nameservers (" + ", ".join(ns[:2]) + ").", value=list(ns[:3]))

    # the same server address (not a known shared-hosting address)
    by_ip: dict[str, list[str]] = {}
    for d, m in members.items():
        for ip in m.a:
            if ip not in shared_hosting_ips:
                by_ip.setdefault(ip, []).append(d)
    for ip, group in by_ip.items():
        if len(group) >= MIN_SHARED_SERVER_MEMBERS:
            for d in group:
                emit(d, sorted(group), "shared_server_cluster", "shared_server", WEIGHT_SHARED_SERVER,
                     "{n} other look-alike(s) of your brand are served from the same address (" + ip + ").", value=ip)

    for d, found in hints.items():             # cluster evidence can raise suspicion by a bounded amount, never decide it alone
        total = sum(h["weight"] for h in found if h["weight"] > 0)
        if total > CLUSTER_POSITIVE_CAP:
            scale = CLUSTER_POSITIVE_CAP / total
            for h in found:
                if h["weight"] > 0:
                    h["weight"] = round(h["weight"] * scale, 1)
    return {d: h for d, h in hints.items() if h}
