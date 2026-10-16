"""
Brand Guard — the customer's own infrastructure baseline and how a candidate compares to it (pure, no network).

Step 2.0 records what the customer's real domain looks like in DNS (nameservers, addresses, mail provider, network
owner). A look-alike that sits on the SAME nameservers or the SAME server address is far more likely to be the
customer's own defensive registration than an attacker's — a benign explainer that lowers its abuse score and tells
the analyst "this may be yours".

The guard that matters is SHARED platforms. A million sites share Cloudflare's addresses and a few hundred
nameserver pairs; "same IP as the customer" proves nothing when the customer is on one. So:
  * address matches count only when the customer's own address is NOT on a shared platform;
  * nameserver matches on a shared DNS platform count for much less.
These weights are hand-set heuristics, to be calibrated in Stage 3 (abuse scoring cannot be measured offline).
"""
from __future__ import annotations

# Substrings of a network owner's name (from the ASN registry) that mean "many unrelated customers share this address".
SHARED_HOSTING_ASN_MARKERS = (
    "cloudflare", "akamai", "fastly", "amazon", "aws", "google", "microsoft", "azure", "godaddy", "digitalocean", "ovh",
    "hetzner", "linode", "vultr", "namecheap", "hostinger", "squarespace", "wix", "shopify", "automattic", "github",
    "netlify", "vercel", "heroku", "incapsula", "imperva", "sucuri", "stackpath", "bunny", "alibaba", "tencent",
    "xneelo", "afrihost", "web africa", "webafrica", "hostafrica", "domains.co.za", "host europe", "ionos", "1&1",
)
# Nameserver domains of DNS platforms whose nameserver SET is shared among many accounts.
SHARED_NS_MARKERS = (
    "cloudflare.com", "awsdns", "azure-dns", "domaincontrol.com", "registrar-servers.com", "googledomains.com", "google.com",
    "wixdns.net", "squarespacedns.com", "nsone.net", "dnsimple.com", "ns.cloudflare", "hostgator", "bluehost", "ionos", "1and1",
    "afrihost", "xneelo", "hetzner", "hosting.co.za", "dns-parking.com", "sedoparking.com", "bodis.com",
)

# MX host suffix -> provider name.
MAIL_PROVIDERS = (
    ("protection.outlook.com", "Microsoft 365"), ("mail.protection.outlook.com", "Microsoft 365"),
    ("aspmx.l.google.com", "Google Workspace"), ("googlemail.com", "Google Workspace"), (".google.com", "Google Workspace"),
    ("mimecast.com", "Mimecast"), ("pphosted.com", "Proofpoint"), ("ppe-hosted.com", "Proofpoint"), ("zoho.com", "Zoho Mail"),
    ("zohomail.com", "Zoho Mail"), ("secureserver.net", "GoDaddy"), ("icloud.com", "iCloud"), ("yandex.net", "Yandex"),
    ("barracudanetworks.com", "Barracuda"), ("registrar-servers.com", "Namecheap"), ("mailgun.org", "Mailgun"),
    ("messagingengine.com", "Fastmail"), ("proton.ch", "Proton"), ("protonmail.ch", "Proton"), ("hetzner.com", "Hetzner"),
    ("xneelo.co.za", "Xneelo"), ("mweb.co.za", "MWEB"), ("afrihost.com", "Afrihost"), ("hosting.co.za", "Hosting.co.za"),
)

SAME_NAMESERVERS_UNSHARED = -15.0
SAME_NAMESERVERS_SHARED = -5.0
SAME_ADDRESS = -15.0


def mail_provider(mx_hosts: list[str]) -> str | None:
    for host in mx_hosts or []:
        host = host.lower().rstrip(".")
        for suffix, name in MAIL_PROVIDERS:
            if host == suffix.lstrip(".") or host.endswith(suffix if suffix.startswith(".") else "." + suffix):
                return name
    return None


def is_shared_hosting(asn_name: str | None) -> bool:
    name = (asn_name or "").lower()
    return any(m in name for m in SHARED_HOSTING_ASN_MARKERS)


def is_shared_nameservers(ns: list[str]) -> bool:
    return any(m in n.lower() for n in ns or [] for m in SHARED_NS_MARKERS)


def shares_infrastructure(enrichment: dict, baseline: dict | None) -> list[dict]:
    """Findings where the candidate sits on the customer's own infrastructure. Each finding:
    {"signal": "same_nameservers" | "same_hosting_ip", "weight": float, "values": [...], "shared_platform": bool}."""
    if not baseline:
        return []
    out: list[dict] = []
    cand_ns = sorted({n.lower().rstrip(".") for n in enrichment.get("ns") or []})
    base_ns = sorted({n.lower().rstrip(".") for n in baseline.get("ns") or []})
    if cand_ns and cand_ns == base_ns:
        shared = bool(baseline.get("shared_nameservers")) or is_shared_nameservers(base_ns)
        out.append({"signal": "same_nameservers", "weight": SAME_NAMESERVERS_SHARED if shared else SAME_NAMESERVERS_UNSHARED,
                    "values": base_ns, "shared_platform": shared})
    cand_a = {a for a in enrichment.get("a") or []}
    common = sorted(cand_a & set(baseline.get("a") or []))
    if common and not (baseline.get("shared_hosting") or is_shared_hosting((baseline.get("asn") or {}).get("name"))):
        out.append({"signal": "same_hosting_ip", "weight": SAME_ADDRESS, "values": common, "shared_platform": False})
    return out
