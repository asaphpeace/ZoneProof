"""
Measure how much more common each abuse-side signal is among KNOWN-BAD young domains than among new registrations in general
(plan step 3.0: the measurement that Stage 3 stands on).

Why this and not "calibration": abuse scoring cannot be calibrated offline against the Stage 1 corpus, because it needs live DNS,
registration age and certificate facts that cannot be reconstructed for historical domains. What CAN be measured today, honestly, is a
likelihood ratio per signal:

    LR+(s) = P(signal present | known-bad, recently registered) / P(signal present | any new registration)

  bad         registered domains currently listed by phishunt.io or abuse.ch URLhaus (public, CC0, NOT human-verified), excluding
              popular sites and names under hosting platforms; restricted to those registered within BAD_MAX_AGE_DAYS for the headline
  background  a random sample of the WhoisDS "newly registered domains" list (registered yesterday: age is held roughly equal by
              construction), which is mostly benign but contains unlisted malicious names, so every ratio is biased TOWARD 1
              (conservative: it understates how bad the bad signals are)

What this does NOT give: a probability. A ratio needs a prior (how common abuse is among look-alikes of a given brand), and no data
we have measures that, so the prior stays an explicit, labelled assumption in the combiner. Also: listed domains are the ones feeds
can see, many are already dead (so "resolves" is biased low for them), and registration-age and certificate-timing signals cannot
be backfilled for historical hosts, so they are NOT measured here.

    python -m brand_eval.abuse_lr                       # collect (live DNS + RDAP) and write the report
    python -m brand_eval.abuse_lr --bad 600 --background 2500
"""
from __future__ import annotations

import argparse
import asyncio
import json
import math
import random
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

OUT_DIR = Path(__file__).resolve().parent.parent / "data" / "brand_guard_corpus" / "abuse_lr"
BAD_MAX_AGE_DAYS = 30
DNS_CONCURRENCY = 40
RDAP_CONCURRENCY = 5


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return 0.0, 1.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return max(0.0, (c - h) / d), min(1.0, (c + h) / d)


def likelihood_ratio(k1: int, n1: int, k0: int, n0: int, z: float = 1.96) -> dict:
    """LR+ = (k1/n1)/(k0/n0) with a Katz log-interval (0.5 added to each cell so zeros do not blow it up), and LR- for the signal being absent."""
    def ratio(a, na, b, nb):
        a, b = a + 0.5, b + 0.5
        na, nb = na + 1, nb + 1
        r = (a / na) / (b / nb)
        se = math.sqrt(1 / a - 1 / na + 1 / b - 1 / nb)
        return r, r * math.exp(-z * se), r * math.exp(z * se)

    pos = ratio(k1, n1, k0, n0)
    neg = ratio(n1 - k1, n1, n0 - k0, n0)
    return {"lr_pos": pos[0], "lr_pos_lo": pos[1], "lr_pos_hi": pos[2], "lr_neg": neg[0], "lr_neg_lo": neg[1], "lr_neg_hi": neg[2]}


def separated(k1: int, n1: int, k0: int, n0: int) -> bool:
    """True when the 95% Wilson intervals of the two rates do not overlap (the project's standard for calling a difference real)."""
    lo1, hi1 = wilson(k1, n1)
    lo0, hi0 = wilson(k0, n0)
    return lo1 > hi0 or lo0 > hi1


# ── collection ───────────────────────────────────────────────────────────────

async def fetch_bad(client: httpx.AsyncClient, want: int, rng: random.Random) -> list[str]:
    from app.services import brand_feeds, brand_popularity
    from app.services.brand_discovery_service import platform_suffix, registrable_domain

    hosts: set[str] = set()
    for feed in brand_feeds.FEEDS:
        text = await brand_feeds._download(client, feed.url)
        hosts |= set(feed.parse(text))
    apexes: set[str] = set()
    for h in hosts:
        if platform_suffix(h):
            continue
        a = registrable_domain(h)
        if "." not in a or brand_popularity.rank_of(a) is not None:
            continue
        apexes.add(a)
    pool = sorted(apexes)
    rng.shuffle(pool)
    return pool[:want * 2]                      # extra: some will not have a usable registration date


async def fetch_background(client: httpx.AsyncClient, want: int, rng: random.Random) -> list[str]:
    from app.services import brand_nrd
    from datetime import date

    today = datetime.now(timezone.utc).date()
    for back in (1, 2, 3):
        try:
            data = await brand_nrd._download(client, brand_nrd.url_for(today - timedelta(days=back)))
            names = sorted(brand_nrd.parse_zip(data))
            rng.shuffle(names)
            return names[:want]
        except Exception as e:                  # try the previous day's list
            print(f"  newly-registered list for -{back}d unavailable: {e}", file=sys.stderr)
    raise SystemExit("no newly-registered list could be downloaded")


async def features_for(domain: str, sem: asyncio.Semaphore) -> dict:
    """Public facts about one domain, from the same functions a scan uses (so the signals are the real ones)."""
    from app.services import brand_guard_service as svc, brand_mail_intent as mi
    from app.services.brand_baseline import is_shared_nameservers, mail_provider
    from app.services.brand_corroboration import parking_service
    from app.services.brand_discovery_service import split_registrable
    from app.services.brand_infra_signals import FREE_SITE_HOSTS
    from app.services.brand_scoring_service import _LURE_WORDS

    out: dict = {"domain": domain}
    async with sem:
        dns_ = await svc._dns_enrich(domain)
        out.update(registered=dns_["registered"], has_a=dns_["has_a"], has_mx=dns_["has_mx"])
        if dns_["registered"]:
            mail = await svc._probe_mail(domain, dns_["mx"]) if dns_["has_mx"] or dns_["has_a"] else None
            findings = {f["signal"] for f in (mi.intent_findings(mail) if mail else [])}
            host = await svc._probe_hosting(domain)
            out.update(
                spf=bool(mail and mail.get("spf")), dmarc=bool(mail and mail.get("dmarc")),
                dkim=bool(mail and mail.get("dkim_selectors")), esp=("esp_sender" in findings), defensive_mail=("defensive_mail_posture" in findings),
                shared_ns=is_shared_nameservers(dns_["ns"]), parked=bool(parking_service(dns_["ns"])),
                free_cname=bool(host and host.get("platform") in FREE_SITE_HOSTS),
            )
    label, tld = split_registrable(domain)
    out.update(tld=tld, lure=any(w in label for w in _LURE_WORDS), hyphens=label.count("-"), digits=sum(c.isdigit() for c in label),
               long_label=len(label) >= 20)
    return out


async def registration_age_days(client: httpx.AsyncClient, domain: str, sem: asyncio.Semaphore) -> int | None:
    from app.services.domain_age_service import lookup_registration_details

    async with sem:
        try:
            info = await lookup_registration_details(client, domain)
        except Exception:
            return None
    if info is None or info.registered_at is None:
        return None
    return max(0, (datetime.now(timezone.utc) - info.registered_at).days)


async def collect(n_bad: int, n_bg: int, seed: int) -> dict:
    rng = random.Random(seed)
    async with httpx.AsyncClient(timeout=30, follow_redirects=True, headers={"User-Agent": "ZoneProof-BrandGuard/1.0 (research)"}) as client:
        print("downloading the abuse feeds and the newly-registered list ...")
        bad_pool = await fetch_bad(client, n_bad, rng)
        bg_pool = await fetch_background(client, n_bg, rng)
        print(f"  {len(bad_pool)} candidate bad names, {len(bg_pool)} background names")
        rdap_sem = asyncio.Semaphore(RDAP_CONCURRENCY)
        print("looking up registration dates for the listed names (RDAP) ...")
        ages = await asyncio.gather(*[registration_age_days(client, d, rdap_sem) for d in bad_pool])
    bad = [(d, a) for d, a in zip(bad_pool, ages) if a is not None][:n_bad]
    print(f"  {len(bad)} listed names have a registration date")
    dns_sem = asyncio.Semaphore(DNS_CONCURRENCY)
    print("collecting DNS / mail / hosting facts (this is the slow part) ...")
    bad_feats = await asyncio.gather(*[features_for(d, dns_sem) for d, _ in bad])
    for f, (_, age) in zip(bad_feats, bad):
        f["age_days"] = age
    bg_feats = await asyncio.gather(*[features_for(d, dns_sem) for d in bg_pool])
    return {"collected_at": datetime.now(timezone.utc).isoformat(), "seed": seed, "bad": bad_feats, "background": bg_feats}


# ── analysis ─────────────────────────────────────────────────────────────────

BINARY = [
    ("registered", "name exists in DNS"),
    ("has_a", "resolves to a server (A record)"),
    ("has_mx", "has mail servers (MX)"),
    ("spf", "publishes SPF"),
    ("dkim", "publishes a DKIM key"),
    ("dmarc", "publishes DMARC"),
    ("esp", "uses a bulk-mail (ESP) sender"),
    ("defensive_mail", "locked-down mail posture (null MX / -all / reject)"),
    ("shared_ns", "on a shared DNS platform"),
    ("parked", "nameservers of a parking service"),
    ("free_cname", "www is a CNAME to a free hosting platform"),
    ("lure", "name contains a credential/payment lure word"),
    ("long_label", "name label is 20+ characters"),
]


def rate_rows(bad: list[dict], bg: list[dict], *, only_registered: bool) -> list[dict]:
    """One row per feature. `only_registered` restricts both groups to names that exist in DNS (features that need DNS are only meaningful there)."""
    rows = []
    for key, text in BINARY:
        needs_dns = key in ("has_a", "has_mx", "spf", "dkim", "dmarc", "esp", "defensive_mail", "shared_ns", "parked", "free_cname")
        b = [f for f in bad if (f.get("registered") or not (only_registered and needs_dns))]
        g = [f for f in bg if (f.get("registered") or not (only_registered and needs_dns))]
        k1, n1 = sum(1 for f in b if f.get(key)), len(b)
        k0, n0 = sum(1 for f in g if f.get(key)), len(g)
        if n1 < 5 or n0 < 5:
            continue
        rows.append({"key": key, "text": text, "bad": [k1, n1], "background": [k0, n0], "bad_ci": wilson(k1, n1), "bg_ci": wilson(k0, n0),
                     "separated": separated(k1, n1, k0, n0), **likelihood_ratio(k1, n1, k0, n0)})
    # TLD: the handful of the most common suffixes in the bad set, against the background rate for the same suffix
    from collections import Counter
    tlds = Counter(f["tld"] for f in bad)
    for tld, _ in tlds.most_common(8):
        k1, n1 = sum(1 for f in bad if f["tld"] == tld), len(bad)
        k0, n0 = sum(1 for f in bg if f["tld"] == tld), len(bg)
        if k1 >= 5:
            rows.append({"key": f"tld:{tld}", "text": f"suffix .{tld}", "bad": [k1, n1], "background": [k0, n0], "bad_ci": wilson(k1, n1), "bg_ci": wilson(k0, n0),
                         "separated": separated(k1, n1, k0, n0), **likelihood_ratio(k1, n1, k0, n0)})
    return rows


def analyse(data: dict) -> dict:
    bad_all = data["bad"]
    bad_young = [f for f in bad_all if f.get("age_days") is not None and f["age_days"] <= BAD_MAX_AGE_DAYS]
    bg = data["background"]
    return {
        "counts": {"bad_all": len(bad_all), "bad_young": len(bad_young), "background": len(bg)},
        "young_vs_background": rate_rows(bad_young, bg, only_registered=True),
        "all_vs_background": rate_rows(bad_all, bg, only_registered=True),
        "age_buckets": {"<=7": sum(1 for f in bad_all if f["age_days"] <= 7), "8-30": sum(1 for f in bad_all if 7 < f["age_days"] <= 30),
                        "31-365": sum(1 for f in bad_all if 30 < f["age_days"] <= 365), ">365": sum(1 for f in bad_all if f["age_days"] > 365)},
        "resolution": {
            "bad_young_registered": [sum(1 for f in bad_young if f.get("registered")), len(bad_young)],
            "background_registered": [sum(1 for f in bg if f.get("registered")), len(bg)],
        },
    }


# ── the table the scorer reads ───────────────────────────────────────────────

# which scoring signal each measured feature stands for
SIGNAL_FOR = {
    "has_a": "dns_live", "has_mx": "mx_live", "spf": "spf_published", "dkim": "dkim_published", "dmarc": "dmarc_published",
    "esp": "esp_sender", "defensive_mail": "defensive_mail_posture", "parked": "parked", "free_cname": "free_platform_cname",
    "lure": "credential_lure_word", "high_abuse_suffix": "high_abuse_suffix",
}
# Properties of the NAME or the DNS provider do not depend on how old the listed domain is, so the larger all-ages comparison is
# used for them. Everything else is judged on the young group only: an old listed site is usually a compromised honest one, whose
# mail and hosting look nothing like a fresh attacker registration.
AGE_INDEPENDENT = {"esp", "parked", "free_cname", "lure"}
NULL_LO, NULL_HI = 0.5, 2.0            # an interval inside this is "measured: no effect"; a wider one that includes 1 is "not enough data"


def classify(row: dict) -> tuple[str, float, str]:
    """(status, ln_lr, note). measured: the interval excludes 1, so the CONSERVATIVE end is used. null: the interval includes 1 but is
    narrow, so the signal measurably does not separate (contributes nothing). unmeasured: too little data to say."""
    lo, hi, r = row["lr_pos_lo"], row["lr_pos_hi"], row["lr_pos"]
    k1, n1 = row["bad"]
    k0, n0 = row["background"]
    where = f"{k1}/{n1} listed vs {k0}/{n0} new registrations; LR+ {r:.2f} ({lo:.2f}-{hi:.2f})"
    if lo > 1.0:
        return "measured", math.log(lo), f"measured: lower bound {lo:.2f}; {where}"
    if hi < 1.0:
        return "measured", math.log(hi), f"measured (points the other way): upper bound {hi:.2f}; {where}"
    if NULL_LO <= lo and hi <= NULL_HI:
        return "null", 0.0, f"measured: does not separate; {where}"
    return "unmeasured", 0.0, f"not enough data to say; {where}"


def with_high_abuse_suffix(feats: list[dict]) -> list[dict]:
    from app.services.brand_infra_signals import HIGH_ABUSE_SUFFIXES
    for f in feats:
        f["high_abuse_suffix"] = f.get("tld", "").rsplit(".", 1)[-1] in HIGH_ABUSE_SUFFIXES and "." not in f.get("tld", "")
    return feats


def export_table(data: dict) -> dict:
    bad_all = with_high_abuse_suffix(data["bad"])
    bg = with_high_abuse_suffix(data["background"])
    young = [f for f in bad_all if f.get("age_days") is not None and f["age_days"] <= BAD_MAX_AGE_DAYS]
    sig_rows = lambda bad: {r["key"]: r for r in rate_rows(bad, bg, only_registered=True)}      # noqa: E731
    from_young, from_all = sig_rows(young), sig_rows(bad_all)
    # rate_rows only knows BINARY; add the derived suffix feature the same way
    for rows, group in ((from_young, young), (from_all, bad_all)):
        k1, n1 = sum(1 for f in group if f.get("high_abuse_suffix")), len(group)
        k0, n0 = sum(1 for f in bg if f.get("high_abuse_suffix")), len(bg)
        rows["high_abuse_suffix"] = {"key": "high_abuse_suffix", "bad": [k1, n1], "background": [k0, n0], **likelihood_ratio(k1, n1, k0, n0)}
    signals: dict[str, dict] = {}
    unmeasured: dict[str, str] = {}
    for feature, signal in SIGNAL_FOR.items():
        group, rows = ("all ages", from_all) if feature in AGE_INDEPENDENT else (f"registered within {BAD_MAX_AGE_DAYS} days", from_young)
        row = rows.get(feature)
        if row is None:
            unmeasured[signal] = f"too few listed names to compare ({group})"
            continue
        status, ln, note = classify(row)
        if status == "unmeasured":
            unmeasured[signal] = f"{note} [{group}]"
            continue
        signals[signal] = {"ln_lr": round(ln, 4), "basis": "measured", "group": group, "null": status == "null", "note": f"{note} [{group}]"}
    return {"measured_on": data["collected_at"][:10], "bad_young": len(young), "bad_all": len(bad_all), "background": len(bg),
            "signals": signals, "unmeasured": unmeasured,
            "how_to_read": "ln_lr is the natural log of the conservative likelihood ratio; points = 10 * ln_lr. Signals in `unmeasured` keep their hand-set weight and are marked as assumed."}


def pct(x: float) -> str:
    return f"{100 * x:.1f}%"


def render(a: dict, collected_at: str) -> str:
    c = a["counts"]
    lines = [
        "# Brand Guard — abuse-signal likelihood ratios (step 3.0)", "",
        f"Collected {collected_at[:16]}Z. Produced by `python -m brand_eval.abuse_lr`; the raw per-domain records stay in the gitignored `backend/data/brand_guard_corpus/abuse_lr/`.", "",
        "**What is measured.** For each signal: how much more often it appears on *known-bad, recently registered* domains than on *new registrations in general*. "
        "Bad = currently listed by phishunt.io or abuse.ch URLhaus (automated, NOT human-verified; popular sites and hosting-platform names excluded). "
        "Background = a random sample of yesterday's newly registered domains, which is mostly benign but contains unlisted malicious names, so every ratio is biased **toward 1** (it understates the signal).", "",
        f"Sizes: {c['bad_all']} listed names with a registration date ({c['bad_young']} registered within {BAD_MAX_AGE_DAYS} days = the headline group), {c['background']} background names.", "",
        f"Age of the listed names: ≤7 d {a['age_buckets']['<=7']}, 8-30 d {a['age_buckets']['8-30']}, 31-365 d {a['age_buckets']['31-365']}, >1 y {a['age_buckets']['>365']}. "
        "Most listed names are NOT new registrations (compromised older sites), which is why the headline group is restricted to young ones.", "",
        "**What this is not.** It is not a probability: a ratio needs a prior (how common abuse is among look-alikes of a brand), and nothing we have measures that. "
        "Registration age and certificate timing cannot be reconstructed for historical hosts, so they are not measured here. Listed domains are the ones feeds can see; many are already dead, which lowers every DNS-derived rate for them.", "",
    ]
    r = a["resolution"]
    lines += [f"Exist in DNS today: listed young {r['bad_young_registered'][0]}/{r['bad_young_registered'][1]} ({pct(r['bad_young_registered'][0] / max(1, r['bad_young_registered'][1]))}), "
              f"background {r['background_registered'][0]}/{r['background_registered'][1]} ({pct(r['background_registered'][0] / max(1, r['background_registered'][1]))}). Features that need DNS are compared among names that exist.", ""]
    for title, key in (("Headline: listed names registered within 30 days vs new registrations", "young_vs_background"), ("Context: ALL listed names (any age) vs new registrations", "all_vs_background")):
        lines += [f"## {title}", "", "| Signal | Listed | New registrations | LR+ (95% interval) | LR− | Intervals separate? |", "|---|---|---|---|---|---|"]
        for row in a[key]:
            k1, n1 = row["bad"]
            k0, n0 = row["background"]
            lines.append(f"| {row['text']} | {pct(k1 / n1)} [{pct(row['bad_ci'][0])}-{pct(row['bad_ci'][1])}] ({k1}/{n1}) | {pct(k0 / n0)} [{pct(row['bg_ci'][0])}-{pct(row['bg_ci'][1])}] ({k0}/{n0}) | "
                         f"{row['lr_pos']:.2f} ({row['lr_pos_lo']:.2f}-{row['lr_pos_hi']:.2f}) | {row['lr_neg']:.2f} | {'**yes**' if row['separated'] else 'no'} |")
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--bad", type=int, default=500)
    ap.add_argument("--background", type=int, default=2500)
    ap.add_argument("--seed", type=int, default=20261002)
    ap.add_argument("--reuse", type=Path, help="analyse an existing collection instead of collecting again")
    ap.add_argument("--export", action="store_true", help="also write app/data/signal_ratios.json, the table the scorer reads")
    args = ap.parse_args(argv)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    if args.reuse:
        data = json.loads(args.reuse.read_text(encoding="utf8"))
    else:
        data = asyncio.run(collect(args.bad, args.background, args.seed))
        (OUT_DIR / f"collection_{data['collected_at'][:10]}.json").write_text(json.dumps(data), encoding="utf8")
    analysis = analyse(data)
    report = render(analysis, data["collected_at"])
    (OUT_DIR / "report.md").write_text(report, encoding="utf8")
    (OUT_DIR / "analysis.json").write_text(json.dumps(analysis, default=list), encoding="utf8")
    if args.export:
        table = export_table(data)
        target = Path(__file__).resolve().parent.parent / "app" / "data" / "signal_ratios.json"
        target.write_text(json.dumps(table, indent=2, sort_keys=True) + "\n", encoding="utf8")
        print(f"\nwrote {target}:{len(table['signals'])} measured signals, {len(table['unmeasured'])} left unmeasured")
        for name, e in sorted(table["signals"].items()):
            print(f"  {name:26s} ln LR {e['ln_lr']:+.3f} = {10 * e['ln_lr']:+.1f} points  ({'no effect' if e['null'] else 'effect'})")
        for name, why in sorted(table["unmeasured"].items()):
            print(f"  {name:26s} UNMEASURED: {why[:100]}")
    else:
        print(report)


if __name__ == "__main__":
    main()
