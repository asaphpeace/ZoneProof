"""
Brand Guard — candidate discovery (pure functions, no network).

Generates the domains an attacker might register to impersonate a brand, and
provides the normalisation primitives (confusable "skeletons", edit distance)
the scorer uses to decide how closely a *discovered* domain resembles the
protected one. Discovery is cheap and broad; classification (brand_scoring_
service.py) is what keeps it from drowning the customer in noise.

Kept dependency-free on purpose: the confusable map below is a curated subset
(Latin look-alikes plus the Cyrillic/Greek letters attackers actually use in
IDN homograph attacks), not the full Unicode TR39 table.
"""
from __future__ import annotations

import itertools
import re
import string
import unicodedata

from app.services import public_suffix as psl

# Characters that render (near-)identically to an ASCII letter. Keys are what
# an attacker types; values are the ASCII letter a human reads.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ԛ": "q", "ԝ": "w",
    # Greek
    "ο": "o", "ν": "v", "ρ": "p", "α": "a", "ι": "i", "τ": "t", "κ": "k",
    # Latin look-alikes
    "ı": "i", "ɑ": "a", "ɩ": "l", "ǀ": "l",
    # Digits that read as letters
    "0": "o", "1": "l", "5": "s", "3": "e", "8": "b",
}

# Multi-character sequences that read as one letter (applied after the
# single-character map, on the ASCII skeleton).
_SEQUENCE_CONFUSABLES = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m")]

# Substitutions to *generate* from an ASCII label (attacker's perspective).
_HOMOGLYPH_SUBSTITUTIONS: list[tuple[str, str]] = [
    ("o", "0"), ("l", "1"), ("i", "1"), ("i", "l"), ("l", "i"), ("e", "3"), ("s", "5"), ("a", "4"),
    ("rn", "m"), ("m", "rn"), ("vv", "w"), ("w", "vv"), ("cl", "d"),
    # IDN variants — encoded to punycode at emit time
    ("a", "а"), ("e", "е"), ("o", "о"), ("p", "р"), ("c", "с"), ("x", "х"), ("y", "у"), ("i", "і"),
]

# QWERTY neighbours for fat-finger substitutions.
_KEYBOARD_NEIGHBOURS = {
    "q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok",
    "o": "ipl", "p": "ol", "a": "qsz", "s": "awdx", "d": "sefc", "f": "drgv", "g": "fthb",
    "h": "gyjn", "j": "hukm", "k": "jil", "l": "kop", "z": "asx", "x": "zsdc", "c": "xdfv",
    "v": "cfgb", "b": "vghn", "n": "bhjm", "m": "njk",
}

# Words attackers bolt onto a brand to look like an official service.
COMBO_PREFIXES = ["login", "secure", "my", "portal", "account", "support", "online", "pay", "mail", "web"]
COMBO_SUFFIXES = [
    "login", "secure", "support", "portal", "account", "online", "pay", "payments", "billing",
    "help", "verify", "auth", "service", "app", "mail", "sa", "za",
]

# Lure words in the languages South African attackers actually write in. Phishing kits aimed at local banks and
# retailers put Afrikaans and Zulu service words next to the brand ("capitec-inteken", "fnb-akhawunti"), which an
# English-only word list never generates. CURATED BY HAND from common banking/login vocabulary and NOT yet reviewed
# by a native speaker (the plan lists that as a human task): treat these lists as a starting point.
LURE_WORDS_AFRIKAANS = [
    "inteken", "aanmeld", "rekening", "betaal", "betaling", "wagwoord", "veilig", "hulp", "diens", "toegang", "verifieer", "bevestig",
]
LURE_WORDS_ZULU = ["ngena", "ukungena", "akhawunti", "khokha", "ukukhokha", "usizo", "iphasiwedi"]
LOCAL_LURE_WORDS = LURE_WORDS_AFRIKAANS + LURE_WORDS_ZULU

# How a South African brand's ".co.za" gets imitated inside someone else's name: brand-co-za.com, brandcoza.com.
_CCTLD_MIMIC_TAILS = ("-co-za", "-coza", "coza", "-za")
_CCTLD_MIMIC_COLLAPSED = ("coza", "za")
# Registries that sell "za" as a suffix of its own: brand.za.com reads like a local site. (brand.co.za.com does not
# work as a registration: co.za.com is one shared name, so that is a subdomain case, handled elsewhere.)
_ZA_PRIVATE_SUFFIXES = ("za.com", "za.net", "za.org")

# Words a compound brand name is commonly built from. Used only to find the word boundary in "capitecbank" so the
# order can be swapped; a name that doesn't split is left alone (there is no dictionary here on purpose).
_COMPOUND_VOCAB = frozenset({
    "bank", "group", "first", "national", "standard", "capital", "mutual", "trust", "life", "insure", "insurance", "medical", "health",
    "pay", "cash", "money", "finance", "post", "mail", "mobile", "telecom", "energy", "motors", "online", "direct", "express", "global",
    "africa", "south", "cape", "town", "shop", "store", "market", "credit", "loans", "invest", "holdings", "services",
})

ALT_TLDS = [
    "com", "net", "org", "co", "io", "info", "online", "xyz", "co.za", "org.za", "net.za", "biz", "support", "app",
    # inexpensive suffixes heavily used for phishing infrastructure
    "top", "icu", "cfd", "sbs", "click", "link", "live", "site", "shop", "store", "vip", "club", "cc", "me", "us", "co.uk",
]

_LABEL_RE = re.compile(r"^[a-z0-9-]+$")
# Hard ceiling — a scan enumerates DNS for every candidate, so this bounds cost
# per profile per run. Ordering in generate_candidates() decides what survives.
MAX_CANDIDATES = 400



def split_registrable(domain: str) -> tuple[str, str]:
    """('acme', 'co.za') for 'acme.co.za'; ('brand', 'com.br') for 'x.brand.com.br'; ('x', 'pages.dev')
    for 'x.pages.dev'. Uses the Public Suffix List, so multi-label suffixes and hosting platforms are
    understood. Subdomains are ignored — brand impersonation is about the registrable name. A host that
    is itself a public suffix (or a single label) has no registrable name: ('', suffix)."""
    parts = psl.split(domain)
    if parts.registrable is None:
        return "", parts.suffix
    label = parts.registrable[: -(len(parts.suffix) + 1)] if parts.suffix else parts.registrable
    return label, parts.suffix


def registrable_domain(domain: str) -> str:
    """The registrable domain, or the normalised host itself when it has none (a bare suffix)."""
    parts = psl.split(domain)
    return parts.registrable or parts.host


def platform_suffix(domain: str) -> str | None:
    """The hosting-platform suffix (e.g. 'pages.dev') when the name lives under one, else None.
    Such a name is a subdomain on someone else's platform, not a registered domain."""
    parts = psl.split(domain)
    return parts.suffix if (parts.private and parts.registrable) else None


def to_ascii(domain: str) -> str | None:
    """IDNA/punycode encode; None when the string isn't a valid hostname."""
    try:
        return domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None


def to_unicode(domain: str) -> str:
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return domain


def skeleton(label: str) -> str:
    """Collapse a label to the ASCII string a human would *read* — used to
    decide whether two different labels are visually the same."""
    text = unicodedata.normalize("NFKC", to_unicode(label).lower())
    text = "".join(_CONFUSABLES.get(ch, ch) for ch in text)
    text = text.replace("-", "")
    for old, new in _SEQUENCE_CONFUSABLES:
        text = text.replace(old, new)
    return text


def has_non_ascii(label: str) -> bool:
    return any(ord(ch) > 127 for ch in to_unicode(label))


def edit_distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (adjacent transposition counts as one edit)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if not la:
        return lb
    if not lb:
        return la
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]


def similarity(a: str, b: str) -> float:
    """0..1, 1.0 = identical."""
    longest = max(len(a), len(b))
    return 1.0 - (edit_distance(a, b) / longest) if longest else 1.0


def _valid(candidate: str) -> bool:
    label, _, tld = candidate.partition(".")
    if not label or not tld or len(candidate) > 253 or len(label) > 63:
        return False
    if label.startswith("-") or label.endswith("-"):
        return False
    ascii_form = to_ascii(candidate)
    if not ascii_form:
        return False
    return bool(_LABEL_RE.match(ascii_form.split(".")[0]))


_LDH = frozenset(string.ascii_lowercase + string.digits + "-")

# A bit-squat only makes sense against a name people actually type or machines request in volume. On a 3-4 letter name
# nearly every one-bit neighbour is some unrelated registered domain (dpd -> lpd.com, tpd.com), which is pure noise.
BITSQUAT_MIN_LEN = 5

# (written, spelled-the-same-sound), applied one occurrence at a time. Number words are the classic text-speak forms.
_SOUND_SWAPS: list[tuple[str, str]] = [
    ("ph", "f"), ("f", "ph"), ("ck", "k"), ("c", "k"), ("k", "c"), ("s", "z"), ("z", "s"), ("x", "ks"), ("ks", "x"),
    ("y", "i"), ("i", "y"), ("ee", "ea"), ("ea", "ee"), ("oo", "u"), ("for", "4"), ("four", "4"), ("to", "2"), ("two", "2"),
    ("one", "1"), ("you", "u"), ("your", "ur"), ("are", "r"),
]
_SOUND_KEY_RULES: list[tuple[str, str]] = [
    ("ph", "f"), ("ck", "k"), ("ks", "x"), ("c", "k"), ("z", "s"), ("y", "i"), ("ee", "i"), ("ea", "i"), ("oo", "u"),
    ("4", "for"), ("2", "to"), ("1", "one"), ("8", "ate"),
]


def sound_key(label: str) -> str:
    """A rough 'how it sounds' form of a label, to see that two spellings are said the same way. Deliberately crude
    (English-ish rules, no pronunciation dictionary): it only has to separate 'kapitec' from 'capital'."""
    text = re.sub(r"[^a-z0-9]", "", to_unicode(label).lower())
    for old, new in _SOUND_KEY_RULES:
        text = text.replace(old, new)
    return re.sub(r"(.)\1+", r"\1", text)


def is_sound_alike(label: str, brand_label: str) -> bool:
    a, b = re.sub(r"[^a-z0-9]", "", label.lower()), re.sub(r"[^a-z0-9]", "", brand_label.lower())
    return len(b) >= 4 and a != b and sound_key(a) == sound_key(b)


def is_bit_flip(label: str, brand_label: str) -> bool:
    """Exactly one character differs, and the two characters differ in exactly one bit."""
    if len(label) != len(brand_label) or label == brand_label:
        return False
    diffs = [(x, y) for x, y in zip(label, brand_label) if x != y]
    if len(diffs) != 1:
        return False
    x = ord(diffs[0][0]) ^ ord(diffs[0][1])
    return x != 0 and x & (x - 1) == 0


def scripts_in(label: str) -> set[str]:
    """The writing systems used by the letters in a label (LATIN, CYRILLIC, GREEK, ...). Digits and hyphens belong to
    no script."""
    found: set[str] = set()
    for ch in to_unicode(label):
        if ch.isalpha():
            try:
                found.add(unicodedata.name(ch).split()[0])
            except ValueError:
                continue
    return found


def is_mixed_script(label: str) -> bool:
    """Letters from more than one alphabet in one name. Real brands almost never do this, and browsers show such
    names as punycode (xn--...) precisely because it is how spoofs are built."""
    return len(scripts_in(label)) > 1


def brand_words(label: str, brand_name: str | None = None) -> list[str]:
    """The words a brand name is made of, best effort: the words of the display name when they spell the domain label
    ('Standard Bank' -> standard, bank), else the hyphen-separated parts of the label, else a known word at either end
    of the label ('capitecbank' -> capitec, bank). A single word means the name does not split."""
    collapsed = re.sub(r"[^a-z0-9]", "", label.lower())
    named = [w for w in re.findall(r"[a-z0-9]+", (brand_name or "").lower()) if w]
    if len(named) >= 2 and "".join(named) == collapsed:
        return named
    parts = [p for p in label.lower().split("-") if p]
    if len(parts) >= 2:
        return parts
    for word in sorted(_COMPOUND_VOCAB, key=len, reverse=True):
        if collapsed.endswith(word) and len(collapsed) - len(word) >= 3:
            return [collapsed[: -len(word)], word]
        if collapsed.startswith(word) and len(collapsed) - len(word) >= 3:
            return [word, collapsed[len(word):]]
    return [collapsed] if collapsed else []


def word_order_match(label: str, words: list[str]) -> bool:
    """True when the label is the brand's words in a different order (hyphens ignored)."""
    if not (2 <= len(words) <= 3):
        return False
    collapsed = re.sub(r"[^a-z0-9]", "", label.lower())
    return any(collapsed == "".join(p) for p in itertools.permutations(words) if list(p) != words)


def cctld_mimic(label: str, tokens: list[str]) -> str | None:
    """'brand-co-za' / 'brandcoza' / 'brand-za': the brand followed by a local-country tail. Returns the tail that
    matched (collapsed), or None. Only the tail is judged here; whether the brand part is real is the caller's job."""
    collapsed = re.sub(r"[^a-z0-9]", "", label.lower())
    for token in tokens:
        token = re.sub(r"[^a-z0-9]", "", token.lower())
        if len(token) < 3 or not collapsed.startswith(token) or collapsed == token:
            continue
        rest = collapsed[len(token):]
        if rest in _CCTLD_MIMIC_COLLAPSED:
            return rest
    return None


def generate_candidates(
    primary_domain: str,
    brand_name: str | None = None,
    keywords: list[str] | None = None,
) -> dict[str, str]:
    """Returns {ascii_domain: threat_class}. Ordered by how likely an attacker
    is to actually register the class, so truncation at MAX_CANDIDATES drops
    the long tail, not the obvious ones."""
    label, tld = split_registrable(primary_domain)
    if not tld or len(label) < 3:
        return {}

    brand_tokens = {label}
    if brand_name:
        collapsed = re.sub(r"[^a-z0-9]", "", brand_name.lower())
        if len(collapsed) >= 3:
            brand_tokens.add(collapsed)
    words = [re.sub(r"[^a-z0-9]", "", k.lower()) for k in (keywords or [])]
    words = [w for w in words if len(w) >= 2]

    out: dict[str, str] = {}

    def add(candidate_label: str, cand_tld: str, klass: str) -> None:
        cand = f"{candidate_label}.{cand_tld}"
        ascii_form = to_ascii(cand)
        if not ascii_form or ascii_form == primary_domain or not _valid(cand):
            return
        out.setdefault(ascii_form, klass)

    # 1. Homoglyphs/IDN — highest-value class, hardest for humans to spot.
    for old, new in _HOMOGLYPH_SUBSTITUTIONS:
        if old in label:
            add(label.replace(old, new, 1), tld, "homoglyph")
            # Also the same-TLD-swapped variants for the two commonest TLDs
            for extra in ("com", "co.za"):
                if extra != tld:
                    add(label.replace(old, new, 1), extra, "homoglyph")

    # 2. Combosquats — brand + service words, hyphenated and joined.
    for token in brand_tokens:
        for word in COMBO_PREFIXES + words:
            add(f"{word}-{token}", tld, "combosquat")
            add(f"{word}{token}", tld, "combosquat")
        for word in COMBO_SUFFIXES + words:
            add(f"{token}-{word}", tld, "combosquat")
            add(f"{token}{word}", tld, "combosquat")
            if tld != "com":
                add(f"{token}-{word}", "com", "combosquat")

    # 2b. Imitating the local country suffix inside another name, and Afrikaans/Zulu service words: the patterns
    #     that target South African customers.
    for token in brand_tokens:
        for tail in _CCTLD_MIMIC_TAILS:
            add(f"{token}{tail}", "com", "cctld_mimic")
        for za in _ZA_PRIVATE_SUFFIXES:
            add(token, za, "cctld_mimic")
        for word in LOCAL_LURE_WORDS:
            add(f"{token}-{word}", tld, "combosquat")
            add(f"{token}{word}", tld, "combosquat")

    # 2c. The brand's own words in a different order ("bank-capitec").
    words = brand_words(label, brand_name)
    if 2 <= len(words) <= 3:
        for perm in itertools.permutations(words):
            if list(perm) != words:
                for joiner in ("", "-"):
                    add(joiner.join(perm), tld, "word_order")

    # 3. TLD swaps on the exact name.
    for token in brand_tokens:
        for alt in ALT_TLDS:
            if alt != tld:
                add(token, alt, "tld_swap")

    # 4. Typos — omission, duplication, transposition, fat-finger, hyphenation, vowel swap.
    for i in range(len(label)):
        add(label[:i] + label[i + 1:], tld, "typo")
        add(label[:i] + label[i] + label[i:], tld, "typo")
        for neighbour in _KEYBOARD_NEIGHBOURS.get(label[i], ""):
            add(label[:i] + neighbour + label[i + 1:], tld, "typo")
    for i in range(len(label) - 1):
        add(label[:i] + label[i + 1] + label[i] + label[i + 2:], tld, "typo")
    for i in range(1, len(label)):
        add(f"{label[:i]}-{label[i:]}", tld, "typo")
    add(f"{label}s", tld, "typo")

    # 5. Sound-alikes: spelled differently, said the same. Typos are accidents; these are chosen.
    for old, new in _SOUND_SWAPS:
        if old in label:
            add(label.replace(old, new, 1), tld, "soundsquat")

    # 6. Bit-squats: one flipped bit in a character of the name, which a memory error in a requesting device turns
    #    into a request for the wrong domain. Rare, but they need no mistake by the victim at all.
    for i, ch in enumerate(label if len(label) >= BITSQUAT_MIN_LEN else ""):
        for bit in range(8):
            flipped = chr(ord(ch) ^ (1 << bit))
            if flipped in _LDH and flipped != ch:
                add(label[:i] + flipped + label[i + 1:], tld, "bitsquat")

    return dict(list(out.items())[:MAX_CANDIDATES])


# Words attackers attach to a brand to look official — the generator's combo words plus a few more.
# Used to decide whether a SHORT brand token is "really there" next to them (see token_match).
_AFFIXES = frozenset(COMBO_PREFIXES) | frozenset(COMBO_SUFFIXES) | frozenset(LOCAL_LURE_WORDS) | frozenset({
    "id", "store", "care", "billing", "help", "cloud", "pro", "hub", "bank", "wallet", "safe", "verify", "update", "service",
    "services", "center", "centre", "official", "global", "group", "signin", "accounts", "app", "online", "refund", "rewards",
})


def _edit_budget(token_len: int) -> int:
    return 0 if token_len < 6 else 1 if token_len < 9 else 2


def token_match(label: str, token: str) -> str | None:
    """How a brand token appears in a registrable label, or None. Returns one of:
        "exact"      label is the token
        "substring"  token inside the label (tokens of 6+ letters: distinctive enough to match anywhere)
        "segment"    token is a whole hyphen-separated word (4-5 letter tokens, and 3-letter ones)
        "affix"      token fused with a common word: apple+support, secure+cash (4-5 letter tokens)
        "near"       a word within 1-2 edits of the token (6+ letters): a typo-squat
    Why the length tiers: short or common-word brands (`cash`, `apple`, `gls`) match half the internet
    as raw substrings — 'visitlancashire' is not about Cash App — but they do appear as whole words
    ('cash-app-login') or fused with lure words ('applesupport'). Long names are rare enough to match
    anywhere. This is a heuristic gate, measured against the evaluation corpus; it is not a wordlist."""
    token = re.sub(r"[^a-z0-9]", "", (token or "").lower())
    label = (label or "").lower()
    if len(token) < 3 or not label:
        return None
    if label == token:
        return "exact"

    segments = [x for x in label.split("-") if x]
    views = ((token, segments, label), (skeleton(token), [skeleton(x) for x in segments], skeleton(label)))
    for tok, segs, whole in views:
        if not tok:
            continue
        if len(tok) >= 6:
            if tok in whole:
                return "substring"
        elif len(tok) >= 4:
            for seg in segs:
                if seg == tok:
                    return "segment"
                # every affix form contains the token, so a segment without it cannot qualify: this guard skips the
                # |affixes|^2 comparison for the ~99% of segments that do not contain the token (identical results)
                if tok in seg and (any(seg in (a + tok, tok + a) for a in _AFFIXES) or any(seg == a + tok + b for a in _AFFIXES for b in _AFFIXES)):
                    return "affix"
        elif tok in segs:
            return "segment"

    budget = _edit_budget(len(token))
    if budget:
        for seg in segments:
            seg_n = re.sub(r"[^a-z0-9]", "", seg)
            if seg_n != token and abs(len(seg_n) - len(token)) <= budget and edit_distance(seg_n, token) <= budget:
                return "near"
    return None


def subdomain_brand_abuse(host: str, brand_tokens: list[str], official_domains: list[str]) -> dict | None:
    """Brand abuse hiding in the SUBDOMAIN of someone else's domain: 'paypal.com.secure-id.xyz' or
    'login-capitec.example.net'. The registrable name carries no resemblance, so name matching on it finds nothing,
    yet a victim reading the left end of the address sees the brand. Returns None, or
        {"kind": "official_domain_in_subdomain" | "brand_in_subdomain", "matched": ..., "subdomain": ..., "apex": ...}
    A host whose registrable label already shows the brand is NOT reported here — the ordinary rules own that — and
    neither is the customer's own domain. Software-as-a-service vendors give each customer a subdomain, so this is a
    weaker signal than a look-alike registration; the scorer weighs it accordingly."""
    parts = psl.split(host)
    if parts.registrable is None or not parts.subdomain or parts.is_ip:
        return None
    owned = {registrable_domain(d) for d in official_domains}
    if parts.registrable in owned:
        return None
    apex_label = split_registrable(host)[0]
    if any(token_match(apex_label, t) for t in brand_tokens if t):
        return None
    sub = parts.subdomain
    dotted, dashed = f".{sub}.", "-" + sub.replace(".", "-") + "-"
    for official in sorted(owned):
        if f".{official}." in dotted or "-" + official.replace(".", "-") + "-" in dashed:
            return {"kind": "official_domain_in_subdomain", "matched": official, "subdomain": sub, "apex": parts.registrable}
    for token in brand_tokens:
        if not token or len(token) < 3:
            continue
        for part in sub.split("."):
            if token_match(part, token) in ("exact", "substring", "segment", "affix"):
                return {"kind": "brand_in_subdomain", "matched": token, "subdomain": sub, "apex": parts.registrable}
    return None


def matches_brand_fingerprint(domain: str, brand_tokens: list[str], *, min_token_len: int = 3) -> str | None:
    """Used by CT monitoring: does this hostname's registrable label show the brand? Returns the
    matched token or None. Matching rules depend on the token's length — see token_match."""
    host_label = split_registrable(domain)[0]
    for token in brand_tokens:
        token = token.strip().lower()
        if len(token) < min_token_len:
            continue
        if token_match(host_label, token):
            return token
    return None


def brand_warnings(primary_domain: str, brand_name: str = "") -> list[str]:
    """Plain-language caveats about how well this brand can be matched by name."""
    label = split_registrable(primary_domain)[0]
    out: list[str] = []
    if not label:
        out.append("This domain is a public suffix or hosting platform, not a registrable brand domain.")
    elif len(label) <= 3:
        out.append("Very short brand names (3 letters or fewer) are matched only as whole words, e.g. 'gls-group', so look-alikes "
                   "where the name is merged into another word will be missed.")
    elif len(label) <= 5:
        out.append("Short brand names (4-5 letters) are matched as whole words or next to common words like 'login' or 'secure', "
                   "to avoid false alarms from ordinary words that contain them.")
    return out
