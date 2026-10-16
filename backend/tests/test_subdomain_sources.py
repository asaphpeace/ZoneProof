"""
The domain's own records, wildcard filtering and the unlisted-subdomain coverage
check. DNS is stubbed so the tests need no network.
"""
import dns.exception
import pytest

from app.services import subdomain_discovery_service as svc


class _Rdata:
    def __init__(self, text=None, strings=None, exchange=None, target=None):
        self._text = text
        self.strings = strings or []
        self.exchange = exchange
        self.target = target

    def to_text(self):
        return self._text or ""


class _FakeResolver:
    """name+type -> list of rdata; anything else does not exist."""
    def __init__(self, table):
        self.table = table
        self.calls = []

    async def resolve(self, name, rdtype):
        self.calls.append((name, rdtype))
        got = self.table.get((name.rstrip(".").lower(), rdtype))
        if got is None:
            raise dns.exception.DNSException("NXDOMAIN")
        return got


def _txt(s):
    return _Rdata(strings=[s.encode()])


@pytest.mark.asyncio
async def test_own_records_found_from_mx_spf_dmarc_srv_and_mta_sts(monkeypatch):
    d = "acme.test"
    table = {
        (d, "MX"): [_Rdata(exchange="mx1.mail.acme.test.")],
        (d, "TXT"): [_txt("v=spf1 include:spf.acme.test a:relay.acme.test include:_spf.google.com -all")],
        ("spf.acme.test", "TXT"): [_txt("v=spf1 a:bulk.acme.test include:other.acme.test ~all")],
        ("other.acme.test", "TXT"): [_txt("v=spf1 ip4:1.2.3.4 -all")],
        ("_dmarc." + d, "TXT"): [_txt("v=DMARC1; p=none; rua=mailto:dmarc@reports.acme.test,mailto:x@elsewhere.example")],
        ("_smtp._tls." + d, "TXT"): [_txt("v=TLSRPTv1; rua=https://tls.acme.test/report")],
        ("_autodiscover._tcp." + d, "SRV"): [_Rdata(target="autodiscover.acme.test.")],
        ("mta-sts." + d, "A"): [_Rdata(text="203.0.113.7")],
    }
    monkeypatch.setattr(svc, "resolver", _FakeResolver(table))
    got = await svc._from_own_records(d)
    assert got == {
        "mx1.mail.acme.test", "spf.acme.test", "relay.acme.test", "bulk.acme.test", "other.acme.test",
        "reports.acme.test", "tls.acme.test", "autodiscover.acme.test", "mta-sts.acme.test",
    }


@pytest.mark.asyncio
async def test_spf_follow_is_bounded(monkeypatch):
    d = "loop.test"
    table = {
        (d, "TXT"): [_txt("v=spf1 include:a.loop.test -all")],
        ("a.loop.test", "TXT"): [_txt("v=spf1 include:b.loop.test -all")],
        ("b.loop.test", "TXT"): [_txt("v=spf1 include:a.loop.test -all")],   # cycle
    }
    monkeypatch.setattr(svc, "resolver", _FakeResolver(table))
    assert await svc._from_own_records(d) == {"a.loop.test", "b.loop.test"}


@pytest.mark.asyncio
async def test_wildcard_zone_does_not_report_every_guess(monkeypatch):
    d = "wild.test"

    class _Wild(_FakeResolver):
        async def resolve(self, name, rdtype):
            name = name.rstrip(".").lower()
            if rdtype == "A" and name.endswith("." + d):
                if name == "mail." + d:
                    return [_Rdata(text="198.51.100.9")]       # a real, different host
                return [_Rdata(text="203.0.113.1")]            # wildcard
            raise dns.exception.DNSException("none")

    monkeypatch.setattr(svc, "resolver", _Wild({}))
    hosts, wildcard = await svc._probe_active(d)
    assert wildcard is True
    assert hosts == {"mail." + d}


@pytest.mark.asyncio
async def test_no_wildcard_reports_resolving_names(monkeypatch):
    d = "plain.test"
    table = {("smtp." + d, "A"): [_Rdata(text="198.51.100.2")], ("vpn." + d, "CNAME"): [_Rdata(text="x.host.test.")]}
    monkeypatch.setattr(svc, "resolver", _FakeResolver(table))
    hosts, wildcard = await svc._probe_active(d)
    assert wildcard is False
    assert hosts == {"smtp." + d, "vpn." + d}


def test_wordlist_is_bounded_and_email_scoped():
    """Guards against this growing into a generic brute-force list."""
    names = svc._ACTIVE_CANDIDATES
    assert len(names) <= 75
    assert len(names) == len(set(names))
    assert {"mail", "smtp", "autodiscover", "mta-sts", "imap"} <= set(names)
    for generic in ("www", "dev", "test", "admin", "staging", "api", "git", "jenkins"):
        assert generic not in names


@pytest.mark.parametrize("record,level,mentions", [
    (None, "open", "No DMARC record"),
    ("v=DMARC1; p=reject", "protected", "p=reject"),
    ("v=DMARC1; p=reject; sp=none", "open", "sp=none"),
    ("v=DMARC1; p=none; sp=reject", "protected", "sp=reject"),
    ("v=DMARC1; p=quarantine; pct=50", "partial", "50%"),
    ("v=DMARC1; p=none", "open", "p=none"),
])
def test_coverage_levels(record, level, mentions):
    out = svc.coverage_from_record(record)
    assert out["level"] == level
    assert mentions in out["summary"]


def test_np_overrides_for_names_that_do_not_exist():
    out = svc.coverage_from_record("v=DMARC1; p=none; sp=none; np=reject")
    assert out["effective_subdomain_policy"] == "reject"
    assert out["np_policy"] == "reject"


def test_email_addresses_and_free_text_are_not_subdomains():
    """Certificate name fields can hold an email address; it is not a hostname."""
    from app.services.subdomain_discovery_service import _is_subdomain
    assert _is_subdomain("webmaster@systemlogistik.dpd.com", "dpd.com") is False
    assert _is_subdomain("not a host.dpd.com", "dpd.com") is False
    assert _is_subdomain("_dmarc.dpd.com", "dpd.com") is True
    assert _is_subdomain("a-b.c1.dpd.com", "dpd.com") is True
