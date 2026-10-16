import base64
import time

import pytest

from app.services import brand_probe_protocol as pp

KEY = "k" * 32
BODY = b'{"a":1}'


def _sig(**kw):
    a = dict(key=KEY, method="POST", path="/probe-worker/claim", timestamp=str(time.time()), body=BODY)
    a.update(kw)
    return a["timestamp"], pp.sign(a["key"], a["method"], a["path"], a["timestamp"], a["body"])


def test_a_correctly_signed_fresh_request_verifies():
    ts, sig = _sig()
    assert pp.verify(KEY, "POST", "/probe-worker/claim", ts, BODY, sig)


@pytest.mark.parametrize("change", [
    dict(key="x" * 32), dict(method="GET"), dict(path="/probe-worker/other"), dict(body=b'{"a":2}'),
])
def test_any_change_to_the_signed_parts_breaks_it(change):
    ts, sig = _sig()
    args = dict(key=KEY, method="POST", path="/probe-worker/claim", timestamp=ts, body=BODY)
    args.update(change)
    assert not pp.verify(args["key"], args["method"], args["path"], args["timestamp"], args["body"], sig)


def test_stale_future_garbage_and_empty_key_are_refused():
    old = str(time.time() - 3600)
    ts, sig = _sig(timestamp=old)
    assert not pp.verify(KEY, "POST", "/probe-worker/claim", ts, BODY, sig)
    fut = str(time.time() + 3600)
    ts, sig = _sig(timestamp=fut)
    assert not pp.verify(KEY, "POST", "/probe-worker/claim", ts, BODY, sig)
    ts, sig = _sig()
    assert not pp.verify(KEY, "POST", "/probe-worker/claim", "nope", BODY, sig)
    assert not pp.verify("", "POST", "/probe-worker/claim", ts, BODY, pp.sign("", "POST", "/probe-worker/claim", ts, BODY))     # no key = API off
    assert not pp.verify(KEY, "POST", "/probe-worker/claim", ts, BODY, "")


def test_the_skew_boundary_is_inclusive_and_uses_the_supplied_clock():
    ts, sig = "1000", pp.sign(KEY, "POST", "/p", "1000", b"")
    assert pp.verify(KEY, "POST", "/p", ts, b"", sig, now=1000 + pp.SKEW_SECONDS)
    assert not pp.verify(KEY, "POST", "/p", ts, b"", sig, now=1000 + pp.SKEW_SECONDS + 1)


def test_clean_result_keeps_only_the_known_fields_and_types():
    raw = {"ok": True, "chain": [{"url": "http://a.xyz/", "status": 301, "evil": "x"}, {"url": "https://a.xyz/", "status": 200}], "final_status": 200,
           "content_type": "text/html", "html": "<html></html>", "elapsed_ms": 120, "shell": "rm -rf /", "__proto__": {"x": 1}}
    out = pp.clean_result(raw)
    assert set(out) == {"ok", "error", "chain", "final_status", "content_type", "truncated", "html", "favicon_b64", "cert_der_b64", "tls_error", "elapsed_ms", "render"}
    assert out["chain"] == [{"url": "http://a.xyz/", "status": 301}, {"url": "https://a.xyz/", "status": 200}] and "shell" not in out


def test_clean_result_rejects_wrong_types_and_oversize_values_without_repairing_them():
    out = pp.clean_result({"ok": "yes", "chain": "notalist", "final_status": "200", "elapsed_ms": 10**9, "html": 5, "favicon_b64": "!!!notb64", "cert_der_b64": base64.b64encode(b"x" * (pp.MAX_CERT_BYTES + 1)).decode()})
    assert out["ok"] is True and out["chain"] == [] and out["final_status"] is None and out["elapsed_ms"] is None and out["html"] is None
    assert out["favicon_b64"] is None and out["cert_der_b64"] is None
    assert pp.clean_result("garbage") == {"ok": False, "error": "invalid result"} and pp.clean_result(None)["ok"] is False


def test_clean_result_caps_the_chain_html_and_strips_control_characters():
    chain = [{"url": f"http://a{i}.xyz/", "status": 302} for i in range(50)]
    out = pp.clean_result({"chain": chain, "html": "x" * (pp.MAX_HTML_BYTES + 50), "error": "bad\x00\x1b[31m thing", "content_type": "text/html\r\nX-Evil: 1"})
    assert len(out["chain"]) == pp.MAX_CHAIN and len(out["html"]) == pp.MAX_HTML_BYTES
    assert "\x00" not in out["error"] and "\x1b" not in out["error"] and "\r" not in out["content_type"] and "\n" not in out["content_type"]


def test_status_codes_outside_http_range_and_booleans_are_not_accepted_as_numbers():
    out = pp.clean_result({"final_status": 99, "chain": [{"url": "u", "status": True}, {"url": "v", "status": 700}]})
    assert out["final_status"] is None and [h["status"] for h in out["chain"]] == [None, None]


def test_valid_base64_within_the_cap_is_kept():
    b = base64.b64encode(b"\x00\x01\x02").decode()
    assert pp.clean_result({"favicon_b64": b, "cert_der_b64": b})["favicon_b64"] == b


def test_booleans_are_not_numbers_even_where_one_is_a_valid_value():
    assert pp.clean_result({"elapsed_ms": True})["elapsed_ms"] is None and pp.clean_result({"elapsed_ms": 5})["elapsed_ms"] == 5


def test_base64_with_junk_characters_is_refused_not_silently_repaired():
    good = base64.b64encode(b"ABC").decode()
    assert pp.clean_result({"favicon_b64": good})["favicon_b64"] == good
    assert pp.clean_result({"favicon_b64": good + "!!!"})["favicon_b64"] is None and pp.clean_result({"cert_der_b64": "QUJD\nQUJD "})["cert_der_b64"] is None
