"""CT tile parsing (app/services/ct_tiles.py) and the log list (ct_log_list.py): pure, no network unless CT_LIVE=1."""
import os
from datetime import datetime, timezone

import pytest

from app.services import ct_log_list as ll, ct_tiles as t
from tests.ct_helpers import checkpoint, leaf, make_cert, tile

# ── paths and checkpoints ──

@pytest.mark.parametrize("index,path", [(0, "000"), (7, "007"), (999, "999"), (1000, "x001/000"), (1234067, "x001/x234/067"), (1000000, "x001/x000/000")])
def test_tile_path(index, path):
    assert t.tile_path(index) == path


def test_partial_tile_path_and_negative():
    assert t.partial_tile_path(1234067, 12) == "x001/x234/067.p/12"
    with pytest.raises(ValueError):
        t.tile_path(-1)


def test_checkpoint_parse():
    origin, size = t.parse_checkpoint("log.example/2026h2\n946048158\nroot=\n\n— sig\n")
    assert (origin, size) == ("log.example/2026h2", 946048158)


@pytest.mark.parametrize("text", ["", "only one line", "origin\nnotanumber\nroot\n", "origin\n-5\nroot\n", "\n10\nroot\n"])
def test_checkpoint_rejects_junk(text):
    with pytest.raises(t.TileError):
        t.parse_checkpoint(text)


# ── tiles ──

def test_x509_and_precert_entries_are_read():
    data = tile([(["Shop.Example.COM", "*.example.com"], 1_700_000_000_000, False), (["login.brand-pay.xyz"], 1_700_000_001_000, True)])
    got = t.parse_tile(data)
    assert [s.names for s in got] == [("shop.example.com", "example.com"), ("login.brand-pay.xyz",)]
    assert [s.precert for s in got] == [False, True]
    assert got[0].logged_at_ms == 1_700_000_000_000 and got[0].issuer == "Test CA" and len(got[0].sha256) == 64
    assert got[0].not_before == datetime(2026, 10, 1, tzinfo=timezone.utc)


def test_wildcards_are_stripped_and_names_deduplicated_and_lowered():
    s = t.sighting_from_der(make_cert(["*.a.example.com", "A.example.com", "b.example.com", "bad name.com", "nodot"]), 0, False)
    assert s.names == ("a.example.com", "b.example.com")


def test_subject_common_name_is_used_only_when_there_is_no_san():
    assert t.sighting_from_der(make_cert([], cn="only-cn.example.org", san=False), 0, False).names == ("only-cn.example.org",)
    assert t.sighting_from_der(make_cert(["san.example.org"], cn="other.example.org"), 0, False).names == ("san.example.org",)


def test_a_certificate_with_no_usable_names_is_skipped():
    assert t.sighting_from_der(make_cert([], cn="nodot", san=False), 0, False) is None
    assert t.sighting_from_der(b"not a certificate", 0, False) is None
    assert t.parse_tile(leaf(make_cert([], cn="nodot", san=False), ts_ms=1)) == []


def test_names_per_certificate_are_capped(monkeypatch):
    monkeypatch.setattr(t, "MAX_NAMES_PER_CERT", 3)
    assert len(t.sighting_from_der(make_cert([f"h{i}.example.com" for i in range(10)]), 0, False).names) == 3


def test_overlong_names_are_dropped():
    long = "a" * 250 + ".com"
    assert t.sighting_from_der(make_cert([long, "ok.example.com"]), 0, False).names == ("ok.example.com",)


@pytest.mark.parametrize("cut", [1, 5, 9, 11, 20, 60])
def test_truncated_tiles_raise_instead_of_returning_garbage(cut):
    data = tile([(["a.example.com"], 1, False)])
    with pytest.raises(t.TileError):
        t.split_tile(data[:cut])


def test_unknown_entry_type_and_oversize_are_rejected(monkeypatch):
    import struct
    with pytest.raises(t.TileError):
        t.split_tile(struct.pack(">QH", 1, 7) + b"\x00" * 20)
    monkeypatch.setattr(t, "MAX_TILE_BYTES", 10)
    with pytest.raises(t.TileError):
        t.split_tile(b"x" * 11)


def test_entries_keep_log_order_and_empty_tile_is_empty():
    data = tile([([f"h{i}.example.com"], 100 + i, i % 2 == 0) for i in range(5)])
    assert [s.names[0] for s in t.parse_tile(data)] == [f"h{i}.example.com" for i in range(5)]
    assert t.parse_tile(b"") == []


@pytest.mark.skipif(not os.environ.get("CT_LIVE"), reason="live network check; set CT_LIVE=1")
def test_a_real_tile_parses():                                       # pragma: no cover
    import httpx
    mon = "https://mon.willow.ct.letsencrypt.org/2026h2/"
    size = t.parse_checkpoint(httpx.get(mon + "checkpoint", timeout=30).text)[1]
    data = httpx.get(mon + "tile/data/" + t.tile_path(size // 256 - 1), timeout=30).content
    assert len(t.split_tile(data)) == 256 and t.parse_tile(data)


# ── log list ──

NOW = datetime(2026, 10, 2, tzinfo=timezone.utc)


def tiled(desc, url, state="usable", start=None, end="2027-01-01T00:00:00Z"):
    interval = {k: v for k, v in (("start_inclusive", start), ("end_exclusive", end)) if v}
    return {"description": desc, "monitoring_url": url, "state": {state: {"timestamp": "2026-01-01T00:00:00Z"}}, "temporal_interval": interval}


DOC = {"operators": [
    {"name": "Google", "logs": [{"description": "Google 'Argon2026h2'", "url": "https://x/"}], "tiled_logs": [
        tiled("Google 'ParcelYard2026h2' log", "https://p26h2.example/", start="2026-07-01T00:00:00Z"),
        tiled("Google 'ParcelYard2027h1' log", "https://p27h1.example", start="2027-01-01T00:00:00Z", end="2027-07-01T00:00:00Z"),
        tiled("Google 'ParcelYard2028h1' log", "https://p28h1.example/", start="2028-01-01T00:00:00Z", end="2028-07-01T00:00:00Z"),
        tiled("Google 'PlumbersArms2026h2' log", "https://plumbers.example/"),
        tiled("Google 'ParcelYard2025h2' log", "https://old.example/", end="2026-01-01T00:00:00Z"),
        tiled("Google 'ParcelYardX' retired", "https://retired.example/", state="retired"),
        tiled("Google 'ParcelYard2026h2b' log", "http://insecure.example/"),
    ]},
    {"name": "Let's Encrypt", "tiled_logs": [
        tiled("Let's Encrypt 'Willow2026h2'", "https://mon.willow.example/2026h2/"),
        tiled("Let's Encrypt 'Sycamore2026h2'", "https://mon.sycamore.example/2026h2/"),
    ]},
]}


def test_parse_picks_only_wanted_families_current_and_near_future_usable_https_shards():
    found = ll.parse_log_list(DOC, ("parcelyard", "willow"), NOW)
    assert [(l.family, l.url) for l in found] == [
        ("parcelyard", "https://p26h2.example/"), ("parcelyard", "https://p27h1.example/"), ("willow", "https://mon.willow.example/2026h2/"),
    ]


def test_a_far_future_shard_is_left_out_and_a_new_one_appears_once_inside_the_horizon():
    assert not any("p28h1" in l.url for l in ll.parse_log_list(DOC, ("parcelyard",), NOW))
    later = datetime(2027, 6, 1, tzinfo=timezone.utc)
    assert any("p28h1" in l.url for l in ll.parse_log_list(DOC, ("parcelyard",), later))
    assert not any("p26h2" in l.url for l in ll.parse_log_list(DOC, ("parcelyard",), later))       # aged out


def test_family_match_is_case_insensitive_and_ids_are_stable():
    found = ll.parse_log_list(DOC, ("PLUMBERSARMS",), NOW)
    assert [l.id for l in found] == ["plumbers.example"]


def test_resolve_falls_back_when_the_list_is_missing_or_yields_nothing():
    fb = ll.resolve(None, ("willow",), NOW)
    assert fb and all(l.family == "willow" for l in fb)
    assert ll.resolve({"operators": []}, ("parcelyard",), NOW) == [l for l in ll.FALLBACK_LOGS if l.family == "parcelyard"]
    assert ll.resolve(DOC, ("willow",), NOW)[0].url == "https://mon.willow.example/2026h2/"


def test_custom_logs_must_be_https_without_credentials():
    got = ll.custom_logs(["https://good.example/log", " http://bad.example/", "ftp://x/", "https://user:pw@host.example/", "nonsense"])
    assert [l.url for l in got] == ["https://good.example/log/"]
