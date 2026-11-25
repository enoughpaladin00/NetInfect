"""Unit tests for the safety-critical parts of NetInfect. Run with: python3 -m pytest tests"""
import os
import shutil
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "src/ml_pipeline"))
sys.path.insert(0, os.path.join(ROOT, "src/active_response"))

import features  # noqa: E402
import model_store  # noqa: E402
import response  # noqa: E402
import waf_rules  # noqa: E402


# --- L7 rules -------------------------------------------------------------------
@pytest.mark.parametrize("uri", [
    "/login?user=1%27%20OR%20%271%27%3D%271",   # payloads used by anomaly_traffic.py
    "/login?user=admin%27%20--",
    "/login?user=%3Cscript%3Ealert(1)%3C/script%3E",
    "/login?user=..%2F..%2F..%2Fetc%2Fpasswd",
    "/login?user=1%2527%20OR%20%25271%2527%3D%25271",  # double encoding
    "/item?id=1%20UNION/**/SELECT%20password",     # comment instead of whitespace
    "/p?q=%3Cimg%20src=x%20onerror=alert(1)%3E",
])
def test_waf_detects_attacks(uri):
    assert waf_rules.match(uri)[0] is not None


@pytest.mark.parametrize("uri", [
    "/blog/my--first-post",
    "/search?q=select+a+gift+from+the+list",
    "/index.html", "/api/v1/status", "/images/logo.png",
    "/search?q=O%27Brien",
])
def test_waf_ignores_benign_uris(uri):
    assert waf_rules.match(uri)[0] is None


# --- Active response safety ----------------------------------------------------------
@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(response, "LOG_DIR", str(tmp_path))
    monkeypatch.setattr(response, "ALERTS_CSV", str(tmp_path / "alerts.csv"))
    monkeypatch.setattr(response, "DETECTIONS_CSV", str(tmp_path / "detections.csv"))
    monkeypatch.setattr(response, "LOCK_FILE", str(tmp_path / ".lock"))
    calls = []
    monkeypatch.setattr(response, "_iptables", lambda action, ip: calls.append((action, ip)) or action == "-I")
    return calls


def test_rejects_non_ip_values(sandbox):
    assert not response.block("1.2.3.4; rm -rf /", "x", [])
    assert sandbox == []


def test_allowlisted_ip_is_not_blocked(sandbox):
    allow = response.load_allowlist(os.path.join(ROOT, "config/allowlist.txt"))
    assert not response.block("192.168.30.254", "x", allow)
    assert sandbox == []


def test_attacker_text_cannot_inject_rows(sandbox):
    evil = 'WAF: XSS (/a)\n1700000000,"; touch /tmp/pwned #",fake,'
    assert response.block("203.0.113.100", evil, [])
    assert response.active_blocks() == {"203.0.113.100"}


def test_block_expires(sandbox):
    assert response.block("203.0.113.100", "x", [], ttl=0)
    response.expire_blocks()
    assert response.active_blocks() == set()
    assert ("-D", "203.0.113.100") in sandbox


def test_repeat_block_renews_instead_of_duplicating(sandbox):
    response.block("203.0.113.100", "x", [])
    response.block("203.0.113.100", "y", [])
    assert [c for c in sandbox if c[0] == "-I"] == [("-I", "203.0.113.100")]


# --- Features and models -------------------------------------------------------------
def test_offline_and_live_features_match():
    import pandas as pd
    df = pd.DataFrame({
        "ts": [0.0, 0.5, 1.0, 3.5, 3.6], "id.orig_h": ["a", "a", "b", "a", "a"],
        "id.resp_p": [80, 22, 80, 80, 443], "conn_state": ["SF", "REJ", "SF", "RSTR", "SF"],
        "duration": [1.0, 0, 2, 0, 0], "orig_bytes": [10, 0, 5, 0, 0], "resp_bytes": [100, 0, 50, 0, 0],
    })
    offline = features.build_features(df)
    sw = features.SlidingWindow()
    for i, r in df.iterrows():
        live = sw.add(r["id.orig_h"], r["ts"], r["id.resp_p"], r["conn_state"],
                      r["duration"], r["orig_bytes"], r["resp_bytes"])
        assert live == offline.loc[i, features.FEATURES].to_dict()
    assert offline.loc[3, "conn_count"] == 1  # the 2 s window dropped the older connections


def test_tampered_model_is_refused(tmp_path):
    src = os.path.join(ROOT, "src/ml_pipeline")
    for name in ("ids_model.pkl", "ids_iso_model.pkl", "model_manifest.json"):
        shutil.copy(os.path.join(src, name), tmp_path / name)
    model_store.load_models(str(tmp_path))  # untouched copy loads
    with open(tmp_path / "ids_model.pkl", "ab") as f:
        f.write(b"tampered")
    with pytest.raises(model_store.ModelIntegrityError):
        model_store.load_models(str(tmp_path))
