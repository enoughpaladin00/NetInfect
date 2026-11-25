#!/usr/bin/env python3
"""
L7 signatures shared by http_analyzer.py (live) and analyze_pcap.py (offline).

These are detection rules, not a complete WAF: they look only at the URI that
Zeek records in http.log (no POST body, headers or cookies) and they run after
the request has already reached the server.
"""
import re
from urllib.parse import unquote_plus

RULES = [
    ("SQL Injection", re.compile(
        r"(union(\s|/\*.*?\*/)+(all(\s|/\*.*?\*/)+)?select"   # UNION SELECT, also UN/**/ION-style spacing
        r"|'\s*(or|and)\s+'?\w*'?\s*=\s*'?\w*"                # ' OR '1'='1
        r"|'\s*(--|#|/\*)"                                      # quote followed by a comment
        r"|;\s*(drop|delete|insert|update)\s"                   # stacked queries
        r"|\b(sleep|benchmark|pg_sleep)\s*\()",                 # time-based blind
        re.IGNORECASE)),
    ("XSS", re.compile(r"(<\s*script|javascript\s*:|\bon\w+\s*=|<\s*(img|svg|iframe)\b)", re.IGNORECASE)),
    ("Path Traversal", re.compile(r"(\.\.[/\\]|/etc/(passwd|shadow)|\bboot\.ini\b)", re.IGNORECASE)),
]


def normalise(uri, max_rounds=3):
    """Decode repeatedly so double encoding (%2527 -> %27 -> ') does not hide a payload."""
    for _ in range(max_rounds):
        decoded = unquote_plus(uri)
        if decoded == uri:
            break
        uri = decoded
    return uri


def match(uri):
    """Return (attack_type, decoded_uri) for the first rule that matches, or (None, decoded_uri)."""
    decoded = normalise(uri)
    for name, pattern in RULES:
        if pattern.search(decoded):
            return name, decoded
    return None, decoded
