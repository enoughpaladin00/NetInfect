#!/usr/bin/env python3
"""
Shared feature extraction for NetInfect.

Training (train_ids.py), live detection (firewall_manager.py) and offline
analysis (analyze_pcap.py) all use the functions in this module, so the
model sees exactly the same features in production as during training.

Unit of analysis: one Zeek conn.log record. For every connection we look back
WINDOW_SIZE seconds over the connections opened by the same source IP and
aggregate them (sliding window, inclusive of the current connection).

Note: Zeek writes a conn.log record only when the connection ends, so a
long-lived connection (e.g. Slowloris, a large transfer) is only visible to
NetInfect after it closes.
"""
from collections import defaultdict, deque

import pandas as pd

WINDOW_SIZE = 2.0  # seconds

FEATURES = [
    "conn_count",
    "unique_ports",
    "rej_count",
    "rstr_count",
    "total_duration",
    "total_orig_bytes",
    "total_resp_bytes",
    "bytes_ratio",
    "avg_duration",
]

NUMERIC_COLS = ["ts", "id.resp_p", "duration", "orig_bytes", "resp_bytes"]


def parse_zeek_log(filepath):
    """Read a Zeek TSV log (e.g. conn.log) into a DataFrame."""
    columns, rows = [], []
    with open(filepath, "r") as f:
        for line in f:
            if line.startswith("#fields"):
                columns = line.rstrip("\n").split("\t")[1:]
            elif not line.startswith("#") and line.strip():
                rows.append(line.rstrip("\n").split("\t"))
    df = pd.DataFrame(rows, columns=columns)
    for col in NUMERIC_COLS:
        if col in df.columns:
            # '-' is Zeek's unset value
            df[col] = pd.to_numeric(df[col].replace("-", "0"), errors="coerce").fillna(0)
    return df


def window_features(window):
    """Aggregate a list of (ts, resp_p, is_rej, is_rstr, duration, orig_bytes, resp_bytes)."""
    conn_count = len(window)
    total_duration = sum(c[4] for c in window)
    total_orig = sum(c[5] for c in window)
    total_resp = sum(c[6] for c in window)
    return {
        "conn_count": conn_count,
        "unique_ports": len({c[1] for c in window}),
        "rej_count": sum(c[2] for c in window),
        "rstr_count": sum(c[3] for c in window),
        "total_duration": total_duration,
        "total_orig_bytes": total_orig,
        "total_resp_bytes": total_resp,
        "bytes_ratio": total_orig / (total_resp + 1),
        "avg_duration": total_duration / max(conn_count, 1),
    }


class SlidingWindow:
    """Per-source-IP sliding window, used both offline and live."""

    def __init__(self, size=WINDOW_SIZE):
        self.size = size
        self.conns = defaultdict(deque)

    def add(self, src_ip, ts, resp_p, conn_state, duration, orig_bytes, resp_bytes):
        q = self.conns[src_ip]
        q.append((ts, resp_p, int(conn_state == "REJ"), int(conn_state == "RSTR"),
                  duration, orig_bytes, resp_bytes))
        while q and q[0][0] < ts - self.size:
            q.popleft()
        return window_features(q)

    def forget(self, src_ip):
        self.conns.pop(src_ip, None)


def build_features(df):
    """Return one feature row per connection (sorted by time), keeping ts and source IP."""
    df = df.sort_values("ts").reset_index(drop=True)
    rows = []
    sw = SlidingWindow()
    for ts, src, port, state, dur, ob, rb in zip(
        df["ts"], df["id.orig_h"], df["id.resp_p"], df["conn_state"],
        df["duration"], df["orig_bytes"], df["resp_bytes"],
    ):
        rows.append(sw.add(src, ts, port, state, dur, ob, rb))
    out = pd.DataFrame(rows, columns=FEATURES)
    out["ts"] = df["ts"].values
    out["src_ip"] = df["id.orig_h"].values
    return out
