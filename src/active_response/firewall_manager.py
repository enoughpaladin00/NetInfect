#!/usr/bin/env python3
"""
L3/L4 active response: tails Zeek's conn.log, scores each connection with the
hybrid model and blocks source IPs on the Kathara gateway.

Two detection paths:
  * Fast path (ML): attack probability over a 2 s sliding window per source IP.
      - probability >= block threshold -> block the IP (with a TTL)
      - alert threshold <= probability < block threshold -> alert only, for an analyst
  * Slow path (reputation): a per-IP score that grows with every connection
    (more for rejected/reset ones) and decays over time. It catches activity
    spread over longer than the 2 s window.

Limitation: Zeek writes a conn.log record when a connection ends, so long
connections (Slowloris, large transfers) are only scored after they close.
"""
import logging
import os
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "../ml_pipeline"))
sys.path.insert(0, HERE)
from features import FEATURES, SlidingWindow  # noqa: E402
from model_store import ModelIntegrityError, load_models, score  # noqa: E402
import response  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

CONN_LOG = os.path.join(response.LOG_DIR, "conn.log")

# Slow path (reputation) parameters
REPUTATION_THRESHOLD = 100.0
DECAY_RATE = 2.0        # points lost per second
CONN_PENALTY = 0.5
REJ_PENALTY = 20.0
RSTR_PENALTY = 10.0

HOUSEKEEPING_EVERY = 5.0  # seconds between blocklist sync / TTL expiry


def parse_conn_line(line):
    parts = line.rstrip("\n").split("\t")
    if len(parts) < 12:
        return None
    ts, _, orig_h, _, _, resp_p, _, _, duration, orig_bytes, resp_bytes, conn_state = parts[:12]

    def num(v):
        return 0.0 if v == "-" else float(v)

    try:
        return orig_h, float(ts), int(resp_p), conn_state, num(duration), num(orig_bytes), num(resp_bytes)
    except ValueError:
        return None


def main():
    try:
        iso, rf, manifest = load_models()
    except (FileNotFoundError, ModelIntegrityError) as e:
        logging.error(e)
        sys.exit(1)
    if manifest["features"] != FEATURES:
        logging.error("The saved model was trained on different features: retrain it.")
        sys.exit(1)
    alert_t, block_t = manifest["alert_threshold"], manifest["block_threshold"]

    allowlist = response.load_allowlist()
    window = SlidingWindow(manifest["window_size_s"])
    reputation, last_seen = defaultdict(float), {}
    blocked = response.active_blocks()
    last_housekeeping = 0.0

    logging.info(f"Model loaded (alert >= {alert_t}, block >= {block_t}). Waiting for {CONN_LOG}...")
    while not os.path.exists(CONN_LOG):
        time.sleep(2)

    with open(CONN_LOG) as f:
        f.seek(0, os.SEEK_END)  # only new connections
        logging.info("Listening for new connections...")
        while True:
            now = time.time()
            if now - last_housekeeping > HOUSEKEEPING_EVERY:
                response.expire_blocks()
                blocked = response.active_blocks()  # picks up manual unblocks and expiries
                last_housekeeping = now

            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            if line.startswith("#"):
                continue
            conn = parse_conn_line(line)
            if conn is None:
                continue
            src, ts, port, state, dur, ob, rb = conn
            if src in blocked:
                continue

            feats = window.add(src, ts, port, state, dur, ob, rb)
            proba = float(score(iso, rf, [[feats[k] for k in FEATURES]])[0][0])

            # Slow path
            if src in last_seen:
                reputation[src] = max(0.0, reputation[src] - (ts - last_seen[src]) * DECAY_RATE)
            last_seen[src] = ts
            reputation[src] += CONN_PENALTY + REJ_PENALTY * (state == "REJ") + RSTR_PENALTY * (state == "RSTR")

            summary = (f"{feats['conn_count']} conns, {feats['unique_ports']} ports, "
                       f"{feats['rej_count']} REJ in {window.size:.0f}s")
            if proba >= block_t or reputation[src] >= REPUTATION_THRESHOLD:
                reason = (f"ML p={proba:.2f}" if proba >= block_t
                          else f"Reputation {reputation[src]:.0f}/{REPUTATION_THRESHOLD:.0f}")
                logging.warning(f"Attack from {src}: {reason} | {summary}")
                if response.block(src, reason, allowlist):
                    blocked.add(src)
                    window.forget(src)
                    reputation.pop(src, None)
                    last_seen.pop(src, None)
            elif proba >= alert_t:
                logging.warning(f"Suspicious traffic from {src} (ML p={proba:.2f}), alert only | {summary}")
                response.record_detection(src, f"ML p={proba:.2f} (below block threshold) | {summary}")


if __name__ == "__main__":
    main()
