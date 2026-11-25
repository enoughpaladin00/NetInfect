#!/usr/bin/env python3
"""
L7 detection with reactive blocking.

Tails Zeek's http.log, matches each URI against the signatures in waf_rules.py
and blocks the source IP on the gateway (with a TTL).

This is not an inline WAF: Zeek logs a request after it has reached the
server, so the first malicious request always gets through. Only the URI is
inspected (no POST body, headers or cookies), and HTTPS traffic is invisible
unless TLS is terminated before the sensor. The real fix for injection flaws
is in the application (parameterised queries, output encoding); this is
defence in depth.
"""
import logging
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import response  # noqa: E402
from waf_rules import match  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

HTTP_LOG = os.path.join(response.LOG_DIR, "http.log")
HOUSEKEEPING_EVERY = 5.0


def main():
    allowlist = response.load_allowlist()
    while not os.path.exists(HTTP_LOG):
        logging.info("Waiting for Zeek to create http.log...")
        time.sleep(2)

    blocked = response.active_blocks()
    last_housekeeping = 0.0
    logging.info(f"L7 detection started on {HTTP_LOG}")
    with open(HTTP_LOG) as f:
        f.seek(0, os.SEEK_END)
        while True:
            now = time.time()
            if now - last_housekeeping > HOUSEKEEPING_EVERY:
                response.expire_blocks()
                blocked = response.active_blocks()
                last_housekeeping = now

            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            if line.startswith("#"):
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 10:
                continue
            orig_h, resp_h, uri = parts[2], parts[4], parts[9]
            if orig_h in blocked:
                continue

            attack, decoded = match(uri)
            if attack:
                shown = response.clean_text(decoded, 120)
                logging.warning(f"L7 attack detected: {attack} from {orig_h} to {resp_h} | URI: {shown}")
                if response.block(orig_h, f"WAF: {attack} ({shown})", allowlist):
                    blocked.add(orig_h)


if __name__ == "__main__":
    main()
