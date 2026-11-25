#!/usr/bin/env python3
"""Manually remove a block from the gateway and from the active blocklist."""
import argparse
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import response  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(message)s")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unblock an IP from the IDS/Firewall")
    parser.add_argument("ip", help="The IP address to unblock")
    args = parser.parse_args()
    sys.exit(0 if response.unblock(args.ip) else 1)
