#!/usr/bin/env python3
"""
Shared active-response logic for the ML firewall and the L7 analyzer.

Safety rules applied to every block:
  * the IP must parse as an IP address (no shell, arguments passed as a list);
  * allowlisted addresses (config/allowlist.txt) are never blocked;
  * every block expires after BLOCK_TTL seconds unless renewed, so a false
    positive does not lock a legitimate host out forever;
  * the shared blocklist (alerts.csv) is written with the csv module under a
    file lock, so attacker-controlled text (e.g. a URI) cannot add fake rows.
"""
import csv
import fcntl
import ipaddress
import logging
import os
import subprocess
import time
from contextlib import contextmanager

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../.."))
LAB_DIR = os.path.join(ROOT, "lab")
LOG_DIR = os.path.join(ROOT, "lab/shared/zeek_logs")
ALERTS_CSV = os.path.join(LOG_DIR, "alerts.csv")          # active blocklist (read by the dashboard)
DETECTIONS_CSV = os.path.join(LOG_DIR, "detections.csv")  # alerts that did not trigger a block
ALLOWLIST_FILE = os.path.join(ROOT, "config/allowlist.txt")
LOCK_FILE = os.path.join(LOG_DIR, ".alerts.lock")

BLOCK_TTL = int(os.environ.get("NETINFECT_BLOCK_TTL", 15 * 60))  # seconds
ALERT_FIELDS = ["timestamp", "attacker_ip", "reason", "expires_at"]
DETECTION_FIELDS = ["timestamp", "src_ip", "reason"]


def parse_ip(value):
    """Return the normalised IP string, or None if value is not an IP address."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def load_allowlist(path=ALLOWLIST_FILE):
    nets = []
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    nets.append(ipaddress.ip_network(line, strict=False))
    return nets


def is_allowlisted(ip, allowlist):
    addr = ipaddress.ip_address(ip)
    return any(addr in net for net in allowlist)


def clean_text(text, limit=200):
    """Make attacker-controlled text safe to log: no control characters, bounded length."""
    text = "".join(ch if ch.isprintable() else "?" for ch in str(text))
    return text[:limit]


@contextmanager
def _locked():
    os.makedirs(LOG_DIR, exist_ok=True)
    with open(LOCK_FILE, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _read_alerts():
    if not os.path.exists(ALERTS_CSV):
        return []
    with open(ALERTS_CSV, newline="") as f:
        rows = list(csv.DictReader(f))
    # Keep only rows with a valid IP: anything else is corrupt or injected.
    return [r for r in rows if parse_ip(r.get("attacker_ip"))]


def _write_alerts(rows):
    tmp = ALERTS_CSV + ".tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=ALERT_FIELDS, extrasaction="ignore", quoting=csv.QUOTE_ALL)
        w.writeheader()
        for r in rows:
            r.setdefault("expires_at", "")
            w.writerow(r)
    os.replace(tmp, ALERTS_CSV)


def active_blocks():
    with _locked():
        return {r["attacker_ip"] for r in _read_alerts()}


def _iptables(action, ip):
    """Run iptables on the Kathara gateway. Arguments are a list: no shell involved."""
    cmd = ["kathara", "exec", "gateway", "--", "iptables", action, "FORWARD", "-s", ip, "-j", "DROP"]
    return subprocess.run(cmd, cwd=LAB_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def block(ip, reason, allowlist, ttl=BLOCK_TTL):
    """Block ip on the gateway. Returns True if the IP is (now) blocked."""
    ip = parse_ip(ip)
    if ip is None:
        logging.error("Refusing to block a value that is not an IP address.")
        return False
    if is_allowlisted(ip, allowlist):
        logging.warning(f"{ip} is allowlisted: logging the detection without blocking.")
        record_detection(ip, f"allowlisted, not blocked: {reason}")
        return False
    with _locked():
        rows = _read_alerts()
        now = int(time.time())
        existing = [r for r in rows if r["attacker_ip"] == ip]
        if existing:
            for r in existing:  # renew the block instead of adding a duplicate rule
                r["expires_at"] = str(now + ttl)
            _write_alerts(rows)
            return True
        if not _iptables("-I", ip):
            logging.error(f"Could not send the iptables command for {ip} to Kathara.")
            return False
        rows.append({"timestamp": str(now), "attacker_ip": ip,
                     "reason": clean_text(reason), "expires_at": str(now + ttl)})
        _write_alerts(rows)
    logging.info(f"Blocked {ip} for {ttl // 60} min ({clean_text(reason)})")
    return True


def unblock(ip):
    ip = parse_ip(ip)
    if ip is None:
        logging.error("Not a valid IP address.")
        return False
    with _locked():
        while _iptables("-D", ip):  # remove every copy of the rule
            pass
        _write_alerts([r for r in _read_alerts() if r["attacker_ip"] != ip])
    logging.info(f"Unblocked {ip}")
    return True


def expire_blocks():
    """Lift blocks whose TTL has passed. Safe to call often from any process."""
    now = time.time()
    with _locked():
        rows = _read_alerts()
        keep = []
        for r in rows:
            exp = r.get("expires_at") or ""
            if exp and float(exp) <= now:
                while _iptables("-D", r["attacker_ip"]):
                    pass
                logging.info(f"Block on {r['attacker_ip']} expired")
            else:
                keep.append(r)
        if len(keep) != len(rows):
            _write_alerts(keep)


def record_detection(ip, reason):
    """Log an alert that did not lead to a block (for analyst review)."""
    os.makedirs(LOG_DIR, exist_ok=True)
    new = not os.path.exists(DETECTIONS_CSV)
    with _locked(), open(DETECTIONS_CSV, "a", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        if new:
            w.writerow(DETECTION_FIELDS)
        w.writerow([int(time.time()), ip, clean_text(reason)])
