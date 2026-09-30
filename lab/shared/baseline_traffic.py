#!/usr/bin/env python3
import time
import random
import socket
import logging
import urllib.request
import urllib.error

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Gli indirizzi IP dei server nella rete vulnerabile
SERVERS = ["192.168.30.10", "192.168.30.11"]
URIS = ["/", "/index.html", "/about", "/contact", "/api/v1/status", "/images/logo.png"]

def simulate_http_browsing(target_ip):
    uri = random.choice(URIS)
    url = f"http://{target_ip}{uri}"
    try:
        logging.info(f"User browsing: {url}")
        # Add random User-Agent to simulate real browsers
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        urllib.request.urlopen(req, timeout=2)
    except Exception:
        pass

def simulate_large_download(target_ip):
    url = f"http://{target_ip}/download/large_dataset.zip"
    try:
        logging.info(f"User starting large download from {target_ip}...")
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass

def simulate_ssh_login(target_ip):
    try:
        logging.info(f"User initiating SSH connection to {target_ip}...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target_ip, 22))
        
        banner = s.recv(1024)
        s.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n")
        time.sleep(0.5)
        s.sendall(b"fake_encrypted_auth_payload_1234567890\n")
        
        s.close()
    except Exception:
        pass

def main():
    logging.info("Starting ADVANCED Baseline Traffic Generator (Simulating real office network)...")
    while True:
        # Scegliamo un server target a caso
        target = random.choice(SERVERS)
        action_choice = random.random()
        
        if action_choice < 0.6:
            simulate_http_browsing(target)
            time.sleep(random.uniform(0.1, 1.5))
        elif action_choice < 0.8:
            simulate_ssh_login(target)
            time.sleep(random.uniform(1.0, 3.0))
        else:
            simulate_large_download(target)
            time.sleep(random.uniform(2.0, 5.0))

if __name__ == "__main__":
    main()
