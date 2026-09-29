#!/usr/bin/env python3
import time
import random
import requests
import paramiko
import logging
import socket

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# IP addresses of the vulnerable servers
SERVERS = ["192.168.10.10", "192.168.10.11"]

def simulate_http(target_ip):
    try:
        logging.info(f"Simulating HTTP request to {target_ip}...")
        response = requests.get(f"http://{target_ip}", timeout=3)
        logging.info(f"HTTP GET {target_ip}: Status {response.status_code}")
    except Exception as e:
        logging.warning(f"HTTP error on {target_ip}: {e}")

def simulate_ssh_login(target_ip):
    # Simulate an SSH login. Even if auth fails, it generates useful traffic for the IDS.
    # We use fake credentials (the real server doesn't have them, but SSH traffic is captured).
    username = "admin"
    password = "password123"
    try:
        logging.info(f"Simulating SSH login to {target_ip}...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Short timeouts to prevent script blocking
        ssh.connect(target_ip, username=username, password=password, timeout=3, auth_timeout=3)
        ssh.close()
        logging.info(f"SSH {target_ip}: Connection terminated.")
    except paramiko.AuthenticationException:
        logging.info(f"SSH {target_ip}: Auth failed (Expected behavior, traffic was still generated).")
    except Exception as e:
        logging.warning(f"SSH error on {target_ip}: {e}")

def main():
    logging.info("Starting Baseline Traffic Generator...")
    while True:
        # Choose a random target server
        target = random.choice(SERVERS)
        
        # Randomly choose protocol (70% probability HTTP, 30% SSH)
        action = random.choices([simulate_http, simulate_ssh_login], weights=[0.7, 0.3])[0]
        
        action(target)
        
        # Random delay to simulate human-like "bursty" behavior
        sleep_time = random.uniform(0.1, 0.5)
        time.sleep(sleep_time)

if __name__ == "__main__":
    main()
