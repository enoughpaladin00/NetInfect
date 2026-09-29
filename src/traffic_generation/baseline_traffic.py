#!/usr/bin/env python3
import time
import random
import requests
import paramiko
import logging
import socket

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Gli indirizzi IP dei server nella rete vulnerabile
SERVERS = ["192.168.10.10", "192.168.10.11"]

def simulate_http(target_ip):
    try:
        logging.info(f"Simulazione richiesta HTTP a {target_ip}...")
        response = requests.get(f"http://{target_ip}", timeout=3)
        logging.info(f"HTTP GET {target_ip}: Status {response.status_code}")
    except Exception as e:
        logging.warning(f"Errore HTTP su {target_ip}: {e}")

def simulate_ssh_login(target_ip):
    # Simuliamo un login SSH. Anche se fallisce o passa, genera traffico utile per l'IDS.
    # Usiamo credenziali finte (il server reale non le ha, ma il traffico SSH viene catturato).
    username = "admin"
    password = "password123"
    try:
        logging.info(f"Simulazione login SSH verso {target_ip}...")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Impostiamo timeout brevi per non bloccare lo script
        ssh.connect(target_ip, username=username, password=password, timeout=3, auth_timeout=3)
        ssh.close()
        logging.info(f"SSH {target_ip}: Connessione terminata.")
    except paramiko.AuthenticationException:
        logging.info(f"SSH {target_ip}: Auth failed (Comportamento atteso, il traffico è stato comunque generato).")
    except Exception as e:
        logging.warning(f"Errore SSH su {target_ip}: {e}")

def main():
    logging.info("Avvio del generatore di traffico Baseline...")
    while True:
        # Scegliamo un server target a caso
        target = random.choice(SERVERS)
        
        # Scegliamo a caso il protocollo (70% probabilità HTTP, 30% SSH)
        action = random.choices([simulate_http, simulate_ssh_login], weights=[0.7, 0.3])[0]
        
        action(target)
        
        # Attesa randomica per simulare un comportamento umano "bursty"
        sleep_time = random.uniform(1.0, 5.0)
        time.sleep(sleep_time)

if __name__ == "__main__":
    main()
