#!/usr/bin/env python3
import time
import os
import pandas as pd
import joblib
import logging
import subprocess
import warnings

# Ignoriamo i warning noiosi di Pandas
warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def tail_and_predict(log_file, model_path, columns_path):
    """
    Legge il file conn.log in tempo reale, usa il modello ML per
    valutare le connessioni e invia comandi iptables al gateway.
    """
    logging.info("Caricamento del modello di Machine Learning...")
    try:
        model = joblib.load(model_path)
        expected_columns = joblib.load(columns_path)
    except Exception as e:
        logging.error(f"Errore nel caricamento del modello: {e}")
        return

    # Teniamo traccia degli IP che abbiamo già "bannato" per evitare
    # di inondare il gateway con le stesse regole iptables.
    blocked_ips = set()
    
    # Categorie fisse usate in fase di training
    zeek_states = ['S0', 'S1', 'SF', 'REJ', 'S2', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'SH', 'SHR', 'OTH']
    zeek_services = ['http', 'ssh', 'dns', 'ftp', 'ssl', '0']
    
    logging.info(f"In ascolto in tempo reale sul file: {log_file}")
    logging.info("In attesa di nuovo traffico...")
    
    with open(log_file, 'r') as f:
        # Spostiamo il puntatore alla FINE del file
        # Analizziamo solo le cose che succedono da ORA in poi
        f.seek(0, 2)
        
        while True:
            line = f.readline()
            if not line:
                # Se non c'è nulla di nuovo, aspetta mezzo secondo
                time.sleep(0.5)
                continue
                
            if line.startswith('#'):
                continue
                
            parts = line.strip().split('\t')
            if len(parts) < 21:
                continue
                
            # Estrazione valori dalle colonne di Zeek (posizione standard)
            orig_h, resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state = parts[2], parts[5], parts[6], parts[7], parts[8], parts[9], parts[10], parts[11]
            
            # Se l'IP è già nella nostra blacklist, non sprecare CPU per analizzarlo
            if orig_h in blocked_ips:
                continue
                
            # Preparazione dati per il modello
            row = {
                'id.resp_p': int(resp_p),
                'proto': proto,
                'service': service if service != '-' else '0',
                'duration': float(duration) if duration != '-' else 0.0,
                'orig_bytes': float(orig_bytes) if orig_bytes != '-' else 0.0,
                'resp_bytes': float(resp_bytes) if resp_bytes != '-' else 0.0,
                'conn_state': conn_state
            }
            
            df = pd.DataFrame([row])
            
            # Preprocessing (Identico al training)
            df['conn_state'] = pd.Categorical(df['conn_state'], categories=zeek_states)
            df['service'] = pd.Categorical(df['service'], categories=zeek_services)
            df['proto'] = pd.Categorical(df['proto'], categories=['tcp', 'udp', 'icmp'])
            
            df_dummies = pd.get_dummies(df, columns=['proto', 'service', 'conn_state'])
            df_model = df_dummies.reindex(columns=expected_columns, fill_value=0)
            
            # --- LA PREDIZIONE ---
            prediction = model.predict(df_model)[0]
            
            if prediction == -1: # Anomalia Rilevata!
                logging.warning(f"⚠️ RILEVATA ANOMALIA! Sorgente: {orig_h} (Porta dest: {resp_p}, Stato: {conn_state})")
                logging.warning(f"🛡️  Esecuzione blocco firewall sull'IP {orig_h}...")
                
                # Comando per far inserire al gateway una regola iptables al volo
                current_dir = os.path.dirname(os.path.abspath(__file__))
                lab_dir = os.path.join(current_dir, "../../lab")
                
                # Blocchiamo il traffico che attraversa il gateway (FORWARD)
                cmd_fw = f"cd {lab_dir} && kathara exec gateway -- iptables -I FORWARD -s {orig_h} -j DROP"
                
                try:
                    subprocess.run(cmd_fw, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    logging.info(f"✅ IP {orig_h} inserito nella Blacklist del Gateway!")
                    blocked_ips.add(orig_h) # Non analizziamo/blocchiamo più questo IP
                except subprocess.CalledProcessError:
                    logging.error(f"❌ Impossibile inviare il comando iptables a Kathara.")

if __name__ == "__main__":
    # Percorsi relativi
    current_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/conn.log")
    model_p = os.path.join(current_dir, "../ml_pipeline/ids_model.pkl")
    cols_p = os.path.join(current_dir, "../ml_pipeline/ids_columns.pkl")
    
    if not os.path.exists(model_p):
        logging.error("Modello non trovato. Esegui prima 'python3 src/ml_pipeline/train_ids.py' per crearlo.")
        exit(1)
        
    tail_and_predict(log_path, model_p, cols_p)
