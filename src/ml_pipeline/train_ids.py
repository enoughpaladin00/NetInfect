#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import logging
import os

logging.basicConfig(level=logging.INFO, format='%(message)s')

def parse_zeek_log(filepath):
    """Legge un file conn.log di Zeek e lo converte in DataFrame Pandas"""
    with open(filepath, 'r') as f:
        lines = f.readlines()
        
    # Trova la riga con i nomi delle colonne
    columns = []
    data_lines = []
    for line in lines:
        if line.startswith('#fields'):
            columns = line.strip().split('\t')[1:]
        elif not line.startswith('#'):
            data_lines.append(line.strip().split('\t'))
            
    df = pd.DataFrame(data_lines, columns=columns)
    
    # Sostituiamo i '-' (valori nulli di Zeek) con 0
    df.replace('-', 0, inplace=True)
    
    # Convertiamo le colonne numeriche
    numeric_cols = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
            
    return df

def main():
    # Otteniamo il percorso assoluto della cartella corrente per trovare il log
    current_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/conn.log")
    
    logging.info(f"Caricamento log da {log_path}...")
    
    try:
        df = parse_zeek_log(log_path)
    except FileNotFoundError:
        logging.error("File conn.log non trovato! Assicurati di aver avviato Kathara e Zeek.")
        return
        
    logging.info(f"Trovate {len(df)} connessioni registrate.")
    
    # 1. Feature Selection
    # Scegliamo le colonne che descrivono il comportamento della connessione
    features = ['id.resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
    X = df[features].copy()
    
    # 2. Preprocessing (One-Hot Encoding per le variabili categoriche)
    logging.info("Preprocessing dei dati (conversione testuale -> numerica)...")
    X = pd.get_dummies(X, columns=['proto', 'service', 'conn_state'])
    
    # 3. Addestramento Isolation Forest
    # contamination='auto' permette al modello di decidere da solo la soglia di anomalia
    # invece di forzarlo a marcare il 15% esatto del dataset come anomalo.
    logging.info("Addestramento del modello Isolation Forest...")
    model = IsolationForest(n_estimators=100, contamination='auto', random_state=42)
    
    # Addestriamo il modello sull'intero dataset (baseline + attack)
    model.fit(X)
    
    # 4. Predizione e Valutazione
    df['anomaly_score'] = model.decision_function(X)
    df['is_anomaly'] = model.predict(X) # 1 = Normale, -1 = Anomalia
    
    # Dividiamo i risultati
    anomalies = df[df['is_anomaly'] == -1]
    normal = df[df['is_anomaly'] == 1]
    
    logging.info(f"\n--- RISULTATI RILEVAMENTO ---")
    logging.info(f"Connessioni Normali (Baseline): {len(normal)}")
    logging.info(f"Connessioni Anomale (Attacco):  {len(anomalies)}")
    
    if len(anomalies) > 0:
        logging.info("\nEsempi di connessioni intercettate dall'IDS come ATTACCO:")
        print(anomalies[['ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'service', 'conn_state', 'duration']].head(15))
        
    logging.info("\nModello ML addestrato e testato con successo!")

if __name__ == "__main__":
    main()
