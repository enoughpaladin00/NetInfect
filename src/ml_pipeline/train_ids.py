#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import logging
import os
import joblib

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
    current_dir = os.path.dirname(os.path.abspath(__file__))
    baseline_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/baseline.log")
    test_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/test_attack.log")
    
    logging.info(f"Caricamento Baseline da {baseline_path}...")
    try:
        df_baseline = parse_zeek_log(baseline_path)
    except FileNotFoundError:
        logging.error("File baseline.log non trovato!")
        return

    logging.info(f"Caricamento Test Set da {test_path}...")
    try:
        df_test = parse_zeek_log(test_path)
    except FileNotFoundError:
        logging.error("File test_attack.log non trovato!")
        return
        
    logging.info(f"Connessioni Baseline (Train): {len(df_baseline)}")
    logging.info(f"Connessioni Test (Attack): {len(df_test)}")
    
    # 1. Feature Selection
    features = ['id.resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
    
    X_train = df_baseline[features].copy()
    X_test = df_test[features].copy()
    
    # 2. Preprocessing
    logging.info("Preprocessing dei dati (One-Hot Encoding)...")
    X_train = pd.get_dummies(X_train, columns=['proto', 'service', 'conn_state'])
    X_test = pd.get_dummies(X_test, columns=['proto', 'service', 'conn_state'])
    
    # TRUCCO ML: Il dataset di test potrebbe avere valori diversi (es. protocolli o porte diverse).
    # Dobbiamo allineare le colonne di X_test affinché siano identiche a quelle su cui si è allenato X_train.
    X_test = X_test.reindex(columns=X_train.columns, fill_value=0)
    
    # 3. Addestramento Isolation Forest
    # Visto che ora usiamo il baseline PULITO, possiamo dirgli che le anomalie attese
    # sono pochissime o quasi inesistenti (es. 1%)
    logging.info("Addestramento del modello Isolation Forest sul traffico Baseline...")
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X_train)
    
    # 4. Salvataggio del modello per l'uso in tempo reale (Milestone 5)
    model_path = os.path.join(current_dir, "ids_model.pkl")
    columns_path = os.path.join(current_dir, "ids_columns.pkl")
    joblib.dump(model, model_path)
    joblib.dump(X_train.columns, columns_path)
    logging.info(f"Modello salvato con successo in {model_path}!")
    
    # 5. Predizione sul Test Set (Attacco)
    logging.info("\nRicerca di anomalie sul file di Test...")
    df_test['is_anomaly'] = model.predict(X_test) # 1 = Normale, -1 = Anomalia
    
    anomalies = df_test[df_test['is_anomaly'] == -1]
    normal = df_test[df_test['is_anomaly'] == 1]
    
    logging.info(f"\n--- RISULTATI TEST (Efficacia IDS) ---")
    logging.info(f"Connessioni analizzate: {len(df_test)}")
    logging.info(f"Classificate come NORMALI: {len(normal)}")
    logging.info(f"Classificate come ANOMALE: {len(anomalies)}")
    
    if len(anomalies) > 0:
        logging.info("\nEsempi di traffico flaggato come ATTACCO:")
        print(anomalies[['ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'service', 'conn_state', 'duration']].head(15))
        
if __name__ == "__main__":
    main()
