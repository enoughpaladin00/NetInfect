#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import logging
import os
import joblib
import warnings

# Ignore pandas warnings
warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format='%(message)s')

def parse_zeek_log(filepath):
    """Reads a Zeek conn.log file and converts it into a Pandas DataFrame."""
    with open(filepath, 'r') as f:
        lines = f.readlines()
        
    # Find the line with column names
    columns = []
    data_lines = []
    for line in lines:
        if line.startswith('#fields'):
            columns = line.strip().split('\t')[1:]
        elif not line.startswith('#'):
            data_lines.append(line.strip().split('\t'))
            
    df = pd.DataFrame(data_lines, columns=columns)
    
    # Replace '-' (Zeek null values) with 0
    df.replace('-', 0, inplace=True)
    
    # Convert numerical columns
    numeric_cols = ['duration', 'orig_bytes', 'resp_bytes', 'orig_pkts', 'resp_pkts']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
            
    return df

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    baseline_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/baseline.log")
    test_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/test_attack.log")
    
    logging.info(f"Loading Baseline from {baseline_path}...")
    try:
        df_baseline = parse_zeek_log(baseline_path)
    except FileNotFoundError:
        logging.error("File baseline.log not found!")
        return

    logging.info(f"Loading Test Set from {test_path}...")
    try:
        df_test = parse_zeek_log(test_path)
    except FileNotFoundError:
        logging.error("File test_attack.log not found!")
        return
        
    logging.info(f"Baseline Connections (Train): {len(df_baseline)}")
    logging.info(f"Test Connections (Attack): {len(df_test)}")
    
    # 1. Feature Selection
    features = ['id.resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
    
    X_train = df_baseline[features].copy()
    X_test = df_test[features].copy()
    
    # 2. Preprocessing
    logging.info("Data Preprocessing (One-Hot Encoding)...")
    
    # Explicitly define all possible categories for Pandas.
    # Ensures no categorical columns are missing during dummy encoding
    # if a category (e.g. REJ) isn't present in the baseline log.
    zeek_states = ['S0', 'S1', 'SF', 'REJ', 'S2', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'SH', 'SHR', 'OTH']
    zeek_services = ['http', 'ssh', 'dns', 'ftp', 'ssl', '0']
    
    for df in [X_train, X_test]:
        df['conn_state'] = pd.Categorical(df['conn_state'], categories=zeek_states)
        # Replace Zeek null service ("-") with "0" before applying categories
        df['service'] = df['service'].replace('-', '0')
        df['service'] = pd.Categorical(df['service'], categories=zeek_services)
    
    X_train = pd.get_dummies(X_train, columns=['proto', 'service', 'conn_state'])
    X_test = pd.get_dummies(X_test, columns=['proto', 'service', 'conn_state'])
    
    # Ensure test columns match training columns exactly
    X_test = X_test.reindex(columns=X_train.columns, fill_value=0)
    
    # 3. Isolation Forest Training
    logging.info("Training Isolation Forest model on Baseline traffic...")
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X_train)
    
    # 4. Save the model for real-time use (Milestone 5)
    model_path = os.path.join(current_dir, "ids_model.pkl")
    columns_path = os.path.join(current_dir, "ids_columns.pkl")
    joblib.dump(model, model_path)
    joblib.dump(X_train.columns, columns_path)
    logging.info(f"Model saved successfully to {model_path}!")
    
    # 5. Prediction on Test Set (Attack)
    logging.info("\nSearching for anomalies on the Test file...")
    df_test['is_anomaly'] = model.predict(X_test) # 1 = Normal, -1 = Anomaly
    
    anomalies = df_test[df_test['is_anomaly'] == -1]
    normal = df_test[df_test['is_anomaly'] == 1]
    
    logging.info(f"\n--- TEST RESULTS (IDS Efficacy) ---")
    logging.info(f"Analyzed connections: {len(df_test)}")
    logging.info(f"Classified as NORMAL: {len(normal)}")
    logging.info(f"Classified as ANOMALOUS: {len(anomalies)}")
    
    if len(anomalies) > 0:
        logging.info("\nExamples of traffic flagged as ATTACK:")
        print(anomalies[['ts', 'id.orig_h', 'id.resp_h', 'id.resp_p', 'service', 'conn_state', 'duration']].head(15))
        
if __name__ == "__main__":
    main()
