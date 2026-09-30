#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
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
    numeric_cols = ['ts', 'id.resp_p', 'duration', 'orig_bytes', 'resp_bytes']
    for col in numeric_cols:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
            
    return df

def feature_engineering(df):
    """Groups connections by Source IP in 2-second windows."""
    df['ts_datetime'] = pd.to_datetime(df['ts'], unit='s')
    df['is_rej'] = (df['conn_state'] == 'REJ').astype(int)
    df['is_rstr'] = (df['conn_state'] == 'RSTR').astype(int)
    
    df = df.sort_values('ts_datetime')
    
    # Aggregation
    grouped = df.groupby(['id.orig_h', pd.Grouper(key='ts_datetime', freq='2s')]).agg(
        conn_count=('id.resp_p', 'count'),
        unique_ports=('id.resp_p', 'nunique'),
        rej_count=('is_rej', 'sum'),
        rstr_count=('is_rstr', 'sum'),
        total_duration=('duration', 'sum'),
        total_orig_bytes=('orig_bytes', 'sum'),
        total_resp_bytes=('resp_bytes', 'sum')
    ).reset_index()
    
    grouped = grouped[grouped['conn_count'] > 0]
    return grouped

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    baseline_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/baseline.log")
    test_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/test_attack.log")
    
    logging.info("--- PHASE 1: Feature Engineering (Windowing) ---")
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
    
    logging.info("Applying 2-second window aggregation...")
    df_base_agg = feature_engineering(df_baseline)
    df_test_agg = feature_engineering(df_test)
    
    logging.info(f"Baseline Windows: {len(df_base_agg)}")
    logging.info(f"Test Windows: {len(df_test_agg)}")
    
    # Features for the model
    features = ['conn_count', 'unique_ports', 'rej_count', 'rstr_count', 'total_duration', 'total_orig_bytes']
    
    X_train = df_base_agg[features]
    X_test = df_test_agg[features]
    
    # Normalization (StandardScaler)
    logging.info("\nData Normalization (StandardScaler)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Model Training
    logging.info("Training Isolation Forest on windowed Baseline traffic...")
    model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
    model.fit(X_train_scaled)
    
    # Save models
    model_path = os.path.join(current_dir, "ids_model.pkl")
    scaler_path = os.path.join(current_dir, "ids_scaler.pkl")
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    logging.info(f"Model and Scaler saved to {current_dir}!")
    
    # Prediction
    logging.info("\nSearching for anomalous behavior windows on Test file...")
    df_test_agg['is_anomaly'] = model.predict(X_test_scaled)
    
    anomalies = df_test_agg[df_test_agg['is_anomaly'] == -1]
    normal = df_test_agg[df_test_agg['is_anomaly'] == 1]
    
    logging.info(f"\n--- TEST RESULTS ---")
    logging.info(f"Analyzed time windows: {len(df_test_agg)}")
    logging.info(f"Classified as NORMAL: {len(normal)}")
    logging.info(f"Classified as ANOMALOUS: {len(anomalies)}")
    
    if len(anomalies) > 0:
        logging.info("\nExamples of traffic windows flagged as ATTACK:")
        print(anomalies[['ts_datetime', 'id.orig_h', 'conn_count', 'unique_ports', 'rej_count', 'rstr_count']].head(10))

if __name__ == "__main__":
    main()
