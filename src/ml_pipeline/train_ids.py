#!/usr/bin/env python3
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
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
    
    grouped = df.groupby(['id.orig_h', pd.Grouper(key='ts_datetime', freq='2s')]).agg(
        conn_count=('id.resp_p', 'count'),
        unique_ports=('id.resp_p', 'nunique'),
        rej_count=('is_rej', 'sum'),
        rstr_count=('is_rstr', 'sum'),
        total_duration=('duration', 'sum'),
        total_orig_bytes=('orig_bytes', 'sum'),
        total_resp_bytes=('resp_bytes', 'sum')
    ).reset_index()
    
    # Calculate advanced features
    grouped['bytes_ratio'] = grouped['total_orig_bytes'] / (grouped['total_resp_bytes'] + 1)
    grouped['avg_duration'] = grouped['total_duration'] / (grouped['conn_count'] + 0.001)
    
    grouped = grouped[grouped['conn_count'] > 0]
    return grouped

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    baseline_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/baseline.log")
    attack_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/pure_attack.log")
    
    logging.info("--- PHASE 1: Supervised Learning (Random Forest) ---")
    
    logging.info(f"Loading Baseline from {baseline_path}...")
    try:
        df_baseline = parse_zeek_log(baseline_path)
    except FileNotFoundError:
        logging.error("File baseline.log not found!")
        return
    
    logging.info(f"Loading Pure Attack Set from {attack_path}...")
    try:
        df_attack = parse_zeek_log(attack_path)
    except FileNotFoundError:
        logging.error("File pure_attack.log not found!")
        return
    
    logging.info("Applying 2-second window aggregation and labeling data...")
    df_base_agg = feature_engineering(df_baseline)
    df_base_agg['label'] = 0 # 0 = Normal
    
    df_attack_agg = feature_engineering(df_attack)
    df_attack_agg['label'] = 1 # 1 = Attack
    
    # Combine datasets
    df_full = pd.concat([df_base_agg, df_attack_agg], ignore_index=True)
    
    logging.info(f"Total Normal Windows: {len(df_base_agg)}")
    logging.info(f"Total Attack Windows: {len(df_attack_agg)}")
    
    # Features for the model
    features = ['conn_count', 'unique_ports', 'rej_count', 'rstr_count', 
                'total_duration', 'total_orig_bytes', 'total_resp_bytes', 
                'bytes_ratio', 'avg_duration']
    
    X = df_full[features]
    y = df_full['label']
    
    # Split into Train and Test (70% Train, 30% Test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
    
    # Normalization (StandardScaler)
    logging.info("\nData Normalization (StandardScaler)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Model Training
    logging.info("Training Random Forest Classifier on labeled traffic...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_scaled, y_train)
    
    # Save models
    model_path = os.path.join(current_dir, "ids_model.pkl")
    scaler_path = os.path.join(current_dir, "ids_scaler.pkl")
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)
    logging.info(f"Model and Scaler saved to {current_dir}!")
    
    # Evaluation
    logging.info("\nEvaluating model on the unseen Test Set (30%)...")
    y_pred = model.predict(X_test_scaled)
    
    acc = accuracy_score(y_test, y_pred)
    logging.info(f"\n--- TEST RESULTS (Accuracy: {acc * 100:.2f}%) ---")
    print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))

if __name__ == "__main__":
    main()
