#!/usr/bin/env python3
import time
import os
import pandas as pd
import joblib
import logging
import subprocess
import warnings
from collections import defaultdict

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def tail_and_predict(log_file, model_path, scaler_path, iso_model_path):
    """
    Reads the conn.log file in real-time, maintains a 2-second rolling window 
    per IP, evaluates it using the HYBRID ML model, and updates iptables.
    """
    logging.info("Loading Machine Learning models (Hybrid) and Scaler...")
    try:
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        iso_model = joblib.load(iso_model_path)
    except Exception as e:
        logging.error(f"Error loading model/scaler: {e}")
        return

    # Keep track of IPs we have already blocked to avoid flooding the gateway with iptables rules.
    blocked_ips = set()
    
    # Dictionary to keep a rolling window of recent connections per IP.
    # Format: { 'ip_address': [ (ts, resp_p, is_rej, is_rstr, duration, orig_bytes, resp_bytes), ... ] }
    recent_conns = defaultdict(list)
    WINDOW_SIZE = 2.0 # seconds
    
    logging.info(f"Listening in real-time on file: {log_file}")
    logging.info("Waiting for new traffic...")
    
    with open(log_file, 'r') as f:
        # Move the pointer to the END of the file to only analyze new events
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                # If there's nothing new, wait half a second
                time.sleep(0.5)
                continue
                
            if line.startswith('#'):
                continue
                
            parts = line.strip().split('\t')
            if len(parts) < 21:
                continue
                
            # Extract values from Zeek columns (standard position)
            ts, _, orig_h, _, _, resp_p, _, _, duration, orig_bytes, resp_bytes, conn_state = parts[:12]
            
            # If the IP is already in our blacklist, don't waste CPU analyzing it
            if orig_h in blocked_ips:
                continue
                
            try:
                current_ts = float(ts)
                resp_p = int(resp_p)
                duration = float(duration) if duration != '-' else 0.0
                orig_bytes = float(orig_bytes) if orig_bytes != '-' else 0.0
                resp_bytes = float(resp_bytes) if resp_bytes != '-' else 0.0
                is_rej = 1 if conn_state == 'REJ' else 0
                is_rstr = 1 if conn_state == 'RSTR' else 0
            except ValueError:
                continue # Skip malformed lines
                
            # Add new connection to the history
            recent_conns[orig_h].append((current_ts, resp_p, is_rej, is_rstr, duration, orig_bytes, resp_bytes))
            
            # Remove connections outside the 2-second window
            recent_conns[orig_h] = [
                conn for conn in recent_conns[orig_h] 
                if conn[0] >= current_ts - WINDOW_SIZE
            ]
            
            # Calculate aggregated features for the current window
            window = recent_conns[orig_h]
            conn_count = len(window)
            unique_ports = len(set(conn[1] for conn in window))
            rej_count = sum(conn[2] for conn in window)
            rstr_count = sum(conn[3] for conn in window)
            total_duration = sum(conn[4] for conn in window)
            total_orig_bytes = sum(conn[5] for conn in window)
            total_resp_bytes = sum(conn[6] for conn in window)
            bytes_ratio = total_orig_bytes / (total_resp_bytes + 1)
            avg_duration = total_duration / (conn_count + 0.001)
            
            features = pd.DataFrame([{
                'conn_count': conn_count,
                'unique_ports': unique_ports,
                'rej_count': rej_count,
                'rstr_count': rstr_count,
                'total_duration': total_duration,
                'total_orig_bytes': total_orig_bytes,
                'total_resp_bytes': total_resp_bytes,
                'bytes_ratio': bytes_ratio,
                'avg_duration': avg_duration
            }])
            
            # Scale features
            features_scaled = scaler.transform(features)
            
            # Feature Stacking: Unsupervised -> Supervised
            import numpy as np
            anomaly_score = iso_model.decision_function(features_scaled).reshape(-1, 1)
            features_stacked = np.hstack((features_scaled, anomaly_score))
            
            # Predict
            prediction = model.predict(features_stacked)[0]
            
            if prediction == 1: # Anomaly / Attack (RandomForest outputs 1 for Attack)
                logging.warning(f"⚠️ ANOMALY DETECTED! Source: {orig_h}")
                logging.warning(f"   Details: {conn_count} conns, {unique_ports} unique ports, {rej_count} REJ in the last {WINDOW_SIZE}s")
                logging.warning(f"🛡️  Executing firewall block on IP {orig_h}...")
                
                # Command to have the gateway insert an iptables rule on the fly
                current_dir = os.path.dirname(os.path.abspath(__file__))
                lab_dir = os.path.join(current_dir, "../../lab")
                
                # Block traffic passing through the gateway (FORWARD)
                cmd_fw = f"cd {lab_dir} && kathara exec gateway -- iptables -I FORWARD -s {orig_h} -j DROP"
                
                try:
                    subprocess.run(cmd_fw, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    logging.info(f"✅ IP {orig_h} successfully added to the Gateway Blacklist!")
                    blocked_ips.add(orig_h)
                    # Clear history for blocked IP to save memory
                    del recent_conns[orig_h]
                except subprocess.CalledProcessError:
                    logging.error(f"❌ Impossible to send iptables command to Kathara.")

if __name__ == "__main__":
    # Relative paths
    current_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/conn.log")
    model_p = os.path.join(current_dir, "../ml_pipeline/ids_model.pkl")
    scaler_p = os.path.join(current_dir, "../ml_pipeline/ids_scaler.pkl")
    iso_p = os.path.join(current_dir, "../ml_pipeline/ids_iso_model.pkl")
    
    if not os.path.exists(model_p):
        logging.error("Model not found. Run 'python3 src/ml_pipeline/train_ids.py' first to create it.")
        exit(1)
        
    tail_and_predict(log_path, model_p, scaler_p, iso_p)
