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
    
    # IP Reputation variables (Slow Path)
    ip_reputation = defaultdict(float)
    last_seen = defaultdict(float)
    REPUTATION_THRESHOLD = 100.0
    DECAY_RATE = 2.0  # Points to decay per second
    
    logging.info(f"Listening in real-time on file: {log_file}")
    
    alert_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../lab/shared/zeek_logs/alerts.csv")
    last_alert_mtime = 0
    
    while not os.path.exists(log_file):
        time.sleep(2)
        
    logging.info("Waiting for new traffic...")
    
    with open(log_file, 'r') as f:
        # Move the pointer to the END of the file to only analyze new events
        f.seek(0, os.SEEK_END)
        
        while True:
            # Sync blocked_ips with alerts.csv to support manual unblocking
            if os.path.exists(alert_log_path):
                try:
                    current_mtime = os.path.getmtime(alert_log_path)
                    if current_mtime > last_alert_mtime:
                        df_sync = pd.read_csv(alert_log_path)
                        blocked_ips = set(df_sync['attacker_ip'].tolist())
                        last_alert_mtime = current_mtime
                except Exception:
                    pass

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
            
            # --- UPDATE IP REPUTATION (SLOW PATH) ---
            if orig_h in last_seen:
                time_passed = current_ts - last_seen[orig_h]
                decay = time_passed * DECAY_RATE
                ip_reputation[orig_h] = max(0.0, ip_reputation[orig_h] - decay)
            last_seen[orig_h] = current_ts
            
            # Base penalty for connection
            ip_reputation[orig_h] += 0.5
            if is_rej:
                ip_reputation[orig_h] += 20.0
            if is_rstr:
                ip_reputation[orig_h] += 10.0
                
            is_reputation_breach = ip_reputation[orig_h] >= REPUTATION_THRESHOLD
            
            if prediction == 1 or is_reputation_breach:
                reason = "ML-IDS Fast Path" if prediction == 1 else f"Reputation Breach ({ip_reputation[orig_h]:.1f}/100)"
                logging.warning(f"⚠️ ANOMALY DETECTED! Source: {orig_h}")
                logging.warning(f"   Reason: {reason} | {conn_count} conns, {unique_ports} ports, {rej_count} REJ in {WINDOW_SIZE}s")
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
                    
                    # Log the alert to a CSV for the Dashboard
                    alert_log_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/alerts.csv")
                    if not os.path.exists(alert_log_path):
                        with open(alert_log_path, "w") as alert_f:
                            alert_f.write("timestamp,attacker_ip,reason\n")
                    
                    with open(alert_log_path, "a") as alert_f:
                        alert_f.write(f"{int(time.time())},{orig_h},{reason}\n")
                        
                    # Clear history for blocked IP to save memory
                    if orig_h in recent_conns: del recent_conns[orig_h]
                    if orig_h in ip_reputation: del ip_reputation[orig_h]
                    if orig_h in last_seen: del last_seen[orig_h]
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
