#!/usr/bin/env python3
import time
import os
import pandas as pd
import joblib
import logging
import subprocess
import warnings

# Ignore pandas warnings
warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

def tail_and_predict(log_file, model_path, columns_path):
    """
    Reads the conn.log file in real-time, uses the ML model to evaluate
    connections, and sends iptables commands to the gateway if anomalies are found.
    """
    logging.info("Loading Machine Learning model...")
    try:
        model = joblib.load(model_path)
        expected_columns = joblib.load(columns_path)
    except Exception as e:
        logging.error(f"Error loading model: {e}")
        return

    # Keep track of IPs we have already blocked to avoid flooding the gateway with iptables rules.
    blocked_ips = set()
    
    # Fixed categories used during training
    zeek_states = ['S0', 'S1', 'SF', 'REJ', 'S2', 'S3', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'SH', 'SHR', 'OTH']
    zeek_services = ['http', 'ssh', 'dns', 'ftp', 'ssl', '0']
    
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
            orig_h, resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state = parts[2], parts[5], parts[6], parts[7], parts[8], parts[9], parts[10], parts[11]
            
            # If the IP is already in our blacklist, don't waste CPU analyzing it
            if orig_h in blocked_ips:
                continue
                
            # Prepare data for the model
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
            
            # Preprocessing (Identical to training)
            df['conn_state'] = pd.Categorical(df['conn_state'], categories=zeek_states)
            df['service'] = pd.Categorical(df['service'], categories=zeek_services)
            df['proto'] = pd.Categorical(df['proto'], categories=['tcp', 'udp', 'icmp'])
            
            df_dummies = pd.get_dummies(df, columns=['proto', 'service', 'conn_state'])
            df_model = df_dummies.reindex(columns=expected_columns, fill_value=0)
            
            # --- PREDICTION ---
            prediction = model.predict(df_model)[0]
            
            if prediction == -1: # Anomaly Detected!
                logging.warning(f"⚠️ ANOMALY DETECTED! Source: {orig_h} (Dest Port: {resp_p}, State: {conn_state})")
                logging.warning(f"🛡️  Executing firewall block on IP {orig_h}...")
                
                # Command to have the gateway insert an iptables rule on the fly
                current_dir = os.path.dirname(os.path.abspath(__file__))
                lab_dir = os.path.join(current_dir, "../../lab")
                
                # Block traffic passing through the gateway (FORWARD)
                cmd_fw = f"cd {lab_dir} && kathara exec gateway -- iptables -I FORWARD -s {orig_h} -j DROP"
                
                try:
                    subprocess.run(cmd_fw, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    logging.info(f"✅ IP {orig_h} successfully added to the Gateway Blacklist!")
                    blocked_ips.add(orig_h) # Do not analyze/block this IP again
                except subprocess.CalledProcessError:
                    logging.error(f"❌ Impossible to send iptables command to Kathara.")

if __name__ == "__main__":
    # Relative paths
    current_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/conn.log")
    model_p = os.path.join(current_dir, "../ml_pipeline/ids_model.pkl")
    cols_p = os.path.join(current_dir, "../ml_pipeline/ids_columns.pkl")
    
    if not os.path.exists(model_p):
        logging.error("Model not found. Run 'python3 src/ml_pipeline/train_ids.py' first to create it.")
        exit(1)
        
    tail_and_predict(log_path, model_p, cols_p)
