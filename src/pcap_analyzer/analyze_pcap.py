#!/usr/bin/env python3
import sys
import os
import subprocess
import shutil
import joblib
import pandas as pd
import re
import tempfile
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Import modules from our ml_pipeline
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
try:
    from ml_pipeline.train_ids import parse_zeek_log, feature_engineering
except ImportError:
    logging.error("Make sure to run this script from the project root or src directory.")
    sys.exit(1)

def run_zeek_on_pcap(pcap_path, output_dir):
    """Uses Docker to run Zeek on the PCAP and outputs logs to output_dir."""
    logging.info(f"Extracting logs from {pcap_path} using Zeek (Docker)...")
    
    # Check if docker is running
    try:
        subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        logging.error("Docker is not running. Please start Docker Desktop first.")
        sys.exit(1)
    
    abs_pcap = os.path.abspath(pcap_path)
    abs_out = os.path.abspath(output_dir)
    
    # docker run --rm -v /path/to/pcap:/pcap -v /path/to/out:/out -w /out zeek/zeek:latest zeek -r /pcap/file.pcap LogAscii::use_json=F
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{os.path.dirname(abs_pcap)}:/pcap_dir",
        "-v", f"{abs_out}:/out",
        "-w", "/out",
        "zeek/zeek:latest",
        "zeek", "-r", f"/pcap_dir/{os.path.basename(abs_pcap)}", "LogAscii::use_json=F"
    ]
    
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        logging.info("Zeek analysis complete.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error running Zeek on Docker: {e}")
        sys.exit(1)

def analyze_l7_http(http_log_path):
    """Parses HTTP logs using Regex WAF rules."""
    if not os.path.exists(http_log_path):
        return
        
    logging.info("--- Phase 2: Layer 7 WAF Analysis ---")
    attack_signatures = [
        (r"UNION.+SELECT", "SQL Injection"),
        (r"1\s*(?:'|\")\s*OR\s*(?:'|\")\s*1\s*=\s*(?:'|\")\s*1", "SQL Injection"),
        (r"<script>.*?</script>", "Cross-Site Scripting (XSS)"),
        (r"(?:\.\./)+", "Path Traversal")
    ]
    
    with open(http_log_path, 'r') as f:
        lines = f.readlines()
        
    for line in lines:
        if line.startswith('#'): continue
        parts = line.strip().split('\t')
        if len(parts) >= 10:
            ts, uid, orig_h, orig_p, resp_h, resp_p, trans_depth, method, host, uri = parts[:10]
            for pattern, attack_name in attack_signatures:
                if re.search(pattern, uri, re.IGNORECASE):
                    logging.warning(f"🚨 WEB ATTACK DETECTED! Type: {attack_name}")
                    logging.warning(f"   Source IP: {orig_h} | Target: {resp_h} | URI: {uri}")
                    break

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_pcap.py <path_to_pcap_file>")
        sys.exit(1)
        
    pcap_path = sys.argv[1]
    if not os.path.exists(pcap_path):
        logging.error(f"PCAP file {pcap_path} not found.")
        sys.exit(1)
        
    # Create temporary directory for Zeek logs
    with tempfile.TemporaryDirectory() as temp_dir:
        run_zeek_on_pcap(pcap_path, temp_dir)
        
        conn_log = os.path.join(temp_dir, "conn.log")
        http_log = os.path.join(temp_dir, "http.log")
        
        if not os.path.exists(conn_log):
            logging.error("Zeek did not generate conn.log. Ensure the PCAP contains valid IP traffic.")
            return
            
        logging.info("--- Phase 1: Machine Learning (L3/L4) Analysis ---")
        df = parse_zeek_log(conn_log)
        df_agg = feature_engineering(df)
        
        if df_agg.empty:
            logging.info("No connections found for 2-second window aggregation.")
            return
            
        features = ['conn_count', 'unique_ports', 'rej_count', 'rstr_count', 'total_duration', 'total_orig_bytes', 'total_resp_bytes', 'bytes_ratio', 'avg_duration']
        X = df_agg[features]
        
        # Load models
        current_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.abspath(os.path.join(current_dir, "../ml_pipeline/ids_model.pkl"))
        scaler_path = os.path.abspath(os.path.join(current_dir, "../ml_pipeline/ids_scaler.pkl"))
        
        if not os.path.exists(model_path) or not os.path.exists(scaler_path):
            logging.error(f"ML models not found at {model_path}. Run train_ids.py first.")
            return
            
        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)
        
        X_scaled = scaler.transform(X)
        predictions = model.predict(X_scaled)
        df_agg['prediction'] = predictions
        
        anomalies = df_agg[df_agg['prediction'] == 1]
        
        if not anomalies.empty:
            logging.warning(f"🚨 ML DETECTED {len(anomalies)} MALICIOUS ACTIVITY WINDOWS!")
            for idx, row in anomalies.iterrows():
                logging.warning(f"   Attacker IP: {row['id.orig_h']} | Conns: {row['conn_count']} | Rejects: {row['rej_count']}")
        else:
            logging.info("✅ ML Model found NO network anomalies (Layer 3/4).")
            
        # Layer 7 Analysis
        analyze_l7_http(http_log)
        
        logging.info("Analysis Complete. Temporary logs cleaned up.")

if __name__ == "__main__":
    main()
