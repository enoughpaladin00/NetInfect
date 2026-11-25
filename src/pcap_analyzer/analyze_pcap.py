#!/usr/bin/env python3
import sys
import os
import subprocess
import shutil
import tempfile
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Shared modules: same features, models and L7 rules as the live pipeline
SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(SRC, 'ml_pipeline'))
sys.path.insert(0, os.path.join(SRC, 'active_response'))
from features import FEATURES, build_features, parse_zeek_log  # noqa: E402
from model_store import ModelIntegrityError, load_models, score  # noqa: E402
from waf_rules import match  # noqa: E402

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
    """Run the same L7 signatures used live by http_analyzer.py."""
    if not os.path.exists(http_log_path):
        return

    logging.info("--- Phase 2: Layer 7 signature analysis ---")
    with open(http_log_path, 'r') as f:
        for line in f:
            if line.startswith('#'):
                continue
            parts = line.rstrip('\n').split('\t')
            if len(parts) >= 10:
                orig_h, resp_h, uri = parts[2], parts[4], parts[9]
                attack, decoded = match(uri)
                if attack:
                    shown = ''.join(c if c.isprintable() else '?' for c in decoded)[:120]
                    logging.warning(f"🚨 WEB ATTACK DETECTED! Type: {attack}")
                    logging.warning(f"   Source IP: {orig_h} | Target: {resp_h} | URI: {shown}")


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
        if df.empty:
            logging.info("No connections found.")
            return
        feats = build_features(df)

        try:
            iso_model, model, manifest = load_models()
        except (FileNotFoundError, ModelIntegrityError) as e:
            logging.error(e)
            return

        proba, _ = score(iso_model, model, feats[FEATURES])
        feats['proba'] = proba
        flagged = feats[feats['proba'] >= manifest['alert_threshold']]

        if not flagged.empty:
            logging.warning(f"🚨 ML flagged {len(flagged)} of {len(feats)} connections as malicious")
            summary = flagged.groupby('src_ip').agg(
                connections=('proba', 'size'), max_proba=('proba', 'max'),
                max_conns_in_window=('conn_count', 'max'), rejects=('rej_count', 'max'))
            for ip, row in summary.iterrows():
                action = "BLOCK" if row['max_proba'] >= manifest['block_threshold'] else "ALERT"
                logging.warning(f"   [{action}] {ip} | flagged conns: {row['connections']} | "
                                f"max p={row['max_proba']:.2f} | max conns/window: {row['max_conns_in_window']}")
        else:
            logging.info("✅ ML Model found NO network anomalies (Layer 3/4).")

        # Layer 7 Analysis
        analyze_l7_http(http_log)
        
        logging.info("Analysis Complete. Temporary logs cleaned up.")

if __name__ == "__main__":
    main()
