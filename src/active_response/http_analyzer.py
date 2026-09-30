#!/usr/bin/env python3
import time
import os
import re
import logging
import subprocess

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# Regex patterns for common Web Attacks
SQLI_PATTERN = re.compile(r"(union\s+select|select\s+.*\s+from|insert\s+into|1'|'1'='1|--|#|\/\*)", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(<script>|javascript:|onerror=|onload=|%3Cscript%3E)", re.IGNORECASE)
PATH_TRAVERSAL_PATTERN = re.compile(r"(\.\.\/|\.\.\\|etc\/passwd)", re.IGNORECASE)

def tail_http_log(log_file):
    logging.info(f"Layer 7 WAF (Web Application Firewall) started. Monitoring: {log_file}")
    blocked_ips = set()
    
    with open(log_file, 'r') as f:
        f.seek(0, os.SEEK_END)
        
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
                
            if line.startswith('#'):
                continue
                
            parts = line.strip().split('\t')
            # http.log standard Zeek format
            if len(parts) < 10:
                continue
                
            ts, uid, orig_h, orig_p, resp_h, resp_p, trans_depth, method, host, uri = parts[:10]
            
            if orig_h in blocked_ips:
                continue
                
            # Decode URL encoding basics (e.g. %20 -> space) for better regex matching
            from urllib.parse import unquote
            decoded_uri = unquote(uri)
            
            # Check for malicious patterns in the URI
            is_sqli = SQLI_PATTERN.search(decoded_uri)
            is_xss = XSS_PATTERN.search(decoded_uri)
            is_pt = PATH_TRAVERSAL_PATTERN.search(decoded_uri)
            
            if is_sqli or is_xss or is_pt:
                attack_type = "SQL Injection" if is_sqli else ("XSS" if is_xss else "Path Traversal")
                logging.warning(f"🚨 WEB ATTACK (Layer 7) DETECTED! Type: {attack_type}")
                logging.warning(f"   Source IP: {orig_h} | Target: {resp_h} | URI: {decoded_uri}")
                logging.warning(f"🛡️  Executing firewall block on IP {orig_h}...")
                
                current_dir = os.path.dirname(os.path.abspath(__file__))
                lab_dir = os.path.join(current_dir, "../../lab")
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
                        alert_f.write(f"{int(time.time())},{orig_h},WAF: {attack_type} ({decoded_uri})\n")
                        
                except subprocess.CalledProcessError:
                    logging.error(f"❌ Impossible to send iptables command to Kathara.")

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    log_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/http.log")
    
    # Wait for the file to be created by Zeek if it doesn't exist yet
    while not os.path.exists(log_path):
        logging.info("Waiting for Zeek to generate http.log...")
        time.sleep(2)
        
    tail_http_log(log_path)
