#!/usr/bin/env python3
import os
import sys
import pandas as pd
import subprocess

def unblock_ip(ip):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    lab_dir = os.path.join(current_dir, "../../lab")
    
    # 1. Unblock on Kathara gateway (L3/L4 FW)
    cmd_fw = f"cd {lab_dir} && kathara exec gateway -- iptables -D FORWARD -s {ip} -j DROP"
    print(f"Removing {ip} from Gateway iptables...")
    try:
        subprocess.run(cmd_fw, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"✅ IP {ip} removed from iptables.")
    except subprocess.CalledProcessError:
        print(f"⚠️ Failed to remove {ip} from iptables. Maybe it wasn't blocked.")
        
    # Also remove from L7 WAF (if blocked via nginx)
    cmd_waf = f"cd {lab_dir} && kathara exec gateway -- iptables -D FORWARD -p tcp --dport 80 -s {ip} -j REJECT"
    try:
        subprocess.run(cmd_waf, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"✅ IP {ip} removed from L7 WAF.")
    except subprocess.CalledProcessError:
        pass

    # 2. Remove from alerts.csv
    alert_log_path = os.path.join(current_dir, "../../lab/shared/zeek_logs/alerts.csv")
    if os.path.exists(alert_log_path):
        try:
            df_alerts = pd.read_csv(alert_log_path)
            df_filtered = df_alerts[df_alerts['attacker_ip'] != ip]
            df_filtered.to_csv(alert_log_path, index=False)
            print(f"✅ IP {ip} removed from alerts.csv.")
        except Exception as e:
            print(f"❌ Error updating alerts.csv: {e}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Unblock an IP from the IDS/Firewall")
    parser.add_argument("ip", help="The IP address to unblock")
    args = parser.parse_args()
    unblock_ip(args.ip)
