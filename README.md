# NetInfect - ML-Driven Network Intrusion Detection System (V2)

An end-to-end, Software-Defined Networking (SDN) style Intrusion Detection System (IDS) and Active Response firewall. This project uses **Kathara** (Docker-based network emulation) to simulate a corporate network, **Zeek** for deep packet inspection, and **Supervised Machine Learning (Random Forest)** to detect and block attacks in real-time.

---

## 🏗 Architecture

The virtual laboratory mimics a realistic enterprise architecture with three zones:
- **`gateway`**: The central router connecting the zones, equipped with Zeek (Network Security Monitor) and `iptables`.
- **DMZ Network (`server_1`, `server_2`)**: Publicly accessible web and SSH servers.
- **LAN Network (`client_1`, `client_2`)**: Internal corporate workstations generating normal background traffic.
- **WAN Network (`attacker`)**: An external host outside the corporate network used to launch malicious campaigns.

## ✨ Features (Version 2.0)

1. **Realistic Traffic Generation (`baseline_traffic.py`)**: Simulates human-like HTTP and SSH connections to the servers to build a "clean" dataset.
2. **Network Monitoring**: The gateway runs Zeek to sniff the `eth0` interface and log all connections to `conn.log`.
3. **Advanced Attack Simulation (`anomaly_traffic.py`)**: A controlled script that performs multi-stage attacks including Port Scanning, SSH Brute-force, L7 Web Attacks, HTTP DDoS, Slowloris, and Data Exfiltration.
4. **Hybrid Machine Learning Pipeline (`train_ids.py`)**: A state-of-the-art Ensemble architecture that uses **Feature Stacking**. It first evaluates traffic with an Unsupervised model (**Isolation Forest**) to generate an anomaly score, and then feeds that score alongside L3/L4 features into a Supervised model (**Random Forest** with `class_weight='balanced'`) to achieve near-perfect detection of Zero-Day and DoS attacks.
5. **Layer 7 WAF (Web Application Firewall) (`http_analyzer.py`)**: Analyzes Zeek's `http.log` using Regex signatures to instantly detect and block web attacks such as SQL Injections, XSS, and Path Traversal.
6. **Real-Time Streamlit Dashboard (`app.py`)**: A modern, live-updating graphical interface to visualize network traffic, connections per port, blocked IPs, and real-time WAF alerts.
7. **Universal PCAP Offline Analysis (`analyze_pcap.py`)**: Don't want to run the full Kathara lab? No problem. Feed any `.pcap` file to the analyzer, and it will use a lightweight Zeek Docker container to extract logs and run the Hybrid ML and L7 pipelines offline.
8. **Active Response (`firewall_manager.py`)**: A real-time controller that tails Zeek logs, passes live data to the trained Hybrid ML models, and dynamically injects `iptables` rules into the Kathara gateway to drop traffic from attacker IPs.

---

## 🚀 Prerequisites

Ensure you have the following installed on your machine:
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Required for both Kathara and Offline PCAP Analysis)
- [Kathara](https://github.com/KatharaFramework/Kathara) (Only required for the live lab)
- Python 3.10+
- Git

---

## 🛠 Setup & Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd Side_Project
   ```

2. **Set up the Python Virtual Environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

---

## 🎮 Usage Guide

### Option A: The Live Lab (Kathara)

**Step 1: Start the Laboratory (Terminal 1)**
Start the network simulation. The clients will wait 30 seconds to allow the servers to fully boot, and then they will automatically begin generating normal background traffic.
```bash
cd lab
kathara lstart
```

**Step 2: Train the Machine Learning Model**
The repository comes with a pre-trained model. If you wish to retrain it using the `baseline.log` and `pure_attack.log` found in `lab/shared/zeek_logs/`, run:
```bash
source .venv/bin/activate
python3 src/ml_pipeline/train_ids.py
```
*(Note: Wait until Kathara finishes deploying all devices before proceeding to the next steps)*

**Step 3: Start the Firewalls (L3/L4 ML and L7 WAF) (Terminal 2 & 3)**
The firewalls will automatically wait for Zeek to generate the logs if they haven't been created yet.
```bash
# Terminal 2 - ML Firewall
source .venv/bin/activate
python3 src/active_response/firewall_manager.py
```
```bash
# Terminal 3 - L7 WAF
source .venv/bin/activate
python3 src/active_response/http_analyzer.py
```

**Step 4: Launch the Visual Dashboard (Terminal 4)**
Open a new terminal and run:
```bash
source .venv/bin/activate
streamlit run src/dashboard/app.py
```

**Step 4: Launch Targeted Attacks (Terminal 5 or Terminal 1)**
Once you see legitimate traffic flowing on the Dashboard, connect to the attacker machine (WAN zone) to launch your attacks.
```bash
cd lab
kathara connect attacker
```
You can now select which specific attack vector to execute using the `--attack` flag:
```bash
# View help menu
python3 /shared/anomaly_traffic.py --help

# Launch specific attacks
python3 /shared/anomaly_traffic.py --attack web        # SQLi & XSS
python3 /shared/anomaly_traffic.py --attack portscan   # Port Scanning
python3 /shared/anomaly_traffic.py --attack ddos       # HTTP Flood DoS
python3 /shared/anomaly_traffic.py --attack slowloris  # Slowloris DoS

# Launch all attacks sequentially
python3 /shared/anomaly_traffic.py
```
*Watch the Streamlit Dashboard and the Firewall terminals as the attacks are detected and blocked in real-time!*

---

### Option B: Universal PCAP Offline Analysis

You can analyze any existing network capture (`.pcap`) without starting Kathara. This script spins up a temporary Zeek Docker container to extract logs and feeds them to the ML model and WAF.

```bash
source .venv/bin/activate
python3 src/pcap_analyzer/analyze_pcap.py <path_to_your_file.pcap>
```

---

## 📂 Project Structure

```
.
├── lab/
│   ├── lab.conf               # Kathara network topology definition
│   ├── gateway.Dockerfile     # Zeek-enabled router image
│   ├── host.Dockerfile        # Python-enabled host image
│   ├── *.startup              # Boot scripts for network nodes
│   └── shared/                # Volume shared between Host and Containers
│       └── zeek_logs/         # Zeek logs output directory
├── src/
│   ├── traffic_generation/    # Scripts to generate baseline and malicious traffic
│   ├── ml_pipeline/           # Random Forest training and data aggregation
│   ├── active_response/       # L3/L4 ML Firewall and L7 Regex WAF
│   ├── dashboard/             # Real-time Streamlit UI
│   └── pcap_analyzer/         # Offline PCAP analysis using Zeek Docker
├── requirements.txt           # Python dependencies
└── README.md
```

---

*Disclaimer: This project is an educational sandbox designed to demonstrate the integration of Software-Defined Networking, Machine Learning, and active defense mechanisms.*
