# NetInfect - ML-Driven Network Intrusion Detection System (V2)

An end-to-end, Software-Defined Networking (SDN) style Intrusion Detection System (IDS) and Active Response firewall. This project uses **Kathara** (Docker-based network emulation) to simulate a corporate network, **Zeek** for deep packet inspection, and **Supervised Machine Learning (Random Forest)** to detect and block attacks in real-time.

---

## 🏗 Architecture

The virtual laboratory consists of a simple corporate topology:
- **`gateway`**: The central router equipped with Zeek (Network Security Monitor) and `iptables`.
- **`server_1` & `server_2`**: Internal web/SSH servers.
- **`client_1` & `client_2`**: Internal workstations generating normal background traffic.
- **`quarantine`**: An isolated network segment for potential future use.

## ✨ Features (Version 2.0)

1. **Realistic Traffic Generation (`baseline_traffic.py`)**: Simulates human-like HTTP and SSH connections to the servers to build a "clean" dataset.
2. **Network Monitoring**: The gateway runs Zeek to sniff the `eth0` interface and log all connections to `conn.log`.
3. **Attack Simulation (`anomaly_traffic.py`)**: A controlled script that performs rapid port scanning and SSH brute-force attacks.
4. **Supervised Machine Learning Pipeline (`train_ids.py`)**: Uses Scikit-Learn's `RandomForestClassifier` with time-based windowing (2-second aggregation) and `StandardScaler` to detect L3/L4 network anomalies (e.g., Port Scans, DoS) with high accuracy.
5. **Layer 7 WAF (Web Application Firewall) (`http_analyzer.py`)**: Analyzes Zeek's `http.log` using Regex signatures to instantly detect and block web attacks such as SQL Injections, XSS, and Path Traversal.
6. **Real-Time Streamlit Dashboard (`app.py`)**: A modern, live-updating graphical interface to visualize network traffic, connections per port, blocked IPs, and real-time WAF alerts.
7. **Universal PCAP Offline Analysis (`analyze_pcap.py`)**: Don't want to run the full Kathara lab? No problem. Feed any `.pcap` file to the analyzer, and it will use a lightweight Zeek Docker container to extract logs and run the ML and L7 pipelines offline.
8. **Active Response (`firewall_manager.py`)**: A real-time controller that tails Zeek logs, passes live data to the trained ML model, and dynamically injects `iptables` rules into the Kathara gateway to drop traffic from attacker IPs.

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

**Step 1: Start the Laboratory**
Start the network simulation. The clients will automatically begin generating normal background traffic.
```bash
cd lab
kathara lstart
cd ..
```

**Step 2: Train the Machine Learning Model**
The repository comes with a pre-trained model. If you wish to retrain it using the `baseline.log` and `pure_attack.log` found in `lab/shared/zeek_logs/`, run:
```bash
source .venv/bin/activate
python3 src/ml_pipeline/train_ids.py
```

**Step 3: Launch the Visual Dashboard**
Open a new terminal and run:
```bash
source .venv/bin/activate
streamlit run src/dashboard/app.py
```

**Step 4: Start the Firewalls (L3/L4 ML and L7 WAF)**
Open another terminal:
```bash
source .venv/bin/activate
python3 src/active_response/firewall_manager.py &
python3 src/active_response/http_analyzer.py &
```

**Step 5: Generate Attack Traffic**
Trigger the attack from the client:
```bash
cd lab
kathara connect client_1
python3 /shared/anomaly_traffic.py
```
*Watch the Streamlit Dashboard and the Firewall terminal as the attacks are detected and blocked in real-time!*

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
