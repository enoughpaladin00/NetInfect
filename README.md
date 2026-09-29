# ML-Driven Network Intrusion Detection System

An end-to-end, Software-Defined Networking (SDN) style Intrusion Detection System (IDS) and Active Response firewall. This project uses **Kathara** (Docker-based network emulation) to simulate a corporate network, **Zeek** for deep packet inspection, and **Machine Learning (Isolation Forest)** to detect and block zero-day attacks in real-time.

---

## 🏗 Architecture

The virtual laboratory consists of a simple corporate topology:
- **`gateway`**: The central router equipped with Zeek (Network Security Monitor).
- **`server_1` & `server_2`**: Internal web/SSH servers.
- **`client_1` & `client_2`**: Internal workstations generating normal background traffic.
- **`quarantine`**: An isolated network segment for potential future use.

## ✨ Features

1. **Realistic Traffic Generation (`baseline_traffic.py`)**: Simulates human-like HTTP and SSH connections to the servers to build a "clean" dataset.
2. **Network Monitoring**: The gateway runs Zeek to sniff the `eth0` interface and log all connections to `conn.log`.
3. **Attack Simulation (`anomaly_traffic.py`)**: A controlled script that performs rapid port scanning and SSH brute-force attacks.
4. **Machine Learning Pipeline (`train_ids.py`)**: Uses Scikit-Learn's `IsolationForest` to analyze the Zeek logs. It learns the baseline normal traffic and flags anomalous connection bursts.
5. **Active Response (`firewall_manager.py`)**: A real-time controller running on the host. It tails the `conn.log`, passes live data to the trained ML model, and dynamically injects `iptables` rules into the Kathara gateway to drop traffic from the attacker's IP.

---

## 🚀 Prerequisites

Ensure you have the following installed on your machine:
- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [Kathara](https://github.com/KatharaFramework/Kathara)
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

3. **Build the Custom Docker Images (Optional but recommended):**
   The lab uses custom `host` and `gateway` images. Kathara will build them automatically if they don't exist.

---

## 🎮 Usage Guide

### Step 1: Start the Laboratory
Start the network simulation. The clients will automatically begin generating normal background traffic.
```bash
cd lab
kathara lstart
cd ..
```

### Step 2: Build the Training Dataset
Let the lab run for 1-2 minutes to gather enough normal traffic. Then, save the baseline log:
```bash
cp lab/shared/zeek_logs/conn.log lab/shared/zeek_logs/baseline.log
```

### Step 3: Generate Attack Traffic
Log into the client container and execute the attack script:
```bash
kathara connect client_1
# Inside the container:
python3 /shared/anomaly_traffic.py
exit
```
Save the log containing the attack:
```bash
cp lab/shared/zeek_logs/conn.log lab/shared/zeek_logs/test_attack.log
```

### Step 4: Train the Machine Learning Model
Train the Isolation Forest model. It will learn from `baseline.log` and validate against `test_attack.log`.
```bash
python3 src/ml_pipeline/train_ids.py
```
*This will generate `ids_model.pkl` and `ids_columns.pkl`.*

### Step 5: Test the Active Response (Firewall Manager)
Open **two** terminal windows.

**Terminal 1 (The Sentinel):**
Start the real-time ML monitoring script:
```bash
source .venv/bin/activate
python3 src/active_response/firewall_manager.py
```

**Terminal 2 (The Attacker):**
Trigger the attack again:
```bash
kathara connect client_1
python3 /shared/anomaly_traffic.py
```

**Result:** Within milliseconds of the attack starting, Terminal 1 will detect the anomaly and automatically inject an `iptables` DROP rule into the Gateway, neutralizing the attacker in Terminal 2.

### Step 6: Teardown
Once you're done, safely destroy the lab environment:
```bash
kathara wipe
deactivate
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
│   ├── traffic_generation/
│   │   ├── baseline_traffic.py  # Legitimate traffic simulator
│   │   └── anomaly_traffic.py   # Port scan & brute-force script
│   ├── ml_pipeline/
│   │   └── train_ids.py         # Isolation Forest training script
│   └── active_response/
│       └── firewall_manager.py  # Real-time monitor and iptables controller
├── requirements.txt           # Python dependencies
└── README.md
```

---

*Disclaimer: This project is an educational sandbox designed to demonstrate the integration of Software-Defined Networking, Machine Learning, and active defense mechanisms.*
