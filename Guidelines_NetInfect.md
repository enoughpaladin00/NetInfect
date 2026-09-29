# Progetto: Kathara ML-IDS & Malware Propagation Simulation
## Linee Guida per Antigravity (AI Assistant)

### 1. Panoramica del Progetto
Questo progetto consiste in una simulazione end-to-end di una rete informatica vulnerabile, infettata da un worm auto-propagante, monitorata da un sistema di Intrusion Detection (IDS) basato su Machine Learning non supervisionato. L'obiettivo è generare un ambiente di test per analizzare i movimenti laterali del malware e testare pipeline di Machine Learning Security.

**Ruolo di Antigravity:** 
Assistere lo sviluppatore nella scrittura dei file di configurazione (`.lab`, `lab.conf`, Dockerfiles) per Kathara, nello scripting Python/Bash per la generazione del traffico, nella stesura del malware e nello sviluppo del modello di Anomaly Detection in Python.

### 2. Stack Tecnologico
*   **Infrastruttura di Rete:** Kathara (Docker-based), interfacce virtuali, routing statico/dinamico.
*   **Generazione Traffico (Background):** Python (Requests, Paramiko per SSH), Bash, Cronjobs.
*   **Malware/Worm:** Python/Go (Socket programming, nmap/scapy per port scanning, exploit simulato).
*   **Network Monitoring:** Zeek (Bro) IDS per la generazione di file di log transazionali (`conn.log`).
*   **Machine Learning:** Python, Pandas, Scikit-Learn (Isolation Forest) o PyTorch (Autoencoder).
*   **Risposta Attiva:** iptables, script Python per l'iniezione dinamica di regole di drop.

### 3. Architettura di Rete (Topologia Kathara)
La rete deve essere suddivisa in tre domini principali:
1.  **Gateway/Monitor:** Un router centrale configurato con interfacce di promiscuous mode/port mirroring. Qui gira Zeek per estrarre le feature di rete in tempo reale.
2.  **Sottorete Vulnerabile:** Un pool di host containerizzati (es. `server_1`, `server_2`, `client_1`). Devono esporre servizi deboli (es. SSH con password banali, HTTP) e generare traffico legittimo continuo.
3.  **Cella di Quarantena (Sandbox):** Rete isolata per la detonazione sicura di sample specifici senza routing verso l'esterno.

### 4. Fasi di Sviluppo (Milestones)

#### Milestone 1: Setup Infrastruttura (Kathara)
*   [ ] Scrivere il file `lab.conf` per definire la topologia (gateway, switch, host).
*   [ ] Creare i file `.startup` per configurare IP, routing e servizi di base (SSH, Apache).
*   [ ] Verificare la connettività end-to-end (ping, traceroute).

#### Milestone 2: Baseline Traffic Generation
*   [ ] Creare script Python `traffic_gen.py` per simulare navigazione web e login SSH tra i container.
*   [ ] Automatizzare l'esecuzione del traffico tramite job in background all'avvio dei container.
*   [ ] Configurare Zeek sul Gateway per generare log puliti del traffico "normale".

#### Milestone 3: Sviluppo del Worm Simulato
*   [ ] Sviluppare un payload in Python che esegue un port scan sulla sua subnet (`/24`).
*   [ ] Implementare un modulo di brute-force SSH basato su un dizionario ristretto.
*   [ ] Implementare la logica di auto-replica: se il login ha successo, il worm si copia tramite SCP e si auto-esegue sul nuovo target.

#### Milestone 4: Pipeline ML e Anomaly Detection
*   [ ] Estrarre feature dai log di Zeek (durata, byte trasferiti, tentativi di connessione).
*   [ ] Addestrare un modello non supervisionato (Isolation Forest o Autoencoder) esclusivamente sul traffico di baseline (Milestone 2).
*   [ ] Introdurre il worm (Milestone 3) e calcolare l'Anomaly Score sulle deviazioni del traffico.

#### Milestone 5: Active Response & Documentazione
*   [ ] Scrivere uno script sul Gateway che legge in tempo reale l'output del modello ML.
*   [ ] Se viene rilevata un'anomalia prolungata, aggiungere dinamicamente una regola `iptables` per droppare il traffico dell'IP infetto.
*   [ ] Raccogliere i risultati, diagrammi a grafo dei movimenti laterali e le metriche di accuratezza per il README.

### 5. Linee Guida per il Codice
*   **Modularità:** Ogni script (worm, ML, infrastruttura) deve vivere in directory separate.
*   **Riproducibilità:** Il lab Kathara deve potersi avviare ed eseguire con un solo comando `kathara lstart`. I requirement Python devono essere gestiti tramite `requirements.txt` o immagini Docker custom estese dalle base image di Kathara.
*   **Sicurezza:** Il worm deve avere meccanismi di *kill switch* o limiti di TTL (Time-To-Live) per evitare runaway loop che blocchino l'host fisico.
