# NetInfect: ML-IDS & Malware Propagation Simulation

Questo progetto implementa una simulazione di rete (basata su Kathara) per testare l'efficacia di un Intrusion Detection System (IDS) basato su Machine Learning (ML) nel rilevamento di traffico anomalo (es. movimenti laterali).

## Struttura del Repository

*   `lab/`: Contiene i file di configurazione per il laboratorio Kathara (`lab.conf`, `.startup`).
*   `src/`: Contiene i codici sorgente del progetto, divisi per macro-area:
    *   `traffic_generation/`: Script Python/Bash per simulare traffico di rete legittimo di base.
    *   `ml_pipeline/`: Codice in Python (Scikit-Learn/PyTorch) per l'estrazione di feature dai log di Zeek e l'addestramento del modello di Anomaly Detection (es. Isolation Forest).
    *   `active_response/`: Script per l'integrazione del modello ML con il firewall di rete (iptables) per mitigare le minacce in tempo reale.

## Requisiti

*   [Kathara](https://www.kathara.org/) installato e configurato (con backend Docker).
*   Python 3.8+ (per gli script di simulazione e la pipeline ML).

## Utilizzo

Per avviare l'infrastruttura di base:

```bash
cd lab
kathara lstart
```
Per terminare e pulire il laboratorio:

```bash
kathara lclean
```
