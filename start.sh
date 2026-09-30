#!/bin/bash
# start.sh - Avvia i 4 componenti di NetInfect in terminali separati su macOS

PROJECT_DIR=$(pwd)

echo "🚀 Avvio dell'ambiente NetInfect in 4 finestre del Terminale..."

# 1. Terminale principale per Kathara
osascript -e 'tell app "Terminal" to do script "echo \"[1] KATHARA TERMINAL\" && cd '$PROJECT_DIR'/lab && echo \"Avvio laboratorio in corso...\" && kathara lstart && echo \"✅ Kathara pronto. Esegui i tuoi comandi qui (es. vstart client_1, ecc).\" && bash"'

# 2. Terminale per L3/L4 IDS (Firewall Manager)
osascript -e 'tell app "Terminal" to do script "echo \"[2] L3/L4 IDS FAST PATH\" && cd '$PROJECT_DIR' && source .venv/bin/activate && python3 src/active_response/firewall_manager.py"'

# 3. Terminale per L7 WAF (HTTP Analyzer)
osascript -e 'tell app "Terminal" to do script "echo \"[3] L7 WAF HTTP ANALYZER\" && cd '$PROJECT_DIR' && source .venv/bin/activate && python3 src/active_response/http_analyzer.py"'

# 4. Terminale per Dashboard Streamlit
osascript -e 'tell app "Terminal" to do script "echo \"[4] STREAMLIT DASHBOARD\" && cd '$PROJECT_DIR' && source .venv/bin/activate && streamlit run src/dashboard/app.py"'

echo "✅ Fatto! Controlla le nuove finestre che si sono aperte."
echo "Per spegnere tutto, chiudi le finestre ed esegui ./stop.sh"
