import streamlit as st
import pandas as pd
import time
import os
import plotly.express as px

# Configurazione base della pagina
st.set_page_config(page_title="NetInfect IDS", page_icon=":material/security:", layout="wide")

# Percorsi ai file di log
current_dir = os.path.dirname(os.path.abspath(__file__))
CONN_LOG_PATH = os.path.join(current_dir, "../../lab/shared/zeek_logs/conn.log")
HTTP_LOG_PATH = os.path.join(current_dir, "../../lab/shared/zeek_logs/http.log")
ALERTS_LOG_PATH = os.path.join(current_dir, "../../lab/shared/zeek_logs/alerts.csv")

def read_zeek_log(filepath, columns):
    """Legge in modo sicuro un file di log Zeek e restituisce un DataFrame limitato."""
    if not os.path.exists(filepath):
        return pd.DataFrame(columns=columns)
        
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()
            
        data = []
        for line in lines[-500:]: # Legge solo le ultime 500 righe per velocità
            if not line.startswith('#'):
                parts = line.strip().split('\t')
                if len(parts) >= len(columns):
                    data.append(parts[:len(columns)])
                    
        df = pd.DataFrame(data, columns=columns)
        return df
    except Exception:
        return pd.DataFrame(columns=columns)

st.title("NetInfect - Live IDS", icon=":material/shield:")
st.caption("Monitoraggio in tempo reale del traffico di rete e rilevamento anomalie (L3, L4, L7)")

# 1. Carica dati di connessione (Layer 3/4)
conn_cols = ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h', 'resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
df_conn = read_zeek_log(CONN_LOG_PATH, conn_cols)

# 2. Carica dati HTTP (Layer 7)
http_cols = ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h', 'resp_p', 'trans_depth', 'method', 'host', 'uri']
df_http = read_zeek_log(HTTP_LOG_PATH, http_cols)

# 3. Carica Storico Attacchi (Alerts)
df_alerts = pd.DataFrame(columns=["timestamp", "attacker_ip", "reason"])
if os.path.exists(ALERTS_LOG_PATH):
    try:
        df_alerts = pd.read_csv(ALERTS_LOG_PATH)
        df_alerts['timestamp'] = pd.to_numeric(df_alerts['timestamp'], errors='coerce')
    except Exception:
        pass

# --- ALLARMI ATTIVI ---
if not df_alerts.empty:
    latest_alert_time = df_alerts['timestamp'].max()
    current_time = int(time.time())
    if current_time - latest_alert_time < 15:
        st.error(f"INTRUSION DETECTED! Un attacco è in corso o è stato appena bloccato. Controlla lo storico in basso.", icon=":material/warning:")

# --- METRICHE IN CIMA ---
tot_conns = len(df_conn)
tot_rej = len(df_conn[df_conn['conn_state'] == 'REJ']) if not df_conn.empty else 0
tot_http = len(df_http)
unique_ips = df_conn['orig_h'].nunique() if not df_conn.empty else 0

with st.container(horizontal=True):
    st.metric("Total Connections (Last 500)", tot_conns, border=True)
    st.metric("Unique Source IPs", unique_ips, border=True)
    # Highlight high rejections
    rej_delta = "- OK" if tot_rej < 10 else f"{tot_rej} Rej"
    st.metric("Rejected Conns (Possible Scan)", tot_rej, delta=rej_delta, delta_color="inverse", border=True)
    st.metric("HTTP Requests (Layer 7)", tot_http, border=True)

st.space(small=True)

# --- GRAFICI ---
if not df_conn.empty:
    df_conn['ts_dt'] = pd.to_datetime(pd.to_numeric(df_conn['ts'], errors='coerce'), unit='s')
    
    # Grafico a barre del traffico per porta
    port_counts = df_conn['resp_p'].value_counts().reset_index()
    port_counts.columns = ['Port', 'Count']
    
    col_chart1, col_chart2 = st.columns(2)
    
    with col_chart1:
        with st.container(border=True):
            st.subheader("Traffico per Porta", icon=":material/bar_chart:")
            fig1 = px.bar(port_counts.head(10), x='Port', y='Count', color='Count', color_continuous_scale='Greens', template='plotly_dark')
            st.plotly_chart(fig1, key="bar_chart")
        
    with col_chart2:
        with st.container(border=True):
            st.subheader("Stati della Connessione", icon=":material/pie_chart:")
            state_counts = df_conn['conn_state'].value_counts().reset_index()
            state_counts.columns = ['State', 'Count']
            # Se ci sono molti REJ o RSTR, spiccano in rosso
            fig2 = px.pie(state_counts, names='State', values='Count', template='plotly_dark', hole=0.4)
            st.plotly_chart(fig2, key="pie_chart")
else:
    st.info("Nessun dato di connessione rilevato. In attesa di traffico...", icon=":material/hourglass_empty:")

st.space(small=True)

# --- LOG RAW E ATTACCHI HTTP ---
with st.container(border=True):
    st.subheader("Ultime Richieste HTTP (WAF)", icon=":material/web:")
    if not df_http.empty:
        st.dataframe(df_http[['ts', 'orig_h', 'method', 'host', 'uri']].tail(10), hide_index=True, use_container_width=True)
    else:
        st.caption("Nessuna richiesta HTTP rilevata.")
        
st.space(small=True)

# --- STORICO ATTACCHI (ALERTS) ---
with st.container(border=True):
    st.subheader("Storico Attacchi e Firewall", icon=":material/history:")
    if not df_alerts.empty:
        df_alerts_disp = df_alerts.copy()
        df_alerts_disp['Time'] = pd.to_datetime(df_alerts_disp['timestamp'], unit='s').dt.strftime('%Y-%m-%d %H:%M:%S')
        df_alerts_disp = df_alerts_disp[['Time', 'attacker_ip', 'reason']].sort_values(by='Time', ascending=False)
        st.dataframe(df_alerts_disp, hide_index=True, use_container_width=True)
    else:
        st.success("Nessun attacco rilevato finora. La rete è sicura.", icon=":material/verified:")

# Aggiorna automaticamente l'app Streamlit ogni 3 secondi
time.sleep(3)
st.rerun()
