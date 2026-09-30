import streamlit as st
import pandas as pd
import time
import os
import plotly.express as px

# Configurazione base della pagina
st.set_page_config(page_title="NetInfect IDS Dashboard", page_icon="🛡️", layout="wide")

# Percorsi ai file di log
current_dir = os.path.dirname(os.path.abspath(__file__))
CONN_LOG_PATH = os.path.join(current_dir, "../../lab/shared/zeek_logs/conn.log")
HTTP_LOG_PATH = os.path.join(current_dir, "../../lab/shared/zeek_logs/http.log")

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

# Layout e Stile CSS personalizzato (Estetica Moderna)
st.markdown("""
    <style>
    .main {background-color: #0E1117;}
    h1 {color: #00FF41; font-family: 'Courier New', Courier, monospace;}
    .metric-box {
        background-color: #1E1E1E;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #00FF41;
        box-shadow: 0 4px 8px rgba(0,0,0,0.5);
    }
    .metric-title {color: #A0A0A0; font-size: 14px;}
    .metric-value {color: #FFFFFF; font-size: 28px; font-weight: bold;}
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ NetInfect - Live Intrusion Detection System")
st.markdown("Monitoraggio in tempo reale del traffico di rete e rilevamento anomalie (L3, L4, L7)")

# Creiamo un placeholder vuoto che aggiorneremo nel loop
placeholder = st.empty()

# Loop di aggiornamento continuo
while True:
    # 1. Carica dati di connessione (Layer 3/4)
    conn_cols = ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h', 'resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
    df_conn = read_zeek_log(CONN_LOG_PATH, conn_cols)
    
    # 2. Carica dati HTTP (Layer 7)
    http_cols = ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h', 'resp_p', 'trans_depth', 'method', 'host', 'uri']
    df_http = read_zeek_log(HTTP_LOG_PATH, http_cols)
    
    with placeholder.container():
        # --- METRICHE IN CIMA ---
        col1, col2, col3, col4 = st.columns(4)
        
        tot_conns = len(df_conn)
        tot_rej = len(df_conn[df_conn['conn_state'] == 'REJ']) if not df_conn.empty else 0
        tot_http = len(df_http)
        unique_ips = df_conn['orig_h'].nunique() if not df_conn.empty else 0
        
        col1.markdown(f'<div class="metric-box"><div class="metric-title">Total Connections (Last 500)</div><div class="metric-value">{tot_conns}</div></div>', unsafe_allow_html=True)
        col2.markdown(f'<div class="metric-box"><div class="metric-title">Unique Source IPs</div><div class="metric-value">{unique_ips}</div></div>', unsafe_allow_html=True)
        col3.markdown(f'<div class="metric-box"><div class="metric-title" style="color: #FF4B4B;">Rejected Conns (Possible Scan)</div><div class="metric-value">{tot_rej}</div></div>', unsafe_allow_html=True)
        col4.markdown(f'<div class="metric-box"><div class="metric-title">HTTP Requests (Layer 7)</div><div class="metric-value">{tot_http}</div></div>', unsafe_allow_html=True)
        
        st.markdown("---")
        
        # --- GRAFICI ---
        if not df_conn.empty:
            df_conn['ts_dt'] = pd.to_datetime(pd.to_numeric(df_conn['ts'], errors='coerce'), unit='s')
            
            # Grafico a barre del traffico per porta
            port_counts = df_conn['resp_p'].value_counts().reset_index()
            port_counts.columns = ['Port', 'Count']
            
            col_chart1, col_chart2 = st.columns(2)
            
            with col_chart1:
                st.subheader("Traffico per Porta di Destinazione")
                fig1 = px.bar(port_counts.head(10), x='Port', y='Count', color='Count', color_continuous_scale='Greens', template='plotly_dark')
                st.plotly_chart(fig1, use_container_width=True)
                
            with col_chart2:
                st.subheader("Stati della Connessione")
                state_counts = df_conn['conn_state'].value_counts().reset_index()
                state_counts.columns = ['State', 'Count']
                # Se ci sono molti REJ o RSTR, spiccano in rosso
                fig2 = px.pie(state_counts, names='State', values='Count', template='plotly_dark', hole=0.4)
                st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("Nessun dato di connessione rilevato. In attesa di traffico...")
            
        # --- LOG RAW E ATTACCHI HTTP ---
        st.markdown("---")
        st.subheader("👀 Ultime Richieste HTTP (Monitoraggio Layer 7 WAF)")
        if not df_http.empty:
            st.dataframe(df_http[['ts', 'orig_h', 'method', 'host', 'uri']].tail(10), use_container_width=True)
        else:
            st.info("Nessuna richiesta HTTP rilevata.")
            
    # Aggiorna ogni 3 secondi
    time.sleep(3)
