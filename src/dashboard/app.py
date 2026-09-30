import streamlit as st
import pandas as pd
import time
import os
import plotly.express as px
import plotly.graph_objects as go

def create_topology_chart(df_alerts, df_conn):
    nodes = {
        "Internet/Attacker": {"ip": "203.0.113.100", "x": 0.1, "y": 0.8, "color": "#00ffcc"},
        "Firewall (IDS)": {"ip": "192.168.30.254", "x": 0.3, "y": 0.5, "color": "#0055ff"},
        "Switch DMZ": {"ip": "DMZ", "x": 0.6, "y": 0.7, "color": "#2c2c2c"},
        "Web Server 1": {"ip": "192.168.30.10", "x": 0.9, "y": 0.85, "color": "#39ff14"},
        "Web Server 2": {"ip": "192.168.30.11", "x": 0.9, "y": 0.55, "color": "#39ff14"},
        "Switch LAN": {"ip": "LAN", "x": 0.6, "y": 0.3, "color": "#2c2c2c"},
        "Client 1": {"ip": "192.168.10.100", "x": 0.9, "y": 0.35, "color": "#39ff14"},
        "Client 2": {"ip": "192.168.10.200", "x": 0.9, "y": 0.05, "color": "#39ff14"},
    }
    
    active_attackers = df_alerts['attacker_ip'].unique() if not df_alerts.empty else []
    for name, data in nodes.items():
        if data['ip'] in active_attackers:
            data['color'] = "#ff003c"
            
    edges = [
        ("Internet/Attacker", "Firewall (IDS)"),
        ("Firewall (IDS)", "Switch DMZ"), ("Firewall (IDS)", "Switch LAN"),
        ("Switch DMZ", "Web Server 1"), ("Switch DMZ", "Web Server 2"),
        ("Switch LAN", "Client 1"), ("Switch LAN", "Client 2")
    ]
    
    edge_x, edge_y = [], []
    for edge in edges:
        x0, y0 = nodes[edge[0]]['x'], nodes[edge[0]]['y']
        x1, y1 = nodes[edge[1]]['x'], nodes[edge[1]]['y']
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
        
    edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=2, color='#333333'), hoverinfo='none', mode='lines')
    
    node_x = [data['x'] for data in nodes.values()]
    node_y = [data['y'] for data in nodes.values()]
    node_text = [f"{name}<br>{data['ip']}" for name, data in nodes.items()]
    node_color = [data['color'] for data in nodes.values()]
    
    node_trace = go.Scatter(
        x=node_x, y=node_y, mode='markers+text', text=list(nodes.keys()), textposition="bottom center",
        hoverinfo='text', hovertext=node_text,
        marker=dict(showscale=False, color=node_color, size=35, line_width=2, line_color='#0f172a')
    )
    
    fig = go.Figure(data=[edge_trace, node_trace],
             layout=go.Layout(
                showlegend=False, hovermode='closest', margin=dict(b=20,l=5,r=5,t=20),
                plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)))
    return fig
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

@st.fragment(run_every="3s")
def render_dashboard():
    # 1. Carica Dati
    conn_cols = ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h', 'resp_p', 'proto', 'service', 'duration', 'orig_bytes', 'resp_bytes', 'conn_state']
    df_conn = read_zeek_log(CONN_LOG_PATH, conn_cols)
    http_cols = ['ts', 'uid', 'orig_h', 'orig_p', 'resp_h', 'resp_p', 'trans_depth', 'method', 'host', 'uri']
    df_http = read_zeek_log(HTTP_LOG_PATH, http_cols)
    
    df_alerts = pd.DataFrame(columns=["timestamp", "attacker_ip", "reason"])
    if os.path.exists(ALERTS_LOG_PATH):
        try:
            df_alerts = pd.read_csv(ALERTS_LOG_PATH)
            df_alerts['timestamp'] = pd.to_numeric(df_alerts['timestamp'], errors='coerce')
        except:
            pass

    # Calcolo Threat Level
    current_time = int(time.time())
    active_threat = not df_alerts.empty and (current_time - df_alerts['timestamp'].max() < 30)
    threat_level = "CRITICAL" if active_threat else "SECURE"
    threat_color = "red" if active_threat else "green"

    # --- SIDEBAR (Global Status) ---
    with st.sidebar:
        st.title("NetInfect", icon=":material/security:")
        st.caption("Live Intrusion Detection")
        st.markdown("---")
        st.subheader("System Status")
        st.markdown(f"**Threat Level:** :{threat_color}[{threat_level}]")
        st.metric("Analyzed Connections", len(df_conn))
        st.metric("Blocked Attackers", df_alerts['attacker_ip'].nunique() if not df_alerts.empty else 0)
        st.markdown("---")
        st.caption("Auto-refresh: Active (3s)")

    # HEADER Principale
    st.title("NetInfect Operations", icon=":material/dashboard:")
    
    if active_threat:
        st.error(f"INTRUSION DETECTED! Un attacco è in corso o è stato appena bloccato.", icon=":material/warning:")

    # TABS
    tab_overview, tab_topo, tab_waf = st.tabs(["📊 Global Overview", "🕸️ Topology & Security", "🌐 WAF & L7 Logs"])

    with tab_overview:
        tot_conns = len(df_conn)
        tot_rej = len(df_conn[df_conn['conn_state'] == 'REJ']) if not df_conn.empty else 0
        tot_http = len(df_http)
        unique_ips = df_conn['orig_h'].nunique() if not df_conn.empty else 0

        # Metriche
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Connections (L3)", tot_conns, border=True)
        c2.metric("Unique Source IPs", unique_ips, border=True)
        c3.metric("Rejected Conns (Scan)", tot_rej, delta=f"{tot_rej} Rej" if tot_rej>10 else "- OK", delta_color="inverse", border=True)
        c4.metric("HTTP Requests (L7)", tot_http, border=True)

        if not df_conn.empty:
            df_conn['ts_dt'] = pd.to_datetime(pd.to_numeric(df_conn['ts'], errors='coerce'), unit='s')
            
            # Area Chart (Trend)
            st.subheader("Traffic Activity Over Time", icon=":material/timeline:")
            traffic_trend = df_conn.set_index('ts_dt').resample('5s').size().reset_index(name='Conns')
            fig_trend = px.area(traffic_trend, x='ts_dt', y='Conns', template='plotly_dark', color_discrete_sequence=['#00ffcc'])
            fig_trend.update_layout(height=250, margin=dict(l=0, r=0, t=10, b=0), plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
            st.plotly_chart(fig_trend, key="trend_chart")

            # Pie & Bar
            col_pie, col_bar = st.columns(2)
            with col_pie:
                with st.container(border=True):
                    st.subheader("Connection States", icon=":material/pie_chart:")
                    sc = df_conn['conn_state'].value_counts().reset_index()
                    sc.columns = ['State', 'Count']
                    c_map = {'SF':'#39ff14','S0':'#0055ff','REJ':'#ff003c','RSTR':'#d80032','RSTO':'#ff7300'}
                    fig2 = px.pie(sc, names='State', values='Count', template='plotly_dark', hole=0.5, color='State', color_discrete_map=c_map)
                    fig2.update_layout(height=250, margin=dict(l=0, r=0, t=0, b=0), plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
                    st.plotly_chart(fig2, key="pie_chart")
            with col_bar:
                with st.container(border=True):
                    st.subheader("Traffic by Port", icon=":material/bar_chart:")
                    pc = df_conn['resp_p'].value_counts().reset_index()
                    pc.columns = ['Port', 'Count']
                    fig1 = px.bar(pc.head(5), x='Port', y='Count', color='Count', color_continuous_scale='Greens', template='plotly_dark')
                    fig1.update_layout(height=250, margin=dict(l=0, r=0, t=0, b=0), plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)')
                    st.plotly_chart(fig1, key="bar_chart")
        else:
            st.info("In attesa di traffico...")

    with tab_topo:
        if not df_conn.empty:
            c_t1, c_t2 = st.columns([1.5, 1])
            with c_t1:
                with st.container(border=True):
                    st.subheader("Network Threat Topology", icon=":material/hub:")
                    st.plotly_chart(create_topology_chart(df_alerts, df_conn), key="topology_chart")
            with c_t2:
                with st.container(border=True):
                    st.subheader("Active Blacklist", icon=":material/history:")
                    if not df_alerts.empty:
                        df_d = df_alerts.copy()
                        df_d['Time'] = pd.to_datetime(df_d['timestamp'], unit='s').dt.strftime('%H:%M:%S')
                        st.dataframe(df_d[['Time', 'attacker_ip', 'reason']].sort_values(by='Time', ascending=False), hide_index=True)
                        with st.expander("Sblocca IP Manualmente", icon=":material/lock_open:"):
                            ip_to_unblock = st.selectbox("Seleziona IP", df_alerts['attacker_ip'].unique())
                            if st.button("Sblocca IP", type="primary"):
                                unblock_script = os.path.join(current_dir, "../active_response/unblock_ip.py")
                                os.system(f"python3 {unblock_script} {ip_to_unblock}")
                                st.success(f"IP {ip_to_unblock} sbloccato!")
                                time.sleep(1)
                                st.rerun()
                    else:
                        st.success("Nessun IP bloccato.")
                        
    with tab_waf:
        with st.container(border=True):
            st.subheader("HTTP WAF Logs", icon=":material/web:")
            if not df_http.empty:
                st.dataframe(df_http[['orig_h', 'method', 'host', 'uri']].tail(15), hide_index=True)
            else:
                st.caption("Nessuna richiesta HTTP.")

render_dashboard()
