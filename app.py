import streamlit as st
import pandas as pd
import joblib
import plotly.express as px
import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin

# ==========================================
# 0. THE BRAIN: MODEL CLASS DEFINITION
# ==========================================
class HierarchicalNIDS(BaseEstimator, ClassifierMixin):
    """
    The 'Super Model' that combines Isolation Forest, 
    Random Forest, and Logic Rules into one system.
    """
    def __init__(self, preprocessor, gatekeeper, specialist):
        self.preprocessor = preprocessor
        self.gatekeeper = gatekeeper
        self.specialist = specialist

    def predict(self, X):
        # 1. Preprocess
        X_processed = self.preprocessor.transform(X)

        # 2. Gatekeeper (Anomaly Detection)
        # 1 = Normal, -1 = Anomaly
        gatekeeper_preds = self.gatekeeper.predict(X_processed)

        # 3. Bypass Rules (The "Stealth" Layer)
        # Rule A: Root Shell = Always Anomaly
        if 'root_shell' in X.columns:
            mask_u2r = (X['root_shell'] == 1) & (gatekeeper_preds == 1)
            gatekeeper_preds[mask_u2r] = -1

        # Rule B: Failed Logins = Always Anomaly
        if 'num_failed_logins' in X.columns:
            mask_r2l = (X['num_failed_logins'] > 2) & (gatekeeper_preds == 1)
            gatekeeper_preds[mask_r2l] = -1
            
        # Rule C: File Creations = Always Anomaly
        if 'num_file_creations' in X.columns:
            mask_files = (X['num_file_creations'] > 2) & (gatekeeper_preds == 1)
            gatekeeper_preds[mask_files] = -1

        # 4. Specialist (Classification)
        final_preds = np.array(["Normal"] * len(X), dtype=object)
        anomaly_indices = np.where(gatekeeper_preds == -1)[0]

        if len(anomaly_indices) > 0:
            X_anomalies = X_processed[anomaly_indices]
            specialist_preds = self.specialist.predict(X_anomalies)
            final_preds[anomaly_indices] = specialist_preds

        return final_preds

# ==========================================
# 1. PAGE CONFIG
# ==========================================
st.set_page_config(
    page_title="Network Sentinel",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
<style>
    .metric-card { background-color: #f0f2f6; padding: 20px; border-radius: 10px; text-align: center; }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Network Sentinel: Hierarchical IDS")
st.markdown("""
**System Architecture:**
1.  **Gatekeeper (Isolation Forest):** Filters mass volume attacks (DoS, Probe).
2.  **Specialist (Random Forest):** Classifies the specific attack type.
3.  **Bypass Rule (U2R):** Catching stealthy rootkit attacks via signature check.
""")

# --- CONFIGURATION: REQUIRED COLUMNS ---
REQUIRED_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root', 
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate', 
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate'
]

# ==========================================
# 2. LOAD MODELS
# ==========================================
@st.cache_resource
def load_nids_system():
    try:
        # Load components
        preprocessor = joblib.load('models/preprocessor.pkl')
        iso_forest = joblib.load('models/isolation_forest.pkl')
        rf_classifier = joblib.load('models/attack_classifier.pkl')
        
        # Assemble the System
        return HierarchicalNIDS(preprocessor, iso_forest, rf_classifier)
    except FileNotFoundError:
        st.error("❌ Models not found! Check your folder structure.")
        return None

nids_system = load_nids_system()

# ==========================================
# 3. HELPER: TEMPLATE
# ==========================================
def get_template_df():
    data = {col: [0] for col in REQUIRED_COLUMNS}
    data['duration'] = [0]
    data['protocol_type'] = ['tcp']
    data['service'] = ['http']
    data['flag'] = ['SF']
    data['src_bytes'] = [230]
    data['dst_bytes'] = [4500]
    return pd.DataFrame(data)

# ==========================================
# 4. SIDEBAR & INPUT
# ==========================================
st.sidebar.header("Configuration")
template_df = get_template_df()
csv_template = template_df.to_csv(index=False).encode('utf-8')
st.sidebar.download_button(
    label="📋 Download CSV Template",
    data=csv_template,
    file_name="network_log_template.csv",
    mime="text/csv"
)

uploaded_file = st.sidebar.file_uploader("Upload Network Log (CSV)", type="csv")

# ==========================================
# 5. MAIN LOGIC
# ==========================================
if uploaded_file is not None and nids_system:
    # Reset state if new file
    if 'last_uploaded' not in st.session_state or st.session_state.last_uploaded != uploaded_file.name:
        st.session_state.data_processed = False
        st.session_state.last_uploaded = uploaded_file.name

    # Read File
    try:
        df = pd.read_csv(uploaded_file)
    except Exception as e:
        st.error(f"❌ Read Error: {e}")
        st.stop()

    # Auto-Fix Headers
    if 'duration' not in df.columns:
        uploaded_file.seek(0)
        df_no_header = pd.read_csv(uploaded_file, header=None)
        if len(df_no_header.columns) == len(REQUIRED_COLUMNS):
            df_no_header.columns = REQUIRED_COLUMNS
            df = df_no_header
            st.toast("⚠️ Auto-fixed missing headers!", icon="🔧")
        elif len(df_no_header.columns) == len(REQUIRED_COLUMNS) + 1:
            df_no_header.columns = REQUIRED_COLUMNS + ['label']
            df = df_no_header

    # Schema Validation
    missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_cols:
        st.error("❌ **Incompatible Data:** File does not match schema.")
        st.dataframe(get_template_df(), use_container_width=True, hide_index=True)
        st.stop()

    # Simulation: IPs
    if 'src_ip' not in df.columns:
        internal_ips = [f"192.168.1.{i}" for i in range(10, 250)]
        df['src_ip'] = np.random.choice(internal_ips, size=len(df))

    st.sidebar.success(f"✅ Loaded {len(df)} Logs")

    # RUN ANALYSIS
    if st.button("🚀 Analyze Traffic", type="primary"):
        with st.spinner("Running Hierarchical Detection Pipeline..."):
            
            # --- THE MAGIC LINE 🚀 ---
            # All the complexity is handled by the class now!
            df['Prediction'] = nids_system.predict(df)
            # -------------------------

            # Assign Bad IPs to Attacks (Simulation)
            bad_ip_pool = ["203.45.112.5", "89.22.101.4", "198.51.100.23", "5.188.62.11", "45.33.22.10"]
            mask_attack = df['Prediction'] != 'Normal'
            if mask_attack.sum() > 0:
                df.loc[mask_attack, 'src_ip'] = np.random.choice(bad_ip_pool, size=mask_attack.sum())

            st.session_state.df_results = df
            st.session_state.data_processed = True

    # ==========================================
    # 6. DASHBOARD
    # ==========================================
    if st.session_state.get('data_processed', False):
        df_results = st.session_state.df_results

        # Calculate Metrics
        total = len(df_results)
        n_threats = len(df_results[df_results['Prediction'] != 'Normal'])
        pct_threats = (n_threats / total) * 100
        
        # Calculate Stealth Attacks (Proxy Metric)
        # We count U2R/R2L detected as a proxy for "Stealth Caught"
        n_stealth = len(df_results[df_results['Prediction'].isin(['U2R', 'R2L'])])

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Traffic", f"{total:,}")
        m2.metric("Threats Detected", f"{n_threats:,}", delta_color="inverse")
        m3.metric("Attack Rate", f"{pct_threats:.1f}%")
        m4.metric("Stealth/Critical Threats", f"{n_stealth}", help="Rootkits (U2R) & Remote Exploits (R2L)")
        
        st.divider()

        # Visuals
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("🛡️ Threat Distribution")
            counts = df_results['Prediction'].value_counts()
            color_map = {"Normal": "#00CC96", "DoS": "#EF553B", "Probe": "#AB63FA", "U2R": "#FFA15A", "R2L": "#19D3F3"}
            fig_pie = px.pie(names=counts.index, values=counts.values, hole=0.4, color=counts.index, color_discrete_map=color_map)
            st.plotly_chart(fig_pie, use_container_width=True)
            
        with c2:
            st.subheader("⚠️ Top Attacker IPs")
            attacks_only = df_results[df_results['Prediction'] != 'Normal']
            if not attacks_only.empty:
                top_ips = attacks_only['src_ip'].value_counts().head(5).reset_index()
                top_ips.columns = ['IP Address', 'Attack Count']
                fig_ip = px.bar(top_ips, x='Attack Count', y='IP Address', orientation='h', color='Attack Count', color_continuous_scale='Reds')
                fig_ip.update_layout(yaxis=dict(autorange="reversed"))
                st.plotly_chart(fig_ip, use_container_width=True)
            else:
                st.success("No attacks found.")

        st.subheader("📡 Attack Frequency by Protocol")
        if not attacks_only.empty:
            fig_bar = px.histogram(attacks_only, x='protocol_type', color='Prediction', barmode='group', color_discrete_map=color_map)
            st.plotly_chart(fig_bar, use_container_width=True)

        # Intelligent Log
        st.subheader("🔍 Intelligent Threat Diagnosis")
        if not attacks_only.empty:
            def get_reason(row):
                if row.get('root_shell', 0) == 1:
                    return f"CRITICAL: Root Access Obtained (root_shell={row['root_shell']})"
                if row['Prediction'] == 'DoS':
                    if row.get('count', 0) > 10:
                        return f"High Traffic Volume (count={row['count']})"
                    return "Denial of Service Pattern"
                if row['Prediction'] == 'Probe':
                    if row.get('dst_bytes', 0) == 0:
                        return f"Blind Port Scan (dst_bytes={row['dst_bytes']})"
                    return f"Surveillance Sweep (src_bytes={row['src_bytes']})"
                if row['Prediction'] == 'R2L':
                    if row.get('num_failed_logins', 0) > 0:
                        return f"Failed Login Attempts (logins={row['num_failed_logins']})"
                    return "Suspicious Remote Access"
                return "Anomaly Detected"

            log_df = attacks_only.copy()
            log_df['Reason'] = log_df.apply(get_reason, axis=1)
            
            st.dataframe(
                log_df[['src_ip', 'Prediction', 'Reason', 'protocol_type', 'service', 'duration']],
                use_container_width=True
            )
        else:
            st.success("✅ Network is Clean.")

elif not uploaded_file:
    st.info("👈 Please upload a CSV file to start the scan.")