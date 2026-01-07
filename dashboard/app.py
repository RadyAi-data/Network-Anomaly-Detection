import streamlit as st
import pandas as pd
import joblib
import plotly.express as px
import numpy as np

# Page Configuration
st.set_page_config(
    page_title="Network Sentinel",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS for styling
st.markdown("""
<style>
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        text-align: center;
    }
    .stAlert {
        padding: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Title & Description
st.title("🛡️ Network Sentinel: Hierarchical IDS")
st.markdown("""
**System Architecture:**
1.  **Gatekeeper (Isolation Forest):** Filters mass volume attacks (DoS, Probe).
2.  **Specialist (Random Forest):** Classifies the specific attack type.
3.  **Bypass Rule (U2R):** Catching stealthy rootkit attacks via signature check.
""")

# --- 1. LOAD MODELS ---
@st.cache_resource
def load_models():
    try:
        # Adjust paths if your folder structure is different
        preprocessor = joblib.load('models/preprocessor.pkl')
        iso_forest = joblib.load('models/isolation_forest.pkl')
        rf_classifier = joblib.load('models/attack_classifier.pkl')
        return preprocessor, iso_forest, rf_classifier
    except FileNotFoundError:
        st.error("❌ Models not found! Make sure you are running this from the project root.")
        return None, None, None

preprocessor, iso_forest, rf_classifier = load_models()

# --- 2. SIDEBAR CONFIG ---
st.sidebar.header("Configuration")
uploaded_file = st.sidebar.file_uploader("Upload Network Log (CSV)", type="csv")
confidence_threshold = st.sidebar.slider("Sensitivity Threshold", 0.0, 1.0, 0.5)

# --- 3. MAIN LOGIC ---
if uploaded_file is not None and preprocessor:
    df = pd.read_csv(uploaded_file)
    st.sidebar.success(f"Loaded {len(df)} connections")
    
    # Run Analysis Button
    if st.button("🚀 Analyze Traffic", type="primary"):
        with st.spinner("Running Multi-Stage Detection Pipeline..."):
            
            # A. PREPROCESS
            try:
                X_processed = preprocessor.transform(df)
            except Exception as e:
                st.error(f"Data Error: {e}")
                st.stop()

            # B. STAGE 1: GATEKEEPER (Isolation Forest)
            # 1 = Normal, -1 = Anomaly
            gatekeeper_preds = iso_forest.predict(X_processed)

            # C. BYPASS RULE (The "U2R" Fix)
            # Only keeping the effective 'root_shell' rule
            bypass_count = 0
            for i in range(len(df)):
                # If Root Shell obtained -> FORCE Anomaly (Catches U2R)
                if df.iloc[i].get('root_shell', 0) == 1:
                    if gatekeeper_preds[i] == 1: # If model missed it
                        gatekeeper_preds[i] = -1 # Override
                        bypass_count += 1
            
            # D. STAGE 2: CLASSIFICATION
            final_types = []
            
            # Get indices of all flagged anomalies
            anomaly_indices = [i for i, x in enumerate(gatekeeper_preds) if x == -1]
            
            if anomaly_indices:
                X_anomalies = X_processed[anomaly_indices]
                attack_preds = rf_classifier.predict(X_anomalies)
                attack_iter = iter(attack_preds)
            
            # Reconstruct final list
            for status in gatekeeper_preds:
                if status == 1:
                    final_types.append("Normal")
                else:
                    final_types.append(next(attack_iter))
            
            # Add results to dataframe
            df['Prediction'] = final_types
            
            # --- 4. VISUALIZATION DASHBOARD ---
            
            # Top Metrics
            total = len(df)
            n_threats = len(df[df['Prediction'] != 'Normal'])
            pct_threats = (n_threats / total) * 100
            
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Traffic", f"{total:,}")
            m2.metric("Threats Detected", f"{n_threats:,}", delta_color="inverse")
            m3.metric("Attack Rate", f"{pct_threats:.1f}%")
            m4.metric("Stealth Attacks Caught", f"{bypass_count}", help="U2R attacks caught by Bypass Rule")
            
            st.divider()

            # Layout: Pie Chart + Bar Chart
            c1, c2 = st.columns(2)
            
            with c1:
                st.subheader("🛡️ Threat Distribution")
                counts = df['Prediction'].value_counts()
                # Custom colors: Normal=Green, Attacks=Red/Orange
                color_map = {
                    "Normal": "#00CC96", 
                    "DoS": "#EF553B", 
                    "Probe": "#AB63FA", 
                    "U2R": "#FFA15A", 
                    "R2L": "#19D3F3"
                }
                fig_pie = px.pie(
                    names=counts.index, 
                    values=counts.values, 
                    hole=0.4,
                    color=counts.index,
                    color_discrete_map=color_map
                )
                st.plotly_chart(fig_pie, use_container_width=True)
                
            with c2:
                st.subheader("📡 Protocol Vulnerabilities")
                attacks_only = df[df['Prediction'] != 'Normal']
                if not attacks_only.empty:
                    fig_bar = px.histogram(
                        attacks_only, 
                        x='protocol_type', 
                        color='Prediction', 
                        barmode='group',
                        color_discrete_map=color_map
                    )
                    st.plotly_chart(fig_bar, use_container_width=True)
                else:
                    st.success("No attacks found to visualize.")

            # Detailed Table
            st.subheader("🔍 Suspicious Activity Log")
            suspicious_df = df[df['Prediction'] != 'Normal'].copy()
            if not suspicious_df.empty:
                # Add a "Risk Score" simulation for visual effect
                suspicious_df['Risk Factor'] = np.where(suspicious_df['Prediction'] == 'DoS', 'High', 'Critical')
                
                st.dataframe(
                    suspicious_df[['duration', 'service', 'src_bytes', 'dst_bytes', 'Prediction', 'Risk Factor']],
                    use_container_width=True
                )
            else:
                st.success("Network is Clean. No suspicious activity.")

elif not uploaded_file:
    st.info("👈 Please upload a CSV file to start the scan.")