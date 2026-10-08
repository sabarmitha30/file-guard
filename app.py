import streamlit as st
import pandas as pd
import numpy as np
import re
from sklearn.ensemble import IsolationForest

st.set_page_config(page_title="AI File Guard", page_icon="🛡️", layout="wide")
st.title("🛡️ AI-Powered Sensitive File Access & Threat Detection System")
st.markdown("---")

# ML Engine
@st.cache_resource
def load_ml_engine():
    np.random.seed(42)
    # Baseline normal data: [HourOfDay, AccessFrequency, SensitivityScore, IsUnknownIP]
    normal_traffic = np.random.normal(loc=[14, 2, 20, 0], scale=[3, 1, 10, 0.1], size=(200, 4))
    normal_traffic = np.clip(normal_traffic, 0, None)
    model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    model.fit(normal_traffic)
    return model

model = load_ml_engine()

tab1, tab2, tab3 = st.tabs(["📄 1. File Scanner", "🚨 2. Threat Engine", "📊 3. Live Logs & Analytics"])

# TAB 1: File Sensitivity Scanner
with tab1:
    st.header("File Content Sensitivity Scanner")
    uploaded_file = st.file_uploader("Upload a document (.txt)", type=["txt"])
    if uploaded_file is not None:
        content = uploaded_file.read().decode("utf-8")
        emails = len(re.findall(r'[\w\.-]+@[\w\.-]+', content))
        phone_nums = len(re.findall(r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b', content))
        secret_words = len(re.findall(r'(?i)(password|secret|confidential|financial|ssn|api_key)', content))
        
        score = min(100, (emails * 10) + (phone_nums * 15) + (secret_words * 25))
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("File Preview")
            st.text_area("Content", content, height=150)
        with col2:
            st.subheader("Sensitivity Tier")
            st.metric("Sensitivity Score", f"{score} / 100")
            if score > 70:
                st.error("Classification: HIGHLY RESTRICTED (Critical PII / Keys Detected)")
            elif score > 30:
                st.warning("Classification: INTERNAL CONFIDENTIAL")
            else:
                st.success("Classification: PUBLIC / LOW RISK")

# TAB 2: Anomaly Detection Engine
with tab2:
    st.header("Simulate File Access Event")
    col_a, col_b = st.columns(2)
    with col_a:
        user_name = st.text_input("User ID", "john_doe")
        hour = st.slider("Time of Access (Hour 0-23)", 0, 23, 14)
        recent_accesses = st.slider("Accesses in Last 10 Mins", 1, 50, 2)
    with col_b:
        file_sens = st.slider("Target File Sensitivity Score", 0, 100, 85)
        ip_status = st.selectbox("IP Status", ["Known Corporate IP (0)", "Unrecognized Remote IP (1)"])
        is_unknown_ip = 1 if "Unrecognized" in ip_status else 0

    if st.button("Evaluate Threat Level", type="primary"):
        features = np.array([[hour, recent_accesses, file_sens, is_unknown_ip]])
        prediction = model.predict(features)[0]
        raw_score = model.decision_function(features)[0]
        threat_index = max(0, min(100, int((0.2 - raw_score) * 100)))
        
        st.markdown("---")
        st.metric("AI Calculated Threat Score", f"{threat_index}%")
        if prediction == -1 or threat_index > 65:
            st.error("🚨 ANOMALOUS ACCESS DETECTED! Threat Mitigated: Token Revoked & Directory Locked.")
        else:
            st.success("✅ NORMAL ACCESS PATTERN. Access Granted.")

# TAB 3: Incident Log Dashboard
with tab3:
    st.header("Security Operations Logs")
    demo_logs = pd.DataFrame([
        {"Timestamp": "2026-10-08 10:14:02", "User": "alice_mgr", "File": "q3_payroll.txt", "Threat Score": "12%", "Status": "ALLOWED"},
        {"Timestamp": "2026-10-08 11:30:45", "User": "bob_dev", "File": "api_keys.env", "Threat Score": "28%", "Status": "ALLOWED"},
        {"Timestamp": "2026-10-08 03:12:10", "User": "unknown_user", "File": "patient_records.db", "Threat Score": "89%", "Status": "BLOCKED"},
        {"Timestamp": "2026-10-08 14:05:22", "User": "john_doe", "File": "financial_audit.pdf", "Threat Score": "78%", "Status": "BLOCKED"}
    ])
    st.dataframe(demo_logs, use_container_width=True)
