import streamlit as st
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier
import datetime
import os

# ==========================================
# 1. Page Configuration & Catchy Theme
# ==========================================
st.set_page_config(
    page_title="AI File Guard :: Neural Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Cyberpunk/Security Theme & Mobile Responsiveness
st.markdown("""
<style>
    /* Main App Background & Text */
    .stApp {
        background-color: #0E1117;
        color: #E0E6ED;
        font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    }

    /* Top Banner Gradient */
    .stHeader {
        background: linear-gradient(90deg, #1e3a8a 0%, #0d9488 100%);
    }

    /* Titles and Headers */
    h1, h2, h3 {
        color: #00FFCC; /* Neon Teal */
        font-weight: 700;
        letter-spacing: -0.5px;
    }

    /* Primary Title Styling */
    .super-title {
        font-size: 3rem;
        background: -webkit-linear-gradient(#00FFCC, #00CCFF);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        padding-bottom: 1rem;
    }

    /* Subtitle Styling */
    .super-subtitle {
        font-size: 1.2rem;
        color: #8899A6;
        text-align: center;
        padding-bottom: 2rem;
        border-bottom: 1px solid #1E293B;
    }

    /* Mobile Title Scaling */
    @media (max-width: 768px) {
        .super-title { font-size: 2rem; }
        .super-subtitle { font-size: 1rem; }
    }

    /* Visual Containers (Cards) */
    .st-emotion-cache-12w0458, .st-emotion-cache-1r6slb0, div[data-testid="stBlock"] {
        background-color: #161B22;
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #1E293B;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2);
        margin-bottom: 20px;
    }

    /* Input Fields */
    .stTextArea textarea {
        background-color: #040609 !important;
        border: 1px solid #30363D !important;
        color: #00FFCC !important;
        font-family: 'Courier New', Courier, monospace;
    }

    /* Buttons */
    .stButton>button {
        width: 100%;
        background: linear-gradient(90deg, #0d9488 0%, #0f766e 100%);
        color: white;
        font-weight: bold;
        border: none;
        border-radius: 8px;
        padding: 10px 20px;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background: linear-gradient(90deg, #0f766e 0%, #0d9488 100%);
        box-shadow: 0 0 10px rgba(0, 255, 204, 0.5);
        transform: translateY(-2px);
    }

    /* Expander styling */
    .streamlit-expanderHeader {
        background-color: #1E293B;
        border-radius: 8px;
        color: #00FFCC;
    }

    /* Detection Results Card */
    .safe-card {
        padding: 20px;
        background-color: rgba(0, 255, 102, 0.1);
        border: 2px solid #00FF66;
        border-radius: 12px;
        color: #00FF66;
        text-align: center;
        font-size: 1.2rem;
        font-weight: bold;
    }
    .unsafe-card {
        padding: 20px;
        background-color: rgba(255, 51, 51, 0.1);
        border: 2px solid #FF3333;
        border-radius: 12px;
        color: #FF3333;
        text-align: center;
        font-size: 1.2rem;
        font-weight: bold;
    }

</style>
""", unsafe_allow_html=True)

# ==========================================
# 2. Dummy AI Model Setup
# ==========================================
@st.cache_resource # Keeps the model in memory
def load_security_model():
    # Placeholder training data (dummy data for the project structure)
    data = pd.DataFrame({
        'content': [
            "Project report for Q3", "API Key: sk_live_12345", 
            "Weekly team sync notes", "User SSN: 987-65-4321",
            "Vacation schedule", "password=SuperSecretPassword123!",
            "Lunch menu options", "CONFIDENTIAL: DO NOT SHARE",
            "Regular meeting agenda", "Database Connection String: host=10.0.0.1;user=admin"
        ],
        'label': [0, 1, 0, 1, 0, 1, 0, 1, 0, 1] # 0 = Safe, 1 = Sensitive
    })
    
    vectorizer = CountVectorizer()
    X = vectorizer.fit_transform(data['content'])
    model = RandomForestClassifier(n_estimators=10)
    model.fit(X, data['label'])
    
    return vectorizer, model

vectorizer, model = load_security_model()

# ==========================================
# 3. Main UI Content
# ==========================================

# Landing Section
st.markdown('<p class="super-title">AI FILE GUARD</p>', unsafe_allow_html=True)
st.markdown('<p class="super-subtitle">Neural Net Data Loss Prevention (DLP)</p>', unsafe_allow_html=True)

# Main Application Area (using columns for layout on desktop, flows vertically on mobile)
col1, col2 = st.columns([2, 1])

with col1:
    st.markdown("### 🖥️ AI Threat Analysis")
    st.write("Input file content below for AI-powered sensitive data detection.")
    
    input_text = st.text_area("Analyze Text Stream:", height=250, placeholder="Paste data logs, file content, or code snippets here...")
    
    scan_btn = st.button("RUN NEURAL SCAN")

    if scan_btn and input_text:
        # Pre-process & Predict
        text_vectorized = vectorizer.transform([input_text])
        prediction = model.predict(text_vectorized)
        
        st.markdown("---")
        st.markdown("### 📊 Scan Results")
        
        if prediction[0] == 0:
            st.markdown("""
                <div class="safe-card">
                    ✅ ANALYSES COMPLETE: NO SENSITIVE DATA DETECTED.
                    <p style="font-size:0.8rem; color:#8899A6; font-weight:normal; margin-top:10px;">
                    This content appears safe for public distribution.</p>
                </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
                <div class="unsafe-card">
                    ⚠️ ALERT: CRITICAL DATA LEAK DETECTED!
                    <p style="font-size:0.8rem; color:#8899A6; font-weight:normal; margin-top:10px;">
                    AI detected patterns matching passwords, API keys, or PII.</p>
                </div>
            """, unsafe_allow_html=True)
            st.error("Do not share this content externally.")
    elif scan_btn and not input_text:
        st.warning("Please enter text to analyze.")

with col2:
    st.markdown("### 📋 Guard Info")
    
    with st.expander("System Architecture", expanded=True):
        st.write("""
        *   **UI:** Streamlit (Python)
        *   **AI Engine:** Random Forest Classifier
        *   **Backend:** Linux Kernel Auditing (Auditd)
        """)

    with st.expander("Detection Capabilities"):
        st.write("""
        *   API Keys / Secret Tokens
        *   Passwords in plain text
        *   PII (SSN, emails)
        *   Database strings
        """)
    
    st.info("**Mobile Compatibility:** This interface uses responsive CSS grids and scales down cleanly on smartphone screens.")

# ==========================================
# 4. Footer
# ==========================================
st.markdown("---")
current_year = datetime.datetime.now().year
st.markdown(f'<p style="text-align:center; color:#8899A6;">© {current_year} | University Cybersecurity Project Demo | Status: Operational</p>', unsafe_allow_html=True)
