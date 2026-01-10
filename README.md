# 🛡️ Network Sentinel: Hierarchical Intrusion Detection System (IDS)

**Tech Stack:** Python 3.10+ | Streamlit Dashboard | Hierarchical Machine Learning Model

**Network Sentinel** is a hybrid security system designed to detect network anomalies in real-time. Unlike traditional signature-based IDSs, it uses a **Hierarchical Machine Learning Architecture** to catch both known attacks and zero-day anomalies, reinforced by heuristic bypass rules for stealth detection.

---

**Network Sentinel** is a hybrid security system designed to detect network anomalies in real-time. Unlike traditional signature-based IDSs, it uses a **Hierarchical Machine Learning Architecture** to catch both known attacks and zero-day anomalies, reinforced by heuristic bypass rules for stealth detection.

---

## 🧠 System Architecture

This project addresses the "Domain Shift" problem in cybersecurity by chaining three detection layers. The system operates hierarchically to filter traffic efficiently:

### 1. The Gatekeeper (Isolation Forest)
* **Role:** Unsupervised Anomaly Detection.
* **Function:** Filters out mass-volume attacks (DoS, Probe) and identifies "weird" traffic without needing specific labels.
* **Why:** Captures unknown "Zero-Day" attacks that supervised models miss.

### 2. The Specialist (Random Forest)
* **Role:** Supervised Multi-Class Classification.
* **Function:** Classifies the specific attack type (DoS, Probe, U2R, R2L) for any traffic flagged by the Gatekeeper.
* **Why:** Provides actionable intelligence on *what* the threat is.

### 3. The Bypass Rules (Heuristics)
* **Role:** Deterministic Logic Layer.
* **Function:** Catches stealthy attacks (like `root_shell` access or repeated failed logins) that statistically look "Normal" to ML models.
* **Impact:** Increased Precision for U2R (User-to-Root) and R2L (Remote-to-Local) attacks.

---

## 📊 Dashboard Features

The system includes a **Streamlit Dashboard** designed for security analysts:

* **Real-Time Simulation:** Simulates IP attribution (identifying potential attackers from Russia, China, etc. proxies).
* **Intelligent Threat Diagnosis:** A "Reasoning Engine" that explains *why* a packet was flagged (e.g., *"CRITICAL: Root Access Obtained"* or *"High Traffic Volume"*).
* **Strict Schema Validation:** Prevents data corruption by rejecting malformed CSV uploads before processing.
* **Traffic Visualization:** Interactive Plotly charts for protocol breakdown and attack sources.

---
2 Testing Options:

Option A:  https://network-anomaly-detection-etfj9gn2gfjbvhwu2ph5vr.streamlit.app/


Option B:

## 🚀 Installation & Usage

### 1. Clone the Repository
```bash
git clone [https://github.com/RadyAi-data/network-anomaly-detection.git](https://github.com/RadyAi-data/network-anomaly-detection.git)
cd network-anomaly-detection
```
2. Install Dependencies

```bash
    pip install -r requirements.txt
```

3. Run the Dashboard

```bash
    streamlit run dashboard/app.py
```
How to test
Download the CSV Template from the dashboard sidebar.

Upload data/test_set_unlabelled.csv (or the provided sample).

Click 🚀 Analyze Traffic.

View the detected threats and the "Intelligent Diagnosis" log.


Project Structure
Plaintext

network-anomaly-detection/
├── dashboard/
│   └── app.py              # Main Streamlit Dashboard (The "Product")
├── models/
│   ├── isolation_forest.pkl # Stage 1 Model (Gate keeper)
│   ├── attack_classifier.pkl # Stage 2 Model (The Specialist)
│   └── preprocessor.pkl     # Data Transformation Pipeline
├── notebooks/
│   ├── 01_Intial_exploration.ipynb # Getting used to the data
│   ├── 02_Deep_eda.ipynb # Exploring the data deeper,feature enginnering & setting up the SQL data base
│   ├── 03_Prepping_data_for_learning.ipynb # Prepping the data for training
│   └── 04_Model_training.ipynb # Training Both models & developing the Bypass to have the Hierarchical System
├── data/                   # (Not included in repo for size)
└── requirements.txt        # Python dependencies


## 📈 Performance

The system was evaluated on the **KDD Cup 99** test set:

| Metric | Score | Notes |
| :--- | :--- | :--- |
| **Accuracy** | **93%** | High fidelity on mixed traffic. |
| **DoS Precision** | **99%** | Almost zero false alarms for Denial of Service attacks. |
| **Probe Recall** | **87%** | Successfully detects the majority of surveillance/scanning attempts. |
| **U2R Recall** | **69%** | High detection rate for rootkit attacks (aided by Sanity Checks). |
