# 🛡️ Python-Based Intrusion Detection System (IDS)

A lightweight IDS built using Python that detects network intrusions using both:
- 🔍 Signature-based detection (via Scapy)
- 🤖 Anomaly detection (via Machine Learning - Isolation Forest)

## 📂 Features
- Real-time packet sniffing and analysis
- Tkinter GUI Dashboard for live monitoring
- Alerts on known attack signatures (SQLi, XSS, Nmap scan)
- ML-based anomaly detection for unknown threats
- Logs alerts to file with timestamps

## 🚀 Run Locally

### 1. Install dependencies
```bash
pip install -r requirements.txt
