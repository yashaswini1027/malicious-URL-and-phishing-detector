# malicious-URL-and-phishing-detector
# Malicious URL & Phishing Detector

[![Live Demo](https://img.shields.io/badge/Demo-Live_App-blue?style=for-the-badge&logo=render)](https://your-app-name.onrender.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green?style=for-the-badge&logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-black?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

An end-to-end full-stack web application and REST API that analyzes URL structure and lexical indicators to flag potentially malicious links. The included offline scanner uses local heuristics and does not fetch submitted pages.

---

##  Key Features

* ** Real-Time Lexical Analysis:** Instantly extracts dynamic structural features from submitted URLs without reliance on slow database lookups.
* **Offline URL Analysis:** Scores URL structure and suspicious lexical indicators locally; it does not require a model file or network access at scan time.
* ** Smart Authority Whitelisting:** Bypasses prediction on recognized high-authority domains (e.g., `github.com`, `google.com`) to eliminate false positives.
* ** Risk Breakdown & Scoring:** Returns a confidence score alongside specific threat flags (e.g., IP addresses in host, suspicious keywords, URL shortening services).
* ** Interactive Web Dashboard:** Lightweight frontend UI built with HTML5, CSS3, and JavaScript for quick manual link testing.

---

## Architecture & System Workflow

```text
  [ User Submits URL ]
           │
           ▼
┌───────────────────────┐
│   Frontend / Client   │ (HTML / CSS / JavaScript)
└──────────┬────────────┘
           │  POST /predict
           ▼
┌───────────────────────┐
│     Flask REST API    │ (Python Backend)
└──────────┬────────────┘
           │
    ┌──────┴────────┐
    ▼               ▼
┌─────────────┐  ┌───────────────────────┐
│ Whitelist   │  │ Feature Extractor     │
│ Check       │  │ (urllib / Regex)      │
└──────┬──────┘  └──────────┬────────────┘
       │                    │
       │ PASS               ▼
       │         ┌───────────────────────┐
       │         │ Local Heuristic Score │
       │         └──────────┬────────────┘
       │                    │
       └──────────┬─────────┘
                  │
                  ▼
       [ JSON Prediction Response ]
```

## Run Offline

With Flask installed in the workspace virtual environment, start the app from the repository root:

```powershell
.\.venv\Scripts\python.exe .\backend\backend\app.py
```

Open `http://127.0.0.1:5000`. Flask serves both the interface and `/predict`, so a separate frontend server, Node.js, and `model.pkl` are not needed. The URL checks run locally; they do not inspect live page contents or consult reputation feeds. Install Python dependencies before going offline if they are not already available.
