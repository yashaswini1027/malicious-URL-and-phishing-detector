# malicious-URL-and-phishing-detector
# Malicious URL & Phishing Detector

[![Live Demo](https://img.shields.io/badge/Demo-Live_App-blue?style=for-the-badge&logo=render)](https://your-app-name.onrender.com)
[![Python](https://img.shields.io/badge/Python-3.10%2B-green?style=for-the-badge&logo=python)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-black?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com/)
[![scikit-learn](https://img.shields.io/badge/ML-scikit--learn-orange?style=for-the-badge&logo=scikit-learn)](https://scikit-learn.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

An end-to-end full-stack web application and REST API that analyzes domain structure, lexical patterns, and heuristic indicators to detect phishing links and malicious URLs in real time using Machine Learning.

---

##  Key Features

* ** Real-Time Lexical Analysis:** Instantly extracts dynamic structural features from submitted URLs without reliance on slow database lookups.
* **Machine Learning Classification:** Powered by a Random Forest Classifier trained on over 50,000 verified safe and malicious URLs.
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
       │         │  Random Forest Model  │ (.pkl pipeline)
       │         └──────────┬────────────┘
       │                    │
       └──────────┬─────────┘
                  │
                  ▼
      [ JSON Prediction Response ]
