# CMPE279 Project
# Phishing Detection System (A Python GUI Application)

A Python desktop application (Tkinter GUI) for detecting **phishing emails** based on **email header analysis**.  
The system combines:

- **Heuristic rules** (e.g., SPF/DKIM, From ↔ Reply-To mismatch, suspicious TLDs)
- **Unsupervised anomaly detection** (IsolationForest trained on the Enron dataset)
- **Optional Large Language Model (LLM) analysis** via [LM Studio](https://lmstudio.ai)  
- **Hybrid voting system** (Heuristic + Anomaly + LLM)

> Built for a Software Security course project: gain hands-on experience with intrusion detection, anomaly detection, and secure email analysis.

---

## Features

- Load the [Enron Email Dataset](https://www.kaggle.com/datasets/wcukierski/enron-email-dataset/data) (CSV format)  
- Extract header-only features  
- **Heuristic scoring** (rule-based flags with explanations)  
- **Train Anomaly Model** (IsolationForest learns "normal" headers)  
- **Analyze Email (.eml)**: paste headers or open a file to classify  
- **Optional LLM support** (LM Studio local server for phishing/legit classification with reasons)  
- **Hybrid verdict**: PHISHING if ≥ 2 of 3 methods vote phishing  
- **Export scan results** to CSV for reporting

---

## Installation

Clone the repo:

```bash
git clone https://github.com/yourusername/phishing-header-analyzer.git
cd phishing-header-analyzer
```

## Create a virtual environment
python -m venv .venv
# Windows
.\.venv\Scripts\activate
# macOS/Linux
source .venv/bin/activate

## Install dependencies
```bash
pip install -r requirements.txt
```

## Run the app
```bash
python PDS.py
```

---

## Demo Workflow

### Dataset & Training
1. Open the app (`python PDS.py`).  
2. Go to **Dataset & Training** tab.  
3. Select your **Enron CSV file** (column: `message`).  
4. Click **Build Dataset**.  
5. (Optional) Set **contamination** (e.g., `0.05`) → **Train Anomaly Model**.  
6. Run **Heuristic Scan CSV** to preview rule-based results.  
7. Export results for your report.

### Analyze Email
1. Go to **Analyze Email** tab.  
2. Paste raw headers or **Open .eml** file.  
3. Click **Classify**.  
4. View:
   - Heuristic score + flags  
   - Anomaly status (if trained)  
   - LLM verdict (if enabled)  
   - Final **hybrid decision**
