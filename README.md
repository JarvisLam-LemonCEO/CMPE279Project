# CMPE279 Project
# Phishing Detection System Using Email Header Analysis

A Python desktop application (Tkinter GUI) for detecting **phishing emails** based on **email header analysis**.  
The system combines:

- **Heuristic rules** (e.g., SPF/DKIM, From ↔ Reply-To mismatch, suspicious TLDs)
- **Unsupervised anomaly detection** (IsolationForest trained on the Enron dataset)
- **Optional Large Language Model (LLM) analysis** via [LM Studio](https://lmstudio.ai)  
- **Hybrid voting system** (Heuristic + Anomaly + LLM)

> 🎯 Built for a Software Security course project: gain hands-on experience with intrusion detection, anomaly detection, and secure email analysis.

---

## ✨ Features

- Load the [Enron Email Dataset](https://www.cs.cmu.edu/~enron/) (CSV format)  
- Extract header-only features  
- **Heuristic scoring** (rule-based flags with explanations)  
- **Train Anomaly Model** (IsolationForest learns "normal" headers)  
- **Analyze Email (.eml)**: paste headers or open a file to classify  
- **Optional LLM support** (LM Studio local server for phishing/legit classification with reasons)  
- **Hybrid verdict**: PHISHING if ≥ 2 of 3 methods vote phishing  
- **Export scan results
