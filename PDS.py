#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Phishing Header Analyzer — Enron CSV Only + Optional LM Studio LLM (Headless LLM Config)
GUI: Tkinter

- Load Enron CSV (raw RFC822 column, default "message")
- Header-only features
- Heuristic scoring (explainable)
- Optional unsupervised anomaly detection (IsolationForest) trained on Enron
- Optional LM Studio LLM classification (OpenAI-compatible endpoint)
- Hybrid voting (Heuristic + Anomaly + LLM)

LLM config is NOT shown in the UI. It uses environment variables:
  LMSTUDIO_URL   (default: http://localhost:12345/v1/chat/completions)
  LMSTUDIO_MODEL (default: local-model)
  LMSTUDIO_API_KEY (optional)
"""

import os
import re
import json
import traceback
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from dataclasses import dataclass
from typing import List, Dict, Any, Tuple, Optional

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import joblib
import tldextract
import requests
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr, getaddresses

from sklearn.ensemble import IsolationForest

# ------------------------------
# Helpers
# ------------------------------

def clean_text(s: Optional[str]) -> str:
    if not s:
        return ""
    return " ".join(str(s).split())

DOMAIN_RE = re.compile(r"[^@\s]+@([^>\s]+)")

def extract_domain(addr: str) -> str:
    if not addr:
        return ""
    name, emailaddr = parseaddr(addr)
    candidate = emailaddr or addr
    try:
        m = DOMAIN_RE.search(candidate)
        host = m.group(1) if m else candidate.split("@")[-1]
        ext = tldextract.extract(host)
        return (ext.registered_domain.lower() if ext.registered_domain else host.lower())
    except Exception:
        return candidate.lower()

def tld_from_domain(domain: str) -> str:
    if not domain:
        return ""
    ext = tldextract.extract(domain)
    return ext.suffix.lower()

def count_header_occurrences(raw: str, header_name: str) -> int:
    pattern = re.compile(rf"\n{re.escape(header_name)}:\s", re.IGNORECASE)
    return len(pattern.findall("\n" + raw))

SUSPICIOUS_TLDS = {
    "xyz","top","gq","cf","tk","ml","work","country","zip","review","link",
    "click","kim","men","info","download","monster","bid","party","science","date",
    "loan","win","stream","racing","wang","fit","ga","ru","cn","accountants"
}

URGENT_WORDS = re.compile(r"\b(verify|urgent|suspend|password|confirm|account|locked|update|action required|security alert)\b", re.I)
BRAND_WORDS  = re.compile(r"\b(apple|paypal|microsoft|google|amazon|bank|chase|wells fargo|office 365|outlook|coinbase)\b", re.I)

@dataclass
class ParsedHeaders:
    headers: Dict[str, str]
    raw: str

# ------------------------------
# Parsing
# ------------------------------

def parse_email_bytes(eml_bytes: bytes) -> ParsedHeaders:
    msg = BytesParser(policy=policy.default).parsebytes(eml_bytes)
    headers = {k: clean_text(v) for k, v in msg.items()}
    raw = "\n".join([f"{k}: {v}" for k, v in msg.items()])
    return ParsedHeaders(headers=headers, raw=raw)

def parse_eml_file(path: str) -> ParsedHeaders:
    with open(path, 'rb') as f:
        data = f.read()
    return parse_email_bytes(data)

def normalize_raw_message(text: str) -> str:
    """Ensure there's a blank line between headers and body so the parser works."""
    if "\n\n" in text or "\r\n\r\n" in text:
        return text
    lines = text.splitlines()
    hdr_end_idx = None
    for j, line in enumerate(lines):
        if line.strip() == "":
            hdr_end_idx = j
            break
        if not (":" in line or (line.startswith(" ") or line.startswith("\t"))):
            hdr_end_idx = j
            break
    if hdr_end_idx is None:
        hdr_end_idx = len(lines)
    lines.insert(hdr_end_idx, "")
    return "\n".join(lines)

# ------------------------------
# Features & Heuristics
# ------------------------------

def features_from_parsed(ph: ParsedHeaders) -> Dict[str, Any]:
    H = {k.lower(): v for k, v in ph.headers.items()}
    raw = ph.raw

    from_h       = H.get('from', '')
    reply_to_h   = H.get('reply-to', '')
    return_path  = H.get('return-path', '')
    msgid_h      = H.get('message-id', '')
    subject_h    = H.get('subject', '')
    authres_h    = H.get('authentication-results', '')

    from_domain  = extract_domain(from_h)
    reply_domain = extract_domain(reply_to_h)
    return_dom   = extract_domain(return_path)
    msgid_domain = extract_domain(msgid_h)

    to_count = len(getaddresses([H.get('to', '')]))
    cc_count = len(getaddresses([H.get('cc', '')]))

    received_count = count_header_occurrences("\n" + raw, 'Received')

    spf_pass = 1 if re.search(r"spf=pass", authres_h, re.I) or H.get('received-spf', '').lower().startswith('pass') else 0
    spf_fail = 1 if re.search(r"spf=(fail|softfail|neutral|none)", authres_h, re.I) or H.get('received-spf', '').lower().startswith(('fail','softfail','neutral','none')) else 0
    has_dkim = 1 if ('dkim-signature' in H) or re.search(r"dkim=pass", authres_h, re.I) else 0

    content_type = H.get('content-type', '')
    is_html = 1 if 'text/html' in content_type.lower() else 0

    from_reply_mismatch = int(bool(from_domain and reply_domain and (from_domain != reply_domain)))
    from_return_mismatch = int(bool(from_domain and return_dom and (from_domain != return_dom)))
    msgid_from_mismatch  = int(bool(from_domain and msgid_domain and (from_domain != msgid_domain)))

    _, from_addr_email = parseaddr(from_h)
    local_part = from_addr_email.split('@')[0] if '@' in from_addr_email else from_addr_email
    digit_ratio = sum(c.isdigit() for c in local_part) / max(1, len(local_part))

    subject_urgent = 1 if URGENT_WORDS.search(subject_h or "") else 0
    subject_brand  = 1 if BRAND_WORDS.search(subject_h or "") else 0

    from_tld = tld_from_domain(from_domain)
    suspicious_tld = 1 if from_tld in SUSPICIOUS_TLDS else 0

    return {
        'from_tld': from_tld,
        'received_count': received_count,
        'spf_pass': spf_pass,
        'spf_fail': spf_fail,
        'has_dkim': has_dkim,
        'is_html': is_html,
        'to_count': to_count,
        'cc_count': cc_count,
        'from_reply_mismatch': from_reply_mismatch,
        'from_return_mismatch': from_return_mismatch,
        'msgid_from_mismatch': msgid_from_mismatch,
        'from_local_digit_ratio': digit_ratio,
        'subject_urgent': subject_urgent,
        'subject_brand': subject_brand,
        'suspicious_tld': suspicious_tld,
    }

HEURISTIC_FIELDS = [
    'received_count','spf_pass','spf_fail','has_dkim','is_html','to_count','cc_count',
    'from_reply_mismatch','from_return_mismatch','msgid_from_mismatch',
    'from_local_digit_ratio','subject_urgent','subject_brand','suspicious_tld'
]

def heuristic_score(feats: Dict[str, Any]) -> Tuple[int, List[str]]:
    reasons = []
    score = 0
    if feats['spf_fail'] and not feats['spf_pass']:
        score += 1; reasons.append("SPF not passing / failing")
    if not feats['has_dkim']:
        score += 1; reasons.append("No DKIM")
    if feats['from_reply_mismatch']:
        score += 1; reasons.append("From ↔ Reply-To mismatch")
    if feats['from_return_mismatch']:
        score += 1; reasons.append("From ↔ Return-Path mismatch")
    if feats['msgid_from_mismatch']:
        score += 1; reasons.append("Message-ID domain ≠ From domain")
    if feats['suspicious_tld']:
        score += 1; reasons.append("Suspicious sender TLD")
    if feats['from_local_digit_ratio'] > 0.3:
        score += 1; reasons.append("Sender local-part has many digits")
    if feats['subject_urgent']:
        score += 1; reasons.append("Urgent language in Subject")
    if feats['received_count'] <= 1:
        score += 1; reasons.append("Short Received chain")
    return score, reasons

def vectorize_feature_rows(rows: List[Dict[str, Any]]) -> Tuple[pd.DataFrame, List[str]]:
    df = pd.DataFrame(rows)
    if 'from_tld' in df:
        df = pd.get_dummies(df, columns=['from_tld'], prefix=['tld'], dummy_na=True)
    df = df.fillna(0)
    feature_names = list(df.columns)
    return df, feature_names

# ------------------------------
# Dataset loader (CSV)
# ------------------------------

def looks_like_headers(text: str) -> bool:
    if not text:
        return False
    return ("From:" in text) and ("Message-ID:" in text or "Date:" in text or "Received:" in text)

def load_enron_csv(csv_path: str, column: str, limit: Optional[int] = None) -> List[ParsedHeaders]:
    out: List[ParsedHeaders] = []
    try:
        df = pd.read_csv(csv_path, low_memory=False)
    except Exception:
        df = pd.read_csv(csv_path, sep='\t', low_memory=False)
    if column not in df.columns:
        raise ValueError(f"Column '{column}' not found in CSV. Available: {list(df.columns)[:12]}…")
    for raw in df[column].astype(str).tolist():
        if limit and len(out) >= limit:
            break
        if not looks_like_headers(raw):
            continue
        pseudo = normalize_raw_message(raw).rstrip() + "\n\n"
        try:
            out.append(parse_email_bytes(pseudo.encode('utf-8', errors='ignore')))
        except Exception:
            continue
    return out

# ------------------------------
# Model (Unsupervised anomaly)
# ------------------------------

class AnomalyModel:
    def __init__(self, contamination: float = 0.05, random_state: int = 42):
        self.model: Optional[IsolationForest] = None
        self.feature_names: List[str] = []
        self.contamination = contamination
        self.random_state = random_state

    def train(self, feats_df: pd.DataFrame, feature_names: List[str]):
        self.feature_names = feature_names
        X = feats_df[feature_names]
        self.model = IsolationForest(
            n_estimators=200,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1
        )
        self.model.fit(X)

    def score_one(self, feats_row: Dict[str, Any]) -> float:
        if not self.model:
            raise RuntimeError("Anomaly model not trained")
        Xdf, _ = vectorize_feature_rows([feats_row])
        for col in self.feature_names:
            if col not in Xdf:
                Xdf[col] = 0
        for col in list(Xdf.columns):
            if col not in self.feature_names:
                Xdf.drop(columns=[col], inplace=True)
        Xdf = Xdf[self.feature_names]
        return float(self.model.score_samples(Xdf)[0])  # higher = more normal

    def predict_one(self, feats_row: Dict[str, Any]) -> int:
        if not self.model:
            raise RuntimeError("Anomaly model not trained")
        Xdf, _ = vectorize_feature_rows([feats_row])
        for col in self.feature_names:
            if col not in Xdf:
                Xdf[col] = 0
        for col in list(Xdf.columns):
            if col not in self.feature_names:
                Xdf.drop(columns=[col], inplace=True)
        Xdf = Xdf[self.feature_names]
        return int(self.model.predict(Xdf)[0] == -1)  # 1 = anomalous (suspicious)

    def save(self, path: str):
        joblib.dump({'model': self.model, 'features': self.feature_names}, path)

    def load(self, path: str):
        obj = joblib.load(path)
        self.model = obj['model']
        self.feature_names = obj['features']

# ------------------------------
# LLM Integration (LM Studio) — headless config
# ------------------------------

DEFAULT_LLM_URL   = os.environ.get("LMSTUDIO_URL", "http://localhost:8080/v1/chat/completions")
DEFAULT_LLM_MODEL = os.environ.get("LMSTUDIO_MODEL", "local-model")
DEFAULT_LLM_API_KEY = os.environ.get("LMSTUDIO_API_KEY")  # optional

SYSTEM_PROMPT = (
    "You are a security analyst. Classify an email based ONLY on headers. "
    "Return JSON with fields: verdict ('phishing' or 'legit_or_unclear'), "
    "reasons (array of short strings). Be conservative—no body analysis."
)

def classify_with_llm(raw_headers: str, timeout: int = 45) -> dict:
    payload = {
        "model": DEFAULT_LLM_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Email headers:\n\n{raw_headers}\n\nReturn JSON only."}
        ],
        "temperature": 0.0,
    }
    headers = {}
    if DEFAULT_LLM_API_KEY:
        headers["Authorization"] = f"Bearer {DEFAULT_LLM_API_KEY}"
    try:
        r = requests.post(DEFAULT_LLM_URL, json=payload, headers=headers, timeout=timeout)
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
        start = content.find("{"); end = content.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(content[start:end+1])
        return {"verdict": "legit_or_unclear", "reasons": ["LLM returned no JSON."]}
    except Exception as e:
        return {"verdict": "legit_or_unclear", "reasons": [f"LLM error: {e}"]}

# ------------------------------
# GUI
# ------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Phishing Header Analyzer — Enron CSV + LLM (Headless)")
        self.geometry("1100x860")

        # Data / model
        self.anom = AnomalyModel()
        self.enron_feats_df: Optional[pd.DataFrame] = None
        self.feature_names: List[str] = []
        self.heur_threshold = 2

        # LLM toggle only (no URL/model/API key fields)
        self.use_llm = tk.BooleanVar(value=False)

        self._last_scan_df: Optional[pd.DataFrame] = None
        self._build_ui()

    def _build_ui(self):
        nb = ttk.Notebook(self); nb.pack(fill=tk.BOTH, expand=True)

        self.tab_dataset = ttk.Frame(nb)
        self.tab_analyze = ttk.Frame(nb)
        nb.add(self.tab_dataset, text="Dataset & Training")
        nb.add(self.tab_analyze, text="Analyze Email")

        self._build_dataset_tab(self.tab_dataset)
        self._build_analyze_tab(self.tab_analyze)

    def _build_dataset_tab(self, parent):
        frm = ttk.Frame(parent, padding=10); frm.pack(fill=tk.BOTH, expand=True)

        self.csv_path_var = tk.StringVar()
        self.csv_col_var = tk.StringVar(value="message")
        self.limit_var = tk.StringVar(value="50000")
        self.contamination_var = tk.StringVar(value="0.05")

        ttk.Label(frm, text="Enron CSV path:").grid(row=0, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.csv_path_var, width=70).grid(row=0, column=1, padx=6, pady=3, sticky="we")
        ttk.Button(frm, text="Browse", command=self.browse_csv).grid(row=0, column=2, padx=4)

        ttk.Label(frm, text="Column name (raw RFC822):").grid(row=1, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.csv_col_var, width=24).grid(row=1, column=1, sticky="w")

        ttk.Label(frm, text="Max rows:").grid(row=2, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.limit_var, width=12).grid(row=2, column=1, sticky="w")

        ttk.Label(frm, text="Anomaly contamination (0.01–0.2):").grid(row=3, column=0, sticky="w")
        ttk.Entry(frm, textvariable=self.contamination_var, width=12).grid(row=3, column=1, sticky="w")

        btns = ttk.Frame(frm); btns.grid(row=4, column=0, columnspan=3, pady=8, sticky="w")
        ttk.Button(btns, text="Build Dataset (from CSV)", command=self.build_dataset).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Train Anomaly Model", command=self.train_anomaly).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Heuristic Scan CSV", command=self.scan_csv_heuristic).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Export Last Scan CSV", command=self.export_last_scan).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Save Model", command=self.save_model).pack(side=tk.LEFT, padx=4)
        ttk.Button(btns, text="Load Model", command=self.load_model).pack(side=tk.LEFT, padx=4)

        self.log = tk.Text(frm, height=24); self.log.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=8)
        frm.rowconfigure(5, weight=1); frm.columnconfigure(1, weight=1)

    def _build_analyze_tab(self, parent):
        frm = ttk.Frame(parent, padding=10); frm.pack(fill=tk.BOTH, expand=True)

        top = ttk.Frame(frm); top.pack(fill=tk.X)
        ttk.Button(top, text="Open .eml", command=self.open_eml).pack(side=tk.LEFT, padx=4)
        ttk.Button(top, text="Classify", command=self.classify_input).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(top, text="Use LLM (LM Studio)", variable=self.use_llm).pack(side=tk.LEFT, padx=10)
        ttk.Button(top, text="Clear", command=lambda: self.headers_box.delete('1.0', tk.END)).pack(side=tk.LEFT, padx=4)

        self.headers_box = tk.Text(frm, height=22); self.headers_box.pack(fill=tk.BOTH, expand=True, pady=8)

        self.result_var = tk.StringVar()
        ttk.Label(frm, textvariable=self.result_var, font=("TkDefaultFont", 11, "bold")).pack(anchor='w')

        self.explain_box = tk.Text(frm, height=12); self.explain_box.pack(fill=tk.BOTH, expand=False, pady=6)

    # --- helpers
    def _log(self, s: str):
        self.log.insert(tk.END, s + "\n"); self.log.see(tk.END); self.update()

    def browse_csv(self):
        path = filedialog.askopenfilename(title="Select Enron CSV", filetypes=[("CSV", "*.csv"), ("All files", "*.*")])
        if path: self.csv_path_var.set(path)

    # --- dataset & model
    def build_dataset(self):
        try:
            csv_path = self.csv_path_var.get().strip()
            col = self.csv_col_var.get().strip()
            if not os.path.isfile(csv_path):
                messagebox.showerror("Missing", "Pick an Enron CSV file"); return
            limit = int(self.limit_var.get() or 0) or None
            self._log("Loading Enron CSV… (this may take a bit)")
            msgs = load_enron_csv(csv_path, col, limit=limit)
            self._log(f"Loaded: {len(msgs)} messages with parseable headers")
            if len(msgs) == 0:
                messagebox.showerror("No data", "No parseable headers found. Check the column name and CSV format."); return
            rows = [features_from_parsed(m) for m in msgs]
            feats_df, names = vectorize_feature_rows(rows)
            self.enron_feats_df = feats_df; self.feature_names = names
            self._log(f"Feature rows: {len(feats_df)} | features: {len(names)}")
        except Exception as e:
            traceback.print_exc(); messagebox.showerror("Build error", str(e))

    def train_anomaly(self):
        if self.enron_feats_df is None:
            messagebox.showerror("No dataset", "Build the dataset from CSV first"); return
        try:
            contamination = float(self.contamination_var.get() or 0.05)
            contamination = max(0.001, min(0.3, contamination))
        except Exception:
            contamination = 0.05
        self._log(f"Training IsolationForest (contamination={contamination})…")
        self.anom = AnomalyModel(contamination=contamination, random_state=42)
        self.anom.train(self.enron_feats_df, self.feature_names)
        self._log("Anomaly model trained. You can now classify individual emails with anomaly scoring.")

    def scan_csv_heuristic(self):
        try:
            csv_path = self.csv_path_var.get().strip()
            col = self.csv_col_var.get().strip()
            if not os.path.isfile(csv_path):
                messagebox.showerror("Missing", "Pick an Enron CSV file"); return
            limit = int(self.limit_var.get() or 0) or None
            self._log("Scanning CSV with heuristics…")
            msgs = load_enron_csv(csv_path, col, limit=limit)
            results = []; phish_cnt = 0
            for m in msgs:
                feats = features_from_parsed(m)
                score, reasons = heuristic_score(feats)
                verdict = "Phishing" if score >= self.heur_threshold else "Legit/Unclear"
                if verdict == "Phishing": phish_cnt += 1
                row = {'score': score, 'verdict': verdict, 'reasons': "; ".join(reasons)}
                row.update({k: feats.get(k, "") for k in HEURISTIC_FIELDS})
                results.append(row)
            df = pd.DataFrame(results)
            self._last_scan_df = df
            self._log(f"Heuristic scan complete. Rows: {len(df)} | flagged as Phishing: {phish_cnt}")
            try:
                counts = df['verdict'].value_counts()
                fig = plt.figure(); ax = fig.add_subplot(111)
                counts.plot(kind='bar', ax=ax)
                ax.set_title('Heuristic Verdict Counts'); ax.set_xlabel('Verdict'); ax.set_ylabel('Count')
                plt.show()
            except Exception:
                pass
        except Exception as e:
            traceback.print_exc(); messagebox.showerror("Heuristic scan error", str(e))

    def export_last_scan(self):
        if self._last_scan_df is None:
            messagebox.showinfo("Nothing to export", "Run 'Heuristic Scan CSV' first."); return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if path:
            try: self._last_scan_df.to_csv(path, index=False); messagebox.showinfo("Exported", f"Saved to {path}")
            except Exception as e: messagebox.showerror("Export failed", str(e))

    # --- Analyze tab (single email)
    def open_eml(self):
        path = filedialog.askopenfilename(title="Open .eml file", filetypes=[("Email files", "*.eml;*"), ("All files", "*.*")])
        if not path: return
        try:
            ph = parse_eml_file(path)
            lines = [f"{k}: {v}" for k, v in ph.headers.items()]
            self.headers_box.delete('1.0', tk.END); self.headers_box.insert(tk.END, "\n".join(lines))
        except Exception as e:
            messagebox.showerror("Open error", str(e))

    def classify_input(self):
        raw = self.headers_box.get('1.0', tk.END)
        if not raw.strip():
            messagebox.showinfo("Empty", "Paste raw headers or open a .eml first"); return
        try:
            pseudo = normalize_raw_message(raw).strip() + "\n\n"
            ph = parse_email_bytes(pseudo.encode('utf-8', errors='ignore'))
            feats = features_from_parsed(ph)

            # Heuristic
            h_score, h_reasons = heuristic_score(feats)
            h_verdict = "phishing" if h_score >= self.heur_threshold else "legit_or_unclear"
            h_vote = 1 if h_verdict == "phishing" else 0

            # Anomaly (optional)
            anom_vote = 0; anom_text = ""
            if self.anom and self.anom.model is not None:
                anom_pred = self.anom.predict_one(feats)  # 1 = anomalous (suspicious)
                anom_score = self.anom.score_one(feats)
                anom_vote = 1 if anom_pred == 1 else 0
                anom_text = f" | Anomaly: {'Suspicious' if anom_pred==1 else 'Normal'} (score={anom_score:.4f})"

            # LLM (optional, headless config)
            llm_vote = 0; llm_text = ""
            if self.use_llm.get():
                llm_res = classify_with_llm(pseudo)
                llm_verd = str(llm_res.get("verdict", "legit_or_unclear")).lower()
                llm_vote = 1 if llm_verd == "phishing" else 0
                llm_text = "\nLLM verdict: " + llm_verd.upper()
                reasons = llm_res.get("reasons", [])
                if reasons: llm_text += "\n" + "\n".join([f" • {r}" for r in reasons])

            # Final hybrid vote (2-of-3)
            votes = h_vote + anom_vote + llm_vote
            final = "PHISHING" if votes >= 2 else "LEGIT/UNCLEAR"
            self.result_var.set(
                f"Final (hybrid): {final} | Heuristic: {h_verdict.upper()} (score={h_score}){anom_text} | Votes={votes}/3"
            )

            lines = ["Heuristic flags:"] + [f" • {r}" for r in h_reasons]
            if llm_text: lines.append(llm_text)
            self.explain_box.delete('1.0', tk.END); self.explain_box.insert(tk.END, "\n".join(lines))
        except Exception as e:
            messagebox.showerror("Classification error", str(e))

    def save_model(self):
        if self.anom is None or self.anom.model is None:
            messagebox.showerror("No model", "Train the anomaly model first"); return
        path = filedialog.asksaveasfilename(defaultextension=".joblib", filetypes=[("Joblib", "*.joblib")])
        if path:
            self.anom.save(path); messagebox.showinfo("Saved", f"Model saved to {path}")

    def load_model(self):
        path = filedialog.askopenfilename(filetypes=[("Joblib", "*.joblib"), ("All files", "*.*")])
        if path:
            self.anom.load(path); messagebox.showinfo("Loaded", f"Model loaded from {path}")

if __name__ == "__main__":
    App().mainloop()
