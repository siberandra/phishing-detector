import streamlit as st
import torch
import re
import numpy as np
import os
import zipfile
import gdown
import pandas as pd
from datetime import datetime
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# PDF
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(
    page_title="SIEVRA - Phishing Detector",
    page_icon="🔐",
    layout="centered"
)

# =========================
# HEADER (BRANDING)
# =========================
st.markdown("""
<h1 style='text-align:center;'>🔐 SIEVRA</h1>
<h4 style='text-align:center; color:gray;'>
Smart Intelligent Email Verification & Risk Analyzer
</h4>
""", unsafe_allow_html=True)

st.markdown("---")

st.markdown("""
<div style='text-align:center; color:gray'>
AI-powered phishing detection system using Hybrid Model (IndoBERT + Rule-Based)
</div>
""", unsafe_allow_html=True)

# =========================
# MODEL CONFIG
# =========================
MODEL_DIR = "phishing_hybrid_model"
ZIP_FILE = "phishing_model.zip"
FILE_ID = "1DcNpMhCbdIuoyg6VjQCrTpLGiuI4yI2w"
GDRIVE_URL = f"https://drive.google.com/uc?id={FILE_ID}"

# =========================
# DOWNLOAD MODEL
# =========================
if not os.path.exists(MODEL_DIR):
    st.info("Downloading model...")
    if not os.path.exists(ZIP_FILE):
        gdown.download(GDRIVE_URL, ZIP_FILE, quiet=False)

    with zipfile.ZipFile(ZIP_FILE, 'r') as zip_ref:
        zip_ref.extractall(".")

# =========================
# LOAD MODEL
# =========================
@st.cache_resource
def load_model():
    path = f"{MODEL_DIR}/indobert"
    model = AutoModelForSequenceClassification.from_pretrained(path)
    tokenizer = AutoTokenizer.from_pretrained(path)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)
    model.eval()

    return model, tokenizer, device

model, tokenizer, device = load_model()

# =========================
# RULE CONFIG
# =========================
trusted_domains = ['.gov','.mil','edu','.go.id','.ac.id','.ac.uk','.sch','.ponpes.id']
danger_ext = ['.exe','.bat','.apk','.js','.scr']
shorteners = ['bit.ly','tinyurl','t.co']

# =========================
# HELPER
# =========================
def count_links(text):
    return len(re.findall(r'http\S+|www\S+', text))

def urgency_score(text):
    keywords = ["urgent","segera","gratis","hadiah","promo","klik sekarang"]
    return sum(1 for k in keywords if k in text.lower())

def typo_score(text):
    return int(bool(re.search(r'[a-z]+[0-9]+[a-z]+', text)))

# =========================
# FILE CHECK
# =========================
def check_file(filename):
    filename = filename.lower()
    score = 0
    reasons = []

    if any(filename.endswith(ext) for ext in danger_ext):
        score += 50
        reasons.append("Dangerous extension")

    if re.search(r'\.(pdf|docx|jpg)\.(exe|bat|js)', filename):
        score += 50
        reasons.append("Double extension")

    if len(filename.split(".")) > 2:
        score += 20
        reasons.append("Multi extension")

    return score, reasons

# =========================
# RULE BASED
# =========================
def rule_based(text, sender, file=None):
    score = 0
    reasons = []

    t = text.lower()
    s = sender.lower()

    if any(d in s for d in trusted_domains):
        score -= 50
        reasons.append("Trusted domain")

    if ('gmail' in s or 'yahoo' in s) and any(k in t for k in ['bank','shopee']):
        score += 40
        reasons.append("Impersonation")

    if any(u in t for u in shorteners):
        score += 30
        reasons.append("Short URL")

    if re.search(r'\d+\.\d+\.\d+\.\d+', t):
        score += 40
        reasons.append("IP URL")

    if count_links(text) > 2:
        score += 20
        reasons.append("Many links")

    if urgency_score(text):
        score += 20
        reasons.append("Urgency language")

    if typo_score(text):
        score += 20
        reasons.append("Typo pattern")

    if file:
        fscore, freason = check_file(file.name)
        score += fscore
        reasons += freason

    return score, reasons

# =========================
# HYBRID
# =========================
def hybrid(text, sender, file=None):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512)
    inputs = {k:v.to(device) for k,v in inputs.items()}

    with torch.no_grad():
        out = model(**inputs)
        probs = torch.softmax(out.logits, dim=1).cpu().numpy()[0]

    ai = probs[1]
    rule, reasons = rule_based(text, sender, file)

    final = (ai*0.7) + ((rule/100)*0.3)
    return final, reasons

# =========================
# LOGGING
# =========================
def log_data(sender, text, score, status):
    file = "logs.csv"
    data = pd.DataFrame([{
        "time": datetime.now(),
        "sender": sender,
        "score": score,
        "status": status
    }])

    if os.path.exists(file):
        old = pd.read_csv(file)
        data = pd.concat([old, data])

    data.to_csv(file, index=False)

# =========================
# PDF
# =========================
def make_pdf(sender, text, score, status, reasons):
    path = "report.pdf"
    doc = SimpleDocTemplate(path)
    style = getSampleStyleSheet()

    content = []
    content.append(Paragraph("Phishing Detection Report", style["Title"]))
    content.append(Spacer(1,10))
    content.append(Paragraph(f"Sender: {sender}", style["Normal"]))
    content.append(Paragraph(f"Status: {status}", style["Normal"]))
    content.append(Paragraph(f"Score: {score}", style["Normal"]))
    content.append(Spacer(1,10))

    for r in reasons:
        content.append(Paragraph(f"- {r}", style["Normal"]))

    doc.build(content)
    return path

# =========================
# UI
# =========================
st.title("🔐 Phishing Detector")

sender = st.text_input("Sender Email")
text = st.text_area("Email Content")
file = st.file_uploader("Upload File")

if st.button("Analyze"):

    score, reasons = hybrid(text, sender, file)

    if score < 0.3:
        status = "SAFE"
    elif score < 0.6:
        status = "SUSPICIOUS"
    else:
        status = "PHISHING"

    st.write("Status:", status)
    st.write("Score:", round(score,3))
    st.progress(min(score,1.0))

    st.write("Reasons:")
    for r in reasons:
        st.write("-", r)

    # LOG
    log_data(sender, text, score, status)

    # PDF
    pdf = make_pdf(sender, text, score, status, reasons)
    with open(pdf, "rb") as f:
        st.download_button("Download PDF", f, file_name="report.pdf")

# FOOTER
st.markdown("---")
st.markdown("© 2026 Vicky Chandra • Thesis Research • Universitas Gunadarma")
