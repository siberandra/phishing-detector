import streamlit as st
import torch
import re
import numpy as np
import os
import zipfile
import gdown
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# =========================
# CONFIG
# =========================
MODEL_DIR = "phishing_hybrid_model"
ZIP_FILE = "phishing_model.zip"
FILE_ID = "1DcNpMhCbdIuoyg6VjQCrTpLGiuI4yI2w"

GDRIVE_URL = f"https://drive.google.com/uc?id={FILE_ID}"

# =========================
# DOWNLOAD & EXTRACT MODEL
# =========================
if not os.path.exists(MODEL_DIR):

    st.info("🔄 Downloading model... (first run agak lama ya)")

    if not os.path.exists(ZIP_FILE):
        gdown.download(GDRIVE_URL, ZIP_FILE, quiet=False)

    st.info("📦 Extracting model...")

    with zipfile.ZipFile(ZIP_FILE, 'r') as zip_ref:
        zip_ref.extractall(".")

    st.success("✅ Model siap!")

# =========================
# LOAD MODEL (CACHE)
# =========================
@st.cache_resource
def load_model():
    model_path = f"{MODEL_DIR}/indobert"

    model = AutoModelForSequenceClassification.from_pretrained(model_path)
    tokenizer = AutoTokenizer.from_pretrained(model_path)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)
    model.eval()

    return model, tokenizer, device

model, tokenizer, device = load_model()

# =========================
# RULE CONFIG
# =========================
trusted_domains = [
    '.gov','.mil','edu','.go.id','.ac.id','.ac.uk','.sch','.ponpes.id'
]

danger_ext = ['.exe','.bat','.apk','.js','.scr']
shorteners = ['bit.ly','tinyurl','t.co']

# =========================
# HELPER FUNCTIONS
# =========================
def count_links(text):
    return len(re.findall(r'http\S+|www\S+', text))

def urgency_score(text):
    keywords = ["urgent","segera","gratis","hadiah","promo","klik sekarang","diskon","limited"]
    return sum(1 for k in keywords if k in text.lower())

def has_danger_file(text):
    return int(any(ext in text.lower() for ext in ['.exe','.zip','.rar','.apk','.bat']))

def typo_score(text):
    score = 0
    if re.search(r'[a-z]+[0-9]+[a-z]+', text): score += 1
    if re.search(r'(.)\1{2,}', text): score += 1
    return score

# =========================
# FILE CHECK
# =========================
def check_file_security(filename):
    filename = filename.lower()
    score = 0
    reasons = []

    if any(filename.endswith(ext) for ext in danger_ext):
        score += 50
        reasons.append("Ekstensi berbahaya")

    if re.search(r'\.(pdf|docx|jpg)\.(exe|bat|js)', filename):
        score += 50
        reasons.append("Double extension")

    return score, reasons

# =========================
# RULE BASED
# =========================
def rule_based_check(text, sender, uploaded_file=None):
    score = 0
    reasons = []

    t = text.lower()
    s = sender.lower()

    # Sender
    if any(d in s for d in trusted_domains):
        score -= 50
        reasons.append("Trusted domain")

    if ('gmail' in s or 'yahoo' in s):
        if any(k in t for k in ['bank','shopee','pajak']):
            score += 40
            reasons.append("Impersonation")

    # URL
    if any(u in t for u in shorteners):
        score += 30
        reasons.append("Short URL")

    if re.search(r'\d+\.\d+\.\d+\.\d+', t):
        score += 40
        reasons.append("IP URL")

    if count_links(text) > 2:
        score += 20
        reasons.append("Banyak link")

    # Content
    if urgency_score(text) > 0:
        score += 20
        reasons.append("Bahasa urgensi/promo")

    if has_danger_file(text):
        score += 30
        reasons.append("File mention berbahaya")

    if typo_score(text) > 0:
        score += 20
        reasons.append("Typo mencurigakan")

    # File upload
    if uploaded_file:
        f_score, f_reason = check_file_security(uploaded_file.name)
        score += f_score
        reasons += f_reason

    return score, reasons

# =========================
# HYBRID
# =========================
def hybrid_prediction(text, sender, uploaded_file=None):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True, max_length=512)
    inputs = {k: v.to(device) for k,v in inputs.items()}

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=1).cpu().numpy()[0]

    ai_score = probs[1]

    rule_score, reasons = rule_based_check(text, sender, uploaded_file)

    final_score = (ai_score * 0.7) + ((rule_score/100) * 0.3)

    return final_score, reasons

# =========================
# UI
# =========================
st.title("🔐 Phishing Email Detector (Hybrid AI + Rule-Based)")

sender = st.text_input("Sender Email")
text = st.text_area("Isi Email")

uploaded_file = st.file_uploader("Upload File (Opsional)")

if st.button("Analisis"):
    score, reasons = hybrid_prediction(text, sender, uploaded_file)

    if score < 0.3:
        status = "AMAN"
        color = "green"
    elif score < 0.6:
        status = "MENCURIGAKAN"
        color = "orange"
    else:
        status = "PHISHING"
        color = "red"

    st.markdown(f"### Status: :{color}[{status}]")
    st.write("Score:", round(score,3))

    st.write("Alasan:")
    for r in reasons:
        st.write("-", r)