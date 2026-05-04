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

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(
    page_title="SIEVRA",
    page_icon="🛡️",
    layout="centered"
)

# =========================
# CUSTOM STYLE
# =========================
st.markdown("""
<style>
# .main-card {
#     padding: 25px;
#     border-radius: 15px;
#     background: #f9fafb;
#     box-shadow: 0px 4px 10px rgba(0,0,0,0.05);
# }

.status-safe {
    color: #16a34a;
    font-weight: bold;
}

.status-warn {
    color: #f59e0b;
    font-weight: bold;
}

.status-danger {
    color: #dc2626;
    font-weight: bold;
}

.footer {
    text-align: center;
    font-size: 12px;
    color: gray;
}

/* BUTTON */
.stButton > button {
    width: 100%;
    height: 48px;
    border-radius: 10px;
    font-weight: bold;
}

/* SPACING */
.block-container {
    padding-top: 2rem;
}

/* Card hover effect */
.main-card:hover {
    box-shadow: 0px 8px 20px rgba(0,0,0,0.1);
    transition: 0.3s;
}

/* Input style */
input, textarea {
    border-radius: 10px !important;
}

/* Progress bar smoother */
div[data-testid="stProgressBar"] > div > div {
    border-radius: 10px;
}

/* kasih jarak antar section */
section.main > div {
    padding-bottom: 10px;
}

</style>
""", unsafe_allow_html=True)

# =========================
# HEADER
# =========================
with st.sidebar:

    st.markdown("""
    <div style='text-align:center; margin-top:10px; margin-bottom:10px;'>
        <div style='font-size:40px;'>🛡️</div>
        <div style='font-size:22px; font-weight:bold;'>SIEVRA</div>
        <div style='font-size:20px; color:gray;'>Smart Email Verification & Risk Analyzer</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    lang = st.selectbox("🌐 Language", ["English", "Indonesia"])

    st.markdown("---")
    st.markdown("## 📜 History")

    if os.path.exists("logs.csv"):
        df = pd.read_csv("logs.csv")
        st.dataframe(df.tail(10), use_container_width=True)

        with open("logs.csv", "rb") as f:
            st.download_button("⬇️ Download Logs", f, "logs.csv")
    else:
        st.info("No logs yet" if lang=="English" else "Belum ada riwayat")

    # =========================
    # CLEAR LOGS
    # =========================    
    if st.button("🗑️ Clear History" if lang=="English" else "🗑️ Hapus Riwayat"):
        
        if os.path.exists("logs.csv"):
            os.remove("logs.csv")
            st.success("Logs cleared successfully" if lang=="English" else "Riwayat berhasil dihapus")
            st.rerun()
        else:
            st.info("No logs to delete" if lang=="English" else "Tidak ada riwayat untuk dihapus")

st.markdown("""
<div style='text-align:center'>
    <h1>🛡️ SIEVRA</h1>
    <p style='color:gray'>Smart Email Verification & Risk Analyzer</p>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# =========================
# MODEL CONFIG
# =========================
MODEL_DIR = "phishing_hybrid_model"
ZIP_FILE = "phishing_model.zip"
FILE_ID = "1DcNpMhCbdIuoyg6VjQCrTpLGiuI4yI2w"
GDRIVE_URL = f"https://drive.google.com/uc?id={FILE_ID}"

if not os.path.exists(MODEL_DIR):
    st.info("🔄 Downloading model...")
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

def check_file(filename):
    filename = filename.lower()
    score = 0
    reasons = []

    is_double = bool(re.search(r'\.(pdf|docx|jpg)\.(exe|bat|js)', filename))
    is_multi = len(filename.split(".")) > 2

    if any(filename.endswith(ext) for ext in danger_ext):
        score += 50

    if is_double:
        score += 50
        reasons.append("Double extension (file disguise attack)")

    elif is_multi:
        score += 20
        reasons.append("Suspicious multi-extension file")

    return score, reasons

# =========================
# RULE
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
        
    # FILE ONLY ATTACK
    if file and not text.strip():
        if any(file.name.lower().endswith(ext) for ext in danger_ext):
            score += 40
            reasons.append("File-only message with dangerous attachment")

    # =========================
    # SUSPICIOUS DOMAIN PATTERN (NEW)
    # =========================
    domain = s.split("@")[-1]
    
    # Banyak tanda strip (-) di domain
    if domain.count("-") >= 1:
        score += 15
        reasons.append("Suspicious domain pattern (hyphen usage)")
    
    # Domain terlalu panjang (indikasi fake domain)
    if len(domain) > 20:
        score += 15
        reasons.append("Unusually long domain name") 

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

    ai = float(probs[1])
    rule, reasons = rule_based(text, sender, file)

    final = (ai*0.7) + ((rule/100)*0.3)
    return float(final), reasons

# =========================
# LOG
# =========================
def extract_urls(text):
    return re.findall(r'http\S+|www\S+', text)

def log_data(sender, text, file, score, status):
    file_path = "logs.csv"

    urls = extract_urls(text)
    url_str = ", ".join(urls) if urls else "-"

    file_ext = "-"
    if file:
        file_ext = file.name.split(".")[-1]

    new = pd.DataFrame([{
        "time": datetime.now(),
        "sender": sender,
        "body": text,
        "url": url_str,
        "file_ext": file_ext,
        "risk_score": round(score, 4),
        "status": status
    }])

    if os.path.exists(file_path):
        old = pd.read_csv(file_path)
        new = pd.concat([old, new])

    new.to_csv(file_path, index=False)

# # =========================
# # PDF
# # =========================
# def make_pdf(sender, score, status, reasons):
#     path = "report.pdf"
#     doc = SimpleDocTemplate(path)
#     style = getSampleStyleSheet()

#     content = []
#     content.append(Paragraph("SIEVRA Report", style["Title"]))
#     content.append(Spacer(1,10))
#     content.append(Paragraph(f"Sender: {sender}", style["Normal"]))
#     content.append(Paragraph(f"Status: {status}", style["Normal"]))
#     content.append(Paragraph(f"Score: {round(score,3)}", style["Normal"]))
#     content.append(Spacer(1,10))

#     for r in reasons:
#         content.append(Paragraph(f"- {r}", style["Normal"]))

#     doc.build(content)
#     return path

# =========================
# UI CARD
# =========================

def t(key):
    translations = {
        "English": {
            "sender": "📧 Sender Email",
            "content": "📝 Email Content",
            "upload": "📎 Upload File (optional)",
            "analyze": "🚀 Analyze Email",
            "result": "## 🔍 Analysis Result",
            "reasons": "### 📌 Detection Reasons",
            "score": "⚠️ Phishing Risk Score",
            "safe": "SAFE",
            "suspicious": "SUSPICIOUS",
            "phishing": "PHISHING",
            "no_reason": "No strong suspicious indicators detected"
        },
        "Indonesia": {
            "sender": "📧 Email Pengirim",
            "content": "📝 Isi Email",
            "upload": "📎 Upload File (opsional)",
            "analyze": "🚀 Analisis Email",
            "result": "## 🔍 Hasil Analisis",
            "reasons": "### 📌 Alasan Deteksi",
            "score": "⚠️ Skor Risiko Phishing",
            "safe": "AMAN",
            "suspicious": "MENCURIGAKAN",
            "phishing": "PHISHING",
            "no_reason": "Tidak ditemukan indikasi mencurigakan"
        }
    }
    return translations[lang][key]

st.markdown("<div class='main-card'>", unsafe_allow_html=True)

sender = st.text_input(
    t("sender") + " *",
    placeholder="example@company.com" if lang=="English" else "contoh@email.com"
)

# =========================
# REAL-TIME VALIDATION
# =========================
email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
email_valid = bool(re.match(email_pattern, sender)) if sender else False

if not sender:
    st.markdown(
        f"<p style='color:#f59e0b; font-size:13px; margin-top:-10px; font-style:italic;'>"
        + ("Sender email is required"
           if lang=="English"
           else "Email pengirim wajib diisi")
        + "</p>",
        unsafe_allow_html=True
    )

elif sender and not email_valid:
    st.markdown(
        f"<p style='color:#f59e0b; font-size:13px; margin-top:-10px; font-style:italic;'>"
        + ("Please enter a valid email format (e.g. example@domain.com)"
           if lang=="English"
           else "Format email tidak valid (contoh: nama@email.com)")
        + "</p>",
        unsafe_allow_html=True
    )

text = st.text_area(
    t("content"),
    height=180,
    placeholder="e.g. Your account will be suspended..." 
    if lang=="English" 
    else "contoh: akun Anda akan diblokir, klik link berikut..."
)

file = st.file_uploader(t("upload"))
analyze = st.button(t("analyze"), use_container_width=True)

st.markdown("</div>", unsafe_allow_html=True)

if analyze:

    email_valid = re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", sender)
    
    if not sender:
        st.warning("Sender email is required" if lang=="English" else "Email pengirim wajib diisi")
        st.stop()
    
    if not email_valid:
        st.warning("Invalid email format" if lang=="English" else "Format email tidak valid")
        st.stop()
    
    score, reasons = hybrid(text, sender, file)
    score = max(0.0, min(float(score), 1.0))

    # ======================
    # CONTEXTUAL REASON FIX
    # ======================
    if score < 0.3:
        if not reasons:
            reasons = [
                "No suspicious patterns detected",
                "No malicious links or attachments found",
                "Sender appears normal"
            ] if lang=="English" else [
                "Tidak ditemukan pola mencurigakan",
                "Tidak ada link atau file berbahaya",
                "Pengirim terlihat normal"
            ]
        else:
            reasons.insert(0, "Low risk detected" if lang=="English" else "Risiko rendah terdeteksi")
    
    elif score < 0.6:
        reasons.insert(0, "Some suspicious indicators detected" if lang=="English" else "Beberapa indikasi mencurigakan ditemukan")
    
    else:
        reasons.insert(0, "High risk phishing indicators detected" if lang=="English" else "Indikasi phishing berisiko tinggi terdeteksi")

    # STATUS
    if score < 0.3:
        status = t("safe")
        css = "status-safe"
    elif score < 0.6:
        status = t("suspicious")
        css = "status-warn"
    else:
        status = t("phishing")
        css = "status-danger"

    # ======================
    # RESULT HEADER
    # ======================
    def translate_reason(r):
        if lang == "English":
            return r
    
        mapping = {
            "Trusted domain": "Domain terpercaya",
            "Impersonation": "Indikasi penyamaran",
            "Short URL": "URL pendek mencurigakan",
            "IP URL": "Link menggunakan IP",
            "Many links": "Terlalu banyak link",
            "Urgency language": "Bahasa mendesak / promosi",
            "Typo pattern": "Pola typo mencurigakan",
            "Suspicious domain pattern (hyphen usage)": "Domain mencurigakan (mengandung tanda -)",
            "Unusually long domain name": "Nama domain terlalu panjang",
            "Double extension (file disguise attack)": "Ekstensi ganda (penyamaran file)",
            "Suspicious multi-extension file": "File dengan banyak ekstensi mencurigakan",
            "File-only message with dangerous attachment": "Pesan hanya berisi file berbahaya"
        }
    
        return mapping.get(r, r)

    
    st.markdown(t("result"))
    st.markdown(f"<p class='{css}'>Status: {status}</p>", unsafe_allow_html=True)
    
    st.write(f"{t('score')}: {score*100:.1f}%")
    
    st.markdown(t("reasons"))

    if reasons:
        for r in reasons:
            st.write(f"• {translate_reason(r)}")
    else:
        st.write("No strong suspicious indicators detected")

    # LOG
    log_data(sender, text, file, score, status)

# =========================
# FOOTER
# =========================
st.markdown("---")
st.markdown("<div class='footer'>© 2026 Vicky Chandra • Undergraduate Thesis • Universitas Gunadarma</div>", unsafe_allow_html=True)
