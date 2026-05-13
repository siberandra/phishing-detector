# ============================================================
# Phishing Email Detection System
# Copyright (C) 2026 Vicky Chandra
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Contact: vickyc.job@gmail.com
# ============================================================


# ============================================================
# SIEVRA - FINAL STREAMLIT (IMPROVED)
# ============================================================

import streamlit as st
import torch
import re
import os
import zipfile
import gdown
import pandas as pd
from datetime import datetime
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(page_title="SIEVRA", page_icon="🛡️", layout="centered")

# =========================
# LANGUAGE SYSTEM
# =========================
lang = st.session_state.get("lang", "English")

def t(key):
    data = {
        "English": {
            "lang": "🌐 Language",
            "history": "📜 History",
            "no_logs": "No logs yet",
            "clear": "🗑️ Clear My History",
            "cleared": "Your history cleared",
            "sender": "📧 Sender Email",
            "content": "📝 Email Content",
            "upload": "📎 Upload File (optional)",
            "analyze": "🚀 Analyze Email",
            "required": "Sender email is required",
            "invalid": "Invalid email format",
            "result": "## 🔍 Analysis Result",
            "score": "⚠️ Phishing Risk Score",
            "safe": "SAFE",
            "suspicious": "SUSPICIOUS",
            "phishing": "PHISHING",
            "hint_sender": "Copy sender email here",
            "hint_content": "Copy entire email content here",
            "hint_file": "Upload attachment or .eml email file. Do NOT execute file."
        },
        "Indonesia": {
            "lang": "🌐 Bahasa",
            "history": "📜 Riwayat",
            "no_logs": "Belum ada riwayat",
            "clear": "🗑️ Hapus Riwayat Saya",
            "cleared": "Riwayat anda dihapus",
            "sender": "📧 Email Pengirim",
            "content": "📝 Isi Email",
            "upload": "📎 Upload File (opsional)",
            "analyze": "🚀 Analisis Email",
            "required": "Email pengirim wajib diisi",
            "invalid": "Format email tidak valid",
            "result": "## 🔍 Hasil Analisis",
            "score": "⚠️ Skor Risiko",
            "safe": "AMAN",
            "suspicious": "MENCURIGAKAN",
            "phishing": "PHISHING",
            "hint_sender": "Salin email pengirim ke sini",
            "hint_content": "Salin seluruh isi email ke sini",
            "hint_file": "Upload file dari email atau .eml. Jangan dibuka / dijalankan."
        }
    }
    return data[lang][key]

# =========================
# SIDEBAR
# =========================
with st.sidebar:

    lang = st.selectbox("🌐 Language / Bahasa", ["English","Indonesia"])
    st.session_state["lang"] = lang

    st.markdown("---")
    st.markdown(f"## {t('history')}")

    if os.path.exists("logs.csv"):
        df = pd.read_csv("logs.csv")
        st.dataframe(df.tail(10), use_container_width=True)
    else:
        st.info(t("no_logs"))

    sender_filter = st.text_input("Your Email (for delete)")

    if st.button(t("clear")):
        if os.path.exists("logs.csv") and sender_filter:
            df = pd.read_csv("logs.csv")
            df = df[df["sender"] != sender_filter]
            df.to_csv("logs.csv", index=False)
            st.success(t("cleared"))
            st.rerun()
            
    st.markdown("---")
    st.markdown(
        "<div class='footer'>SIEVRA v1.0.0-beta</div>",
        unsafe_allow_html=True
    )

# =========================
# HEADER
# =========================
st.markdown("""
<div style='text-align:center'>
<h1>🛡️ SIEVRA</h1>
<p style='color:gray'>Smart Email Verification & Risk Analyzer</p>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# =========================
# MODEL LOAD
# =========================
MODEL_DIR = "phishing_hybrid_model"
FILE_ID = "1IJ1PoXkq_6GGT8vFvYVyQCAgnYAbVfsO"
ZIP_FILE = "model.zip"

if not os.path.exists(MODEL_DIR):
    gdown.download(f"https://drive.google.com/uc?id={FILE_ID}", ZIP_FILE)
    with zipfile.ZipFile(ZIP_FILE, 'r') as z:
        z.extractall(".")

@st.cache_resource
def load_model():
    model = AutoModelForSequenceClassification.from_pretrained(f"{MODEL_DIR}/indobert")
    tokenizer = AutoTokenizer.from_pretrained(f"{MODEL_DIR}/indobert")
    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)
    model.eval()
    return model, tokenizer, device

model, tokenizer, device = load_model()

# =========================
# RULE CONFIG
# =========================
LEGIT_TLDS = {'.ac.id','.go.id','.co.id','.gov','.edu'}
SUSPICIOUS_TLDS = {'.xyz','.top','.online','.site','.cloud','.ru','.cn','.tk'}
SHORTENERS = {'bit.ly','tinyurl.com','t.co'}
DANGEROUS_EXTENSIONS = {'.exe','.bat','.apk','.js','.scr'}

# =========================
# EML PARSER
# =========================
def parse_eml(file):
    msg = BytesParser(policy=policy.default).parse(file)
    text = msg.get_body(preferencelist=('plain','html')).get_content()
    soup = BeautifulSoup(text, "html.parser")

    links = []
    for a in soup.find_all("a", href=True):
        links.append(a["href"])
    for img in soup.find_all("img", src=True):
        links.append(img["src"])

    return text, links

# =========================
# RULE BASED
# =========================
def rule_based(text, sender, urls):
    score = 0
    reasons = []

    sender_domain = sender.split("@")[-1]

    # mismatch
    for u in urls:
        if sender_domain not in u:
            score += 40
            reasons.append("Domain mismatch")

    # suspicious tld
    for tld in SUSPICIOUS_TLDS:
        if sender_domain.endswith(tld):
            score += 30
            reasons.append("Suspicious TLD")

    # urgency
    if any(k in text.lower() for k in ["urgent","segera","verify","klik"]):
        score += 20
        reasons.append("Urgency")

    return score, reasons

# =========================
# HYBRID
# =========================
def hybrid(text, sender, urls):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    inputs = {k:v.to(device) for k,v in inputs.items()}

    with torch.no_grad():
        logits = model(**inputs).logits
        probs = torch.softmax(logits, dim=1)[0]

    ai = float(probs[1])
    rule, reasons = rule_based(text, sender, urls)

    final = (ai * 0.7) + ((rule/100) * 0.3)
    return final, reasons

# =========================
# UI INPUT
# =========================
st.markdown("### "+t("sender"))
st.caption("💡 "+t("hint_sender"))
sender = st.text_input("")

st.markdown("### "+t("content"))
st.caption("💡 "+t("hint_content"))
text = st.text_area("", height=150)

st.markdown("### "+t("upload"))
st.caption("💡 "+t("hint_file"))
file = st.file_uploader("", accept_multiple_files=True)

# =========================
# VALIDATION
# =========================
email_valid = bool(re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", sender)) if sender else False

if not sender:
    st.warning(t("required"))
elif not email_valid:
    st.warning(t("invalid"))

# =========================
# ANALYZE
# =========================
if st.button(t("analyze")):

    urls = re.findall(r'http\S+', text)

    if file:
        for f in file:
            if f.name.endswith(".eml"):
                text_eml, urls_eml = parse_eml(f)
                text += text_eml
                urls += urls_eml

    score, reasons = hybrid(text, sender, urls)

    if score < 0.3:
        status = t("safe")
    elif score < 0.6:
        status = t("suspicious")
    else:
        status = t("phishing")

    st.markdown(t("result"))
    st.write(f"{t('score')}: {score*100:.2f}%")
    st.write("Status:", status)

    for r in reasons:
        st.write("•", r)

    # LOG
    new = pd.DataFrame([{
        "time": datetime.now(),
        "sender": sender,
        "score": score,
        "status": status
    }])

    if os.path.exists("logs.csv"):
        old = pd.read_csv("logs.csv")
        new = pd.concat([old, new])

    new.to_csv("logs.csv", index=False)

# =========================
# FOOTER
# =========================
st.markdown("---")
st.markdown(
    "<div class='footer'>Copyright © 2026 Vicky Chandra. Some Rights Reserved.</div>",
    unsafe_allow_html=True
)
