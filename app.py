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


# =========================
# IMPORT
# =========================
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
import uuid
import email
from bs4 import BeautifulSoup

# =========================
# SESSION USER ID
# =========================
if "user_id" not in st.session_state:
    st.session_state.user_id = str(uuid.uuid4())

# =========================
# PAGE CONFIG (UNCHANGED)
# =========================
st.set_page_config(
    page_title="SIEVRA",
    page_icon="🛡️",
    layout="centered"
)

# =========================
# STYLE (UNCHANGED)
# =========================
st.markdown("""<style>
.status-safe {color:#16a34a;font-weight:bold;}
.status-warn {color:#f59e0b;font-weight:bold;}
.status-danger {color:#dc2626;font-weight:bold;}
.footer {text-align:center;font-size:12px;color:gray;}
.stButton > button {width:100%;height:48px;border-radius:10px;font-weight:bold;}
.block-container {padding-top:2rem;}
input, textarea {border-radius:10px !important;}
</style>""", unsafe_allow_html=True)

# =========================
# LANGUAGE
# =========================
lang = st.sidebar.selectbox("🌐 Language", ["English", "Indonesia"])

def t(k):
    data = {
        "English": {
            "history": "📜 History",
            "clear": "🗑️ Clear My History",
            "sender_hint": "Paste sender email here",
            "content_hint": "Paste full email content here",
            "upload_hint": "Upload file from email (.eml supported)",
        },
        "Indonesia": {
            "history": "📜 Riwayat",
            "clear": "🗑️ Hapus Riwayat Saya",
            "sender_hint": "Salin email pengirim ke sini",
            "content_hint": "Salin semua isi email di sini",
            "upload_hint": "Upload file dari email (.eml didukung)",
        }
    }
    return data[lang][k]

# =========================
# SIDEBAR HISTORY (FIXED USER ONLY)
# =========================
st.sidebar.markdown("---")
st.sidebar.markdown(f"## {t('history')}")

if os.path.exists("logs.csv"):
    df = pd.read_csv("logs.csv")

    df_user = df[df["user_id"] == st.session_state.user_id]

    if not df_user.empty:
        st.sidebar.dataframe(df_user.tail(10))
    else:
        st.sidebar.info("No history" if lang=="English" else "Belum ada riwayat")

# CLEAR ONLY USER DATA
if st.sidebar.button(t("clear")):
    if os.path.exists("logs.csv"):
        df = pd.read_csv("logs.csv")
        df = df[df["user_id"] != st.session_state.user_id]
        df.to_csv("logs.csv", index=False)
        st.rerun()

# =========================
# MODEL LOAD (UNCHANGED)
# =========================
MODEL_DIR = "phishing_hybrid_model"
ZIP_FILE = "phishing_model.zip"
FILE_ID = "1IJ1PoXkq_6GGT8vFvYVyQCAgnYAbVfsO"
URL = f"https://drive.google.com/uc?id={FILE_ID}"

if not os.path.exists(MODEL_DIR):
    gdown.download(URL, ZIP_FILE, quiet=False)
    with zipfile.ZipFile(ZIP_FILE, 'r') as zip_ref:
        zip_ref.extractall(".")

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
# RULE CONFIG (UPDATED)
# =========================
LEGIT_TLDS = {'.ac.id','.go.id','.co.id','.gov','.edu'}
SUSPICIOUS_TLDS = {'.xyz','.top','.online','.click','.link','.shop','.cloud'}
SHORTENERS = {'bit.ly','tinyurl.com','t.co'}
FREE_MAIL = {'gmail.com','yahoo.com','outlook.com'}

# =========================
# URL EXTRACT
# =========================
def extract_urls(text):
    return re.findall(r'https?://[^\s]+', text)

# =========================
# EML PARSER
# =========================
def parse_eml(file):
    raw = file.read()
    msg = email.message_from_bytes(raw)

    text = ""
    links = []

    for part in msg.walk():
        content_type = part.get_content_type()

        if content_type == "text/plain":
            text += part.get_payload(decode=True).decode(errors="ignore")

        if content_type == "text/html":
            html = part.get_payload(decode=True).decode(errors="ignore")
            soup = BeautifulSoup(html, "html.parser")

            text += soup.get_text()

            for a in soup.find_all("a", href=True):
                links.append(a["href"])

    return text, links

# =========================
# RULE BASED (UPGRADED)
# =========================
def rule_based(text, sender, links):
    score = 0
    reasons = []

    sender_domain = sender.split("@")[-1]

    # TLD check
    if any(sender_domain.endswith(t) for t in LEGIT_TLDS):
        score -= 20
    if any(sender_domain.endswith(t) for t in SUSPICIOUS_TLDS):
        score += 30
        reasons.append("Suspicious TLD")

    # URL checks
    for url in links:
        if any(s in url for s in SHORTENERS):
            score += 30
            reasons.append("Shortened URL")

        if sender_domain not in url:
            score += 25
            reasons.append("Domain mismatch")

    # FREE MAIL impersonation
    if sender_domain in FREE_MAIL and any(k in text.lower() for k in ['bank','akun']):
        score += 30
        reasons.append("Impersonation")

    return score, reasons

# =========================
# HYBRID (FIXED)
# =========================
def hybrid(text, sender, links):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True).to(device)

    with torch.no_grad():
        logits = model(**inputs).logits
        probs = torch.softmax(logits, dim=1).cpu().numpy()[0]

    ai_score = float(probs[1])
    rule_score, reasons = rule_based(text, sender, links)

    final = (ai_score * 0.8) + ((rule_score / 100) * 0.2)

    return final, reasons

# =========================
# UI (UNCHANGED + HINT)
# =========================
st.title("🛡️ SIEVRA")

with st.expander("💡 Hint - Sender"):
    st.write(t("sender_hint"))

sender = st.text_input("📧 Email Pengirim")

with st.expander("💡 Hint - Content"):
    st.write(t("content_hint"))

text = st.text_area("📝 Isi Email")

with st.expander("💡 Hint - Upload"):
    st.write(t("upload_hint"))

file = st.file_uploader("📎 Upload File")

# =========================
# ANALYZE
# =========================
if st.button("🚀 Analyze"):

    links = extract_urls(text)

    # HANDLE EML
    if file and file.name.endswith(".eml"):
        eml_text, eml_links = parse_eml(file)
        text += eml_text
        links += eml_links

    score, reasons = hybrid(text, sender, links)

    status = "AMAN" if score < 0.3 else "MENCURIGAKAN" if score < 0.6 else "PHISHING"

    st.write("Score:", round(score,3))
    st.write("Status:", status)

    for r in reasons:
        st.write("-", r)

    # SAVE LOG (USER ONLY)
    new = pd.DataFrame([{
        "user_id": st.session_state.user_id,
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
# FOOTER (UNCHANGED)
# =========================
st.markdown("---")
st.markdown("<div class='footer'>Copyright © 2026 Vicky Chandra. Some Rights Reserved.</div>", unsafe_allow_html=True)
