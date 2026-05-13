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


# ============================================================
# SIEVRA - Phishing Email Detection System
# ============================================================

import streamlit as st
import torch
import re
import numpy as np
import os
import zipfile
import gdown
import pandas as pd
import uuid
import email
from bs4 import BeautifulSoup
from datetime import datetime
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# =========================
# PAGE CONFIG
# =========================
st.set_page_config(page_title="SIEVRA", page_icon="🛡️", layout="centered")

# =========================
# SESSION USER ID
# =========================
if "user_id" not in st.session_state:
    st.session_state.user_id = str(uuid.uuid4())

# =========================
# STYLE (TIDAK DIUBAH)
# =========================
st.markdown("""
<style>
.status-safe {color:#16a34a;font-weight:bold;}
.status-warn {color:#f59e0b;font-weight:bold;}
.status-danger {color:#dc2626;font-weight:bold;}
.footer {text-align:center;font-size:12px;color:gray;}

.stButton > button {
    width:100%; height:48px; border-radius:10px; font-weight:bold;
}

.block-container {padding-top:2rem;}

input, textarea {border-radius:10px !important;}
</style>
""", unsafe_allow_html=True)

# =========================
# SIDEBAR
# =========================
with st.sidebar:

    st.markdown("""
    <div style='text-align:center'>
        <div style='font-size:38px;'>🛡️</div>
        <div style='font-size:18px;font-weight:bold;'>SIEVRA</div>
        <div style='font-size:12px;color:gray;'>Email Risk Analyzer</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    lang = st.selectbox("🌐 Language", ["English", "Indonesia"])

    st.markdown("---")
    st.markdown("## 📜 History" if lang=="English" else "## 📜 Riwayat")

    if os.path.exists("logs.csv"):
        df = pd.read_csv("logs.csv")

        df["owner"] = df["user_id"].apply(
            lambda x: "You" if x == st.session_state.user_id else "Other"
        )

        st.dataframe(df.tail(10), use_container_width=True)
    else:
        st.info("No logs yet" if lang=="English" else "Belum ada riwayat")

    # DELETE ONLY OWN
    if st.button("🗑️ Clear My History" if lang=="English" else "🗑️ Hapus Riwayat Saya"):

        if os.path.exists("logs.csv"):
            df = pd.read_csv("logs.csv")

            df = df[df["user_id"] != st.session_state.user_id]

            df.to_csv("logs.csv", index=False)

            st.success("Deleted" if lang=="English" else "Berhasil dihapus")
            st.rerun()

    st.markdown("---")
    st.markdown("<div class='footer'>SIEVRA v1.0.0-beta</div>", unsafe_allow_html=True)

# =========================
# HEADER (CENTER)
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
# RULE CONFIG
# =========================
LEGIT_TLDS = {'.ac.id','.go.id','.gov','.edu','.mil'}
SUSPICIOUS_TLDS = {'.xyz','.top','.online','.site','.fun','.click','.biz','.info'}
SHORTENERS = {'bit.ly','tinyurl','t.co'}
URGENCY_KW = ['urgent','verify','segera','klik','suspended']

# =========================
# PARSE EML
# =========================
def parse_eml(file):
    msg = email.message_from_bytes(file.read())
    text = ""
    links = []

    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            text += part.get_payload(decode=True).decode(errors="ignore")

        if part.get_content_type() == "text/html":
            html = part.get_payload(decode=True).decode(errors="ignore")
            soup = BeautifulSoup(html, "html.parser")

            text += soup.get_text()

            for a in soup.find_all("a", href=True):
                links.append(a['href'])

    return text, links

# =========================
# RULE BASED
# =========================
def rule_based(text, sender, links):
    score = 0
    reasons = []

    domain = sender.split("@")[-1]

    # TLD check
    if any(domain.endswith(t) for t in SUSPICIOUS_TLDS):
        score += 40
        reasons.append("Suspicious TLD")

    # mismatch
    for l in links:
        if domain not in l:
            score += 30
            reasons.append("Domain mismatch")
            break

    # urgency
    if any(k in text.lower() for k in URGENCY_KW):
        score += 20
        reasons.append("Urgency language")

    # many links
    if len(links) > 2:
        score += 20
        reasons.append("Many links")

    return score, reasons

# =========================
# HYBRID
# =========================
def hybrid(text, sender, links):
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True).to(device)

    with torch.no_grad():
        probs = torch.softmax(model(**inputs).logits, dim=1)[0]

    ai = float(probs[1])
    rule, reasons = rule_based(text, sender, links)

    final = (0.7 * ai) + (0.3 * (rule/100))
    return final, reasons

# =========================
# INPUT (DENGAN HINT)
# =========================

col1, col2 = st.columns([10,1])
with col1:
    sender = st.text_input("📧 Sender Email")
with col2:
    st.markdown("<span title='Paste sender email here' style='color:gray;'>❔</span>", unsafe_allow_html=True)

col1, col2 = st.columns([10,1])
with col1:
    text = st.text_area("📝 Email Content", height=180)
with col2:
    st.markdown("<span title='Paste full email content here' style='color:gray;'>❔</span>", unsafe_allow_html=True)

col1, col2 = st.columns([10,1])
with col1:
    file = st.file_uploader("📎 Upload File (.eml supported)")
with col2:
    st.markdown("<span title='Upload .eml file to extract hidden links' style='color:gray;'>❔</span>", unsafe_allow_html=True)

analyze = st.button("🚀 Analyze Email", use_container_width=True)

# =========================
# PROCESS
# =========================
if analyze:

    links = []

    if file and file.name.endswith(".eml"):
        parsed_text, links = parse_eml(file)
        text += " " + parsed_text

    links += re.findall(r'http\S+', text)

    score, reasons = hybrid(text, sender, links)

    if score < 0.3:
        status = "SAFE"
        css = "status-safe"
    elif score < 0.6:
        status = "SUSPICIOUS"
        css = "status-warn"
    else:
        status = "PHISHING"
        css = "status-danger"

    st.markdown("## 🔍 Result")
    st.markdown(f"<p class='{css}'>{status}</p>", unsafe_allow_html=True)
    st.write(f"Score: {score*100:.2f}%")

    for r in reasons:
        st.write(f"- {r}")

    # LOG
    new = pd.DataFrame([{
        "user_id": st.session_state.user_id,
        "time": datetime.now(),
        "sender": sender,
        "body": text,
        "risk_score": round(score,4),
        "status": status
    }])

    if os.path.exists("logs.csv"):
        old = pd.read_csv("logs.csv")
        new = pd.concat([old,new])

    new.to_csv("logs.csv", index=False)


# =========================
# FOOTER (UNCHANGED)
# =========================
st.markdown("---")
st.markdown("<div class='footer'>Copyright © 2026 Vicky Chandra. Some Rights Reserved.</div>", unsafe_allow_html=True)
