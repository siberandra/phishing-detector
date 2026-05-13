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



import os
import re
import uuid
import zipfile
import email
from datetime import datetime
from urllib.parse import urlparse

import gdown
import pandas as pd
import streamlit as st
import tldextract
import torch

from bs4 import BeautifulSoup
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification
)

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="SIEVRA",
    page_icon="🛡️",
    layout="centered"
)

# ============================================================
# SESSION
# ============================================================
if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())

# ============================================================
# CUSTOM CSS
# ============================================================
st.markdown("""
<style>

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

.stButton > button {
    width: 100%;
    height: 48px;
    border-radius: 10px;
    font-weight: bold;
}

.block-container {
    padding-top: 2rem;
}

.main-card:hover {
    box-shadow: 0px 8px 20px rgba(0,0,0,0.1);
    transition: 0.3s;
}

input, textarea {
    border-radius: 10px !important;
}

div[data-testid="stProgressBar"] > div > div {
    border-radius: 10px;
}

section.main > div {
    padding-bottom: 10px;
}

</style>
""", unsafe_allow_html=True)

# ============================================================
# TRANSLATION
# ============================================================
def t(key):

    translations = {

        "English": {

            "language": "🌐 Language",
            "history": "## 📜 History",

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

            "clear_history": "🗑️ Clear History",

            "no_logs": "No logs yet",
            "logs_deleted": "Your history has been deleted",

            "sender_required": "Sender email is required",
            "invalid_email": "Invalid email format",

            "low_risk": "Low risk detected",
            "mid_risk": "Some suspicious indicators detected",
            "high_risk": "High risk phishing indicators detected",

            "hint_sender": "Copy the sender email here",

            "hint_content": "Copy all email content here",

            "hint_upload": (
                "Please upload files received from the email. "
                "You may download the file but do not open or execute it. "
                "You can also upload the entire email as .eml file."
            )
        },

        "Indonesia": {

            "language": "🌐 Bahasa",
            "history": "## 📜 Riwayat",

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

            "clear_history": "🗑️ Hapus Riwayat",

            "no_logs": "Belum ada riwayat",
            "logs_deleted": "Riwayat Anda berhasil dihapus",

            "sender_required": "Email pengirim wajib diisi",
            "invalid_email": "Format email tidak valid",

            "low_risk": "Risiko rendah terdeteksi",
            "mid_risk": "Beberapa indikasi mencurigakan ditemukan",
            "high_risk": "Indikasi phishing berisiko tinggi terdeteksi",

            "hint_sender": "Salin email pengirim kesini",

            "hint_content": "Salin semua isi email disini",

            "hint_upload": (
                "Silahkan upload file yang anda terima dari email. "
                "Cukup download namun jangan dibuka atau dijalankan. "
                "Anda juga bisa upload email penuh dalam format .eml"
            )
        }
    }

    return translations[lang][key]

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:

    st.markdown("""
    <div style='text-align:center; margin-top:10px; margin-bottom:10px;'>
        <div style='font-size:40px; font-weight:bold'>🛡️ SIEVRA</div>
        <div style='font-size:13px; color:gray;'>
            Smart Email Verification & Risk Analyzer
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    lang = st.selectbox(
        "🌐 Language",
        ["English", "Indonesia"]
    )

    st.markdown("---")
    st.markdown(t("history"))

    if os.path.exists("logs.csv"):

        df = pd.read_csv("logs.csv")

        user_df = df[
            df["session_id"] == st.session_state.session_id
        ]

        show_cols = [
            c for c in user_df.columns
            if c != "session_id"
        ]

        st.dataframe(
            user_df[show_cols].tail(10),
            use_container_width=True
        )

    else:
        st.info(t("no_logs"))

    # ========================================================
    # CLEAR HISTORY
    # ========================================================
    if st.button(t("clear_history")):

        if os.path.exists("logs.csv"):

            df = pd.read_csv("logs.csv")

            df = df[
                df["session_id"] != st.session_state.session_id
            ]

            df.to_csv("logs.csv", index=False)

            st.success(t("logs_deleted"))

            st.rerun()

# ============================================================
# HEADER
# ============================================================
st.markdown("""
<div style='text-align:center'>
    <h1>🛡️ SIEVRA</h1>
    <p style='color:gray'>
        Smart Email Verification & Risk Analyzer
    </p>
</div>
""", unsafe_allow_html=True)

st.markdown("---")

# ============================================================
# MODEL CONFIG
# ============================================================
MODEL_DIR = "phishing_hybrid_model"
ZIP_FILE = "phishing_model.zip"

FILE_ID = "1IJ1PoXkq_6GGT8vFvYVyQCAgnYAbVfsO"

GDRIVE_URL = f"https://drive.google.com/uc?id={FILE_ID}"

if not os.path.exists(MODEL_DIR):

    st.info("🔄 Downloading model...")

    if not os.path.exists(ZIP_FILE):
        gdown.download(
            GDRIVE_URL,
            ZIP_FILE,
            quiet=False
        )

    with zipfile.ZipFile(ZIP_FILE, "r") as zip_ref:
        zip_ref.extractall(".")

# ============================================================
# LOAD MODEL
# ============================================================
@st.cache_resource
def load_model():

    path = f"{MODEL_DIR}/indobert"

    model = AutoModelForSequenceClassification.from_pretrained(path)

    tokenizer = AutoTokenizer.from_pretrained(path)

    device = (
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    model.to(device)
    model.eval()

    return model, tokenizer, device

model, tokenizer, device = load_model()

# ============================================================
# RULE CONFIG
# ============================================================
LEGIT_TLDS = {

    ".ac.id",
    ".go.id",
    ".sch.id",
    ".ponpes.id",

    ".mil.id",
    ".or.id",
    ".co.id",

    ".ac.uk",
    ".gov.uk",
    ".nhs.uk",

    ".gov",
    ".mil",
    ".edu",

    ".ac.au",
    ".gov.au"
}

SUSPICIOUS_TLDS = {

    ".xin",
    ".bond",
    ".cfd",
    ".today",

    ".lol",
    ".top",
    ".best",
    ".buzz",

    ".shop",
    ".online",
    ".xyz",

    ".icu",
    ".sbs",
    ".cyou",

    ".info",
    ".biz",
    ".click",

    ".link",
    ".lease",
    ".live",

    ".cloud",
    ".my.id",
    ".biz.id",

    ".zip",
    ".mov",
    ".tk",

    ".pw",
    ".ml",
    ".ga",

    ".cf",
    ".gq",
    ".ru",

    ".cn",
    ".me",
    ".site",

    ".store",
    ".fun",
    ".rehab",

    ".skin",
    ".associates"
}

SHORTENERS = {

    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "rb.gy",
    "shorturl.at",
    "cutt.ly",
    "rebrand.ly"
}

DANGEROUS_EXTENSIONS = {

    ".exe",
    ".bat",
    ".cmd",
    ".com",

    ".scr",
    ".pif",

    ".vbs",
    ".vbe",

    ".js",
    ".jse",

    ".wsf",
    ".wsh",

    ".apk",
    ".ipa",

    ".msi",
    ".dll",

    ".sys",
    ".ps1",

    ".psm1",
    ".jar",

    ".class",
    ".hta"
}

FREE_MAIL = {

    "gmail.com",
    "yahoo.com",
    "hotmail.com",
    "outlook.com"
}

INST_KW = [

    "bank",
    "paypal",
    "shopee",
    "tokopedia",

    "bca",
    "bri",
    "mandiri",

    "pemerintah",
    "kpu",
    "ojk",
    "bpjs"
]

URGENCY_KW = [

    "urgent",
    "immediately",
    "verify now",
    "account disabled",

    "segera",
    "gratis",
    "hadiah",
    "promo",

    "klik sekarang",
    "verifikasi",
    "dibekukan"
]

# ============================================================
# HELPERS
# ============================================================
def get_registered_domain(domain):

    ext = tldextract.extract(domain)

    if not ext.domain or not ext.suffix:
        return domain.lower()

    return f"{ext.domain}.{ext.suffix}".lower()

def extract_urls(text):

    return re.findall(
        r'https?://[^\s]+|www\.[^\s]+',
        text
    )

def count_links(text):

    return len(extract_urls(text))

def urgency_score(text):

    return sum(
        1 for k in URGENCY_KW
        if k in text.lower()
    )

def typo_score(text):

    return int(
        bool(
            re.search(
                r'[a-z]+[0-9]+[a-z]+',
                text.lower()
            )
        )
    )

# ============================================================
# FILE CHECK
# ============================================================
def check_file(filename):

    filename = filename.lower()

    score = 0
    reasons = []

    is_double = bool(
        re.search(
            r'\.(pdf|docx|jpg|png)\.(exe|bat|js|scr)',
            filename
        )
    )

    is_multi = len(filename.split(".")) > 2

    if any(
        filename.endswith(ext)
        for ext in DANGEROUS_EXTENSIONS
    ):

        score += 50
        reasons.append("Dangerous attachment extension")

    if is_double:

        score += 50

        reasons.append(
            "Double extension (file disguise attack)"
        )

    elif is_multi:

        score += 20

        reasons.append(
            "Suspicious multi-extension file"
        )

    return score, reasons

# ============================================================
# EML ANALYZER
# ============================================================
def analyze_eml(uploaded_file):

    findings = []

    try:

        uploaded_file.seek(0)

        raw = uploaded_file.read()

        msg = email.message_from_bytes(raw)

        html_content = ""

        for part in msg.walk():

            ctype = part.get_content_type()

            if ctype == "text/html":

                payload = part.get_payload(decode=True)

                if payload:

                    html_content += payload.decode(
                        errors="ignore"
                    )

        soup = BeautifulSoup(
            html_content,
            "html.parser"
        )

        # ====================================================
        # HIDDEN LINK CHECK
        # ====================================================
        for a in soup.find_all("a", href=True):

            visible = a.get_text(
                " ",
                strip=True
            )

            href = a["href"]

            if visible and href:

                visible_urls = extract_urls(visible)

                if visible_urls:

                    visible_domain = get_registered_domain(
                        urlparse(
                            visible_urls[0]
                        ).netloc
                    )

                    href_domain = get_registered_domain(
                        urlparse(
                            href
                        ).netloc
                    )

                    if visible_domain != href_domain:

                        findings.append(
                            "Hidden link mismatch detected"
                        )

        # ====================================================
        # CLICKABLE IMAGE LINK
        # ====================================================
        for img in soup.find_all("img"):

            parent = img.parent

            if parent and parent.name == "a":

                findings.append(
                    "Clickable image link detected"
                )

    except Exception:
        pass

    return findings

# ============================================================
# RULE BASED
# ============================================================
def rule_based(text, sender, file=None):

    score = 0
    reasons = []

    text_lower = text.lower()

    sender = sender.lower()

    sender_domain = sender.split("@")[-1]

    sender_registered = get_registered_domain(
        sender_domain
    )

    # ========================================================
    # TRUSTED TLD
    # ========================================================
    sender_suffix = (
        "." +
        tldextract.extract(sender_domain).suffix
    )

    if sender_suffix in LEGIT_TLDS:

        score -= 15

        reasons.append(
            "Trusted domain"
        )

    # ========================================================
    # SUSPICIOUS TLD
    # ========================================================
    if sender_suffix in SUSPICIOUS_TLDS:

        score += 20

        reasons.append(
            "Suspicious TLD"
        )

    # ========================================================
    # IMPERSONATION
    # ========================================================
    if any(
        mail in sender_domain
        for mail in FREE_MAIL
    ):

        if any(
            k in text_lower
            for k in INST_KW
        ):

            score += 35

            reasons.append(
                "Possible impersonation"
            )

    # ========================================================
    # SHORTENER
    # ========================================================
    if any(
        s in text_lower
        for s in SHORTENERS
    ):

        score += 25

        reasons.append(
            "Shortened URL detected"
        )

    # ========================================================
    # IP URL
    # ========================================================
    if re.search(
        r'\d+\.\d+\.\d+\.\d+',
        text_lower
    ):

        score += 35

        reasons.append(
            "IP address URL detected"
        )

    # ========================================================
    # MANY LINKS
    # ========================================================
    if count_links(text) > 2:

        score += 15

        reasons.append(
            "Many links detected"
        )

    # ========================================================
    # URGENCY
    # ========================================================
    if urgency_score(text):

        score += 20

        reasons.append(
            "Urgency language detected"
        )

    # ========================================================
    # TYPO
    # ========================================================
    if typo_score(text):

        score += 15

        reasons.append(
            "Suspicious typo pattern"
        )

    # ========================================================
    # URL DOMAIN MISMATCH
    # ========================================================
    urls = extract_urls(text)

    for u in urls:

        parsed = urlparse(
            u if u.startswith("http")
            else f"http://{u}"
        )

        url_domain = parsed.netloc.lower()

        if not url_domain:
            continue

        url_registered = get_registered_domain(
            url_domain
        )

        if sender_registered != url_registered:

            score += 20

            reasons.append(
                "Sender domain mismatch with URL"
            )

    # ========================================================
    # DOMAIN PATTERN
    # ========================================================
    if sender_domain.count("-") >= 1:

        score += 15

        reasons.append(
            "Suspicious domain pattern"
        )

    if len(sender_domain) > 25:

        score += 15

        reasons.append(
            "Unusually long domain"
        )

    # ========================================================
    # FILE CHECK
    # ========================================================
    if file:

        fscore, freason = check_file(
            file.name
        )

        score += fscore
        reasons += freason

        # ====================================================
        # FILE ONLY ATTACK
        # ====================================================
        if (
            not text.strip()
            and any(
                file.name.lower().endswith(ext)
                for ext in DANGEROUS_EXTENSIONS
            )
        ):

            score += 30

            reasons.append(
                "File-only dangerous attachment"
            )

        # ====================================================
        # EML ANALYSIS
        # ====================================================
        if file.name.lower().endswith(".eml"):

            findings = analyze_eml(file)

            for finding in findings:

                score += 25
                reasons.append(finding)

    return score, reasons

# ============================================================
# HYBRID
# ============================================================
def hybrid(text, sender, file=None):

    inputs = tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=512
    )

    inputs = {
        k: v.to(device)
        for k, v in inputs.items()
    }

    with torch.no_grad():

        outputs = model(**inputs)

        probs = torch.softmax(
            outputs.logits,
            dim=1
        ).cpu().numpy()[0]

    ai_score = float(probs[1])

    rule_score, reasons = rule_based(
        text,
        sender,
        file
    )

    normalized_rule = min(
        rule_score / 150,
        1.0
    )

    # ========================================================
    # FINAL HYBRID
    # ========================================================
    final_score = (
        (ai_score * 0.60)
        +
        (normalized_rule * 0.40)
    )

    return float(final_score), reasons

# ============================================================
# LOGGING
# ============================================================
def log_data(sender, text, file, score, status):

    file_path = "logs.csv"

    urls = extract_urls(text)

    url_str = (
        ", ".join(urls)
        if urls
        else "-"
    )

    file_ext = "-"

    if file:
        file_ext = file.name.split(".")[-1]

    new_data = pd.DataFrame([{

        "session_id":
            st.session_state.session_id,

        "time":
            datetime.now(),

        "sender":
            sender,

        "body":
            text,

        "url":
            url_str,

        "file_ext":
            file_ext,

        "risk_score":
            round(score, 4),

        "status":
            status
    }])

    if os.path.exists(file_path):

        old = pd.read_csv(file_path)

        new_data = pd.concat([
            old,
            new_data
        ])

    new_data.to_csv(
        file_path,
        index=False
    )

# ============================================================
# HINT UI
# ============================================================
def hint(label, message):

    col1, col2 = st.columns([20, 1])

    with col1:
        st.markdown(label)

    with col2:
        with st.popover("❔"):
            st.write(message)

# ============================================================
# MAIN UI
# ============================================================
st.markdown(
    "<div class='main-card'>",
    unsafe_allow_html=True
)

# ============================================================
# SENDER
# ============================================================
hint(
    f"### {t('sender')} *",
    t("hint_sender")
)

sender = st.text_input(
    "",
    placeholder=(
        "example@company.com"
        if lang == "English"
        else "contoh@email.com"
    )
)

# ============================================================
# EMAIL VALIDATION
# ============================================================
email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"

email_valid = bool(
    re.match(email_pattern, sender)
) if sender else False

if not sender:

    st.markdown(
        f"""
        <p style='
            color:#f59e0b;
            font-size:13px;
            margin-top:-10px;
            font-style:italic;
        '>
        {t("sender_required")}
        </p>
        """,
        unsafe_allow_html=True
    )

elif sender and not email_valid:

    st.markdown(
        f"""
        <p style='
            color:#f59e0b;
            font-size:13px;
            margin-top:-10px;
            font-style:italic;
        '>
        {t("invalid_email")}
        </p>
        """,
        unsafe_allow_html=True
    )

# ============================================================
# EMAIL CONTENT
# ============================================================
hint(
    f"### {t('content')}",
    t("hint_content")
)

text = st.text_area(
    "",
    height=180,
    placeholder=(
        "e.g. Your account will be suspended..."
        if lang == "English"
        else "contoh: akun Anda akan diblokir..."
    )
)

# ============================================================
# FILE UPLOAD
# ============================================================
hint(
    f"### {t('upload')}",
    t("hint_upload")
)

file = st.file_uploader(
    "",
    type=None
)

# ============================================================
# BUTTON
# ============================================================
analyze = st.button(
    t("analyze"),
    use_container_width=True
)

st.markdown(
    "</div>",
    unsafe_allow_html=True
)

# ============================================================
# ANALYSIS
# ============================================================
if analyze:

    if not sender:

        st.warning(
            t("sender_required")
        )

        st.stop()

    if not email_valid:

        st.warning(
            t("invalid_email")
        )

        st.stop()

    score, reasons = hybrid(
        text,
        sender,
        file
    )

    score = max(
        0.0,
        min(float(score), 1.0)
    )

    # ========================================================
    # STATUS
    # ========================================================
    if score < 0.30:

        status = t("safe")
        css = "status-safe"

        reasons.insert(
            0,
            t("low_risk")
        )

    elif score < 0.60:

        status = t("suspicious")
        css = "status-warn"

        reasons.insert(
            0,
            t("mid_risk")
        )

    else:

        status = t("phishing")
        css = "status-danger"

        reasons.insert(
            0,
            t("high_risk")
        )

    # ========================================================
    # RESULT
    # ========================================================
    st.markdown(
        t("result")
    )

    st.markdown(
        f"<p class='{css}'>Status: {status}</p>",
        unsafe_allow_html=True
    )

    st.write(
        f"{t('score')}: {score*100:.1f}%"
    )

    st.markdown(
        t("reasons")
    )

    if reasons:

        unique_reasons = list(
            dict.fromkeys(reasons)
        )

        for r in unique_reasons:
            st.write(f"• {r}")

    # ========================================================
    # LOGGING
    # ========================================================
    log_data(
        sender,
        text,
        file,
        score,
        status
    )

# ============================================================
# FOOTER
# ============================================================
st.markdown("---")

st.markdown("""
<div class='footer'>
    Copyright © 2026 Vicky Chandra.
    Some Rights Reserved.
</div>
""", unsafe_allow_html=True)
