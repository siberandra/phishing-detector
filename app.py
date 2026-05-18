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

import streamlit as st
import torch
import re
import numpy as np
import os
import zipfile
import email
import email.policy
import gdown
import tldextract
import pandas as pd
from datetime import datetime
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from bs4 import BeautifulSoup

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

button[kind="secondary"] {
    font-size: 14px;
    padding: 4px 8px;
}
</style>
""", unsafe_allow_html=True)

# =========================
# SESSION STATE INIT
# =========================
# if "show_hint_sender" not in st.session_state:
#     st.session_state.show_hint_sender = False
# if "show_hint_content" not in st.session_state:
#     st.session_state.show_hint_content = False
# if "show_hint_upload" not in st.session_state:
#     st.session_state.show_hint_upload = False
if "current_user" not in st.session_state:
    # Simulate user identity via session (simple unique ID per session)
    import uuid
    st.session_state.current_user = str(uuid.uuid4())[:8]

# =========================
# TRANSLATIONS
# =========================
TRANSLATIONS = {
    "English": {
        "sender":           "📧 Sender Email",
        "content":          "📝 Email Content",
        "upload":           "📎 Upload File (optional)",
        "analyze":          "🚀 Analyze Email",
        "result":           "## 🔍 Analysis Result",
        "reasons":          "### 📌 Detection Reasons",
        "score":            "⚠️ Phishing Risk Score",
        "safe":             "SAFE",
        "suspicious":       "SUSPICIOUS",
        "phishing":         "PHISHING",
        "no_reason":        "No strong suspicious indicators detected",
        "history":          "📜 History",
        "language":         "🌐 Language",
        "clear_history":    "🗑️ Clear My History",
        "no_logs":          "No logs yet",
        "no_logs_delete":   "No logs to delete",
        "logs_cleared":     "Your history cleared successfully",
        "eml_section":      "### 🔬 EML Structure Analysis",
        # "hint_sender":      "ℹ️ Copy and paste the sender's email address here exactly as it appears in the email header (e.g. no-reply@company.com).",
        # "hint_content":     "ℹ️ Copy and paste the full body text of the email here. Include all paragraphs, links, and any visible text.",
        # "hint_upload":      "ℹ️ Upload any file you received from the email. Do NOT open or run it — just upload it here for safety analysis.\n\nYou can also upload the entire email as an .eml file: in most email clients, use 'Save As' or 'Download' → '.eml' to export the email, then upload it here. This enables deeper link and structure analysis.",
        "sender_required":  "Sender email is required",
        "sender_invalid":   "Please enter a valid email format (e.g. example@domain.com)",
        "low_risk":         "Low risk detected",
        "some_suspicious":  "Some suspicious indicators detected",
        "high_risk":        "High risk phishing indicators detected",
        "no_suspicious":    "No suspicious patterns detected",
        "no_malicious":     "No malicious links or attachments found",
        "sender_normal":    "Sender appears normal",
        "ai_score":         "🤖 AI Score",
        "rule_score":       "📋 Rule Score",
    },
    "Indonesia": {
        "sender":           "📧 Email Pengirim",
        "content":          "📝 Isi Email",
        "upload":           "📎 Upload File (opsional)",
        "analyze":          "🚀 Analisis Email",
        "result":           "## 🔍 Hasil Analisis",
        "reasons":          "### 📌 Alasan Deteksi",
        "score":            "⚠️ Skor Risiko Phishing",
        "safe":             "AMAN",
        "suspicious":       "MENCURIGAKAN",
        "phishing":         "PHISHING",
        "no_reason":        "Tidak ditemukan indikasi mencurigakan",
        "history":          "📜 Riwayat",
        "language":         "🌐 Bahasa",
        "clear_history":    "🗑️ Hapus Riwayat Saya",
        "no_logs":          "Belum ada riwayat",
        "no_logs_delete":   "Tidak ada riwayat untuk dihapus",
        "logs_cleared":     "Riwayat Anda berhasil dihapus",
        "eml_section":      "### 🔬 Analisis Struktur EML",
        # "hint_sender":      "ℹ️ Salin dan tempel alamat email pengirim di sini persis seperti yang tertera di header email (contoh: no-reply@perusahaan.com).",
        # "hint_content":     "ℹ️ Salin semua isi email ke sini. Termasuk semua paragraf, link, dan teks yang tampak di badan email.",
        # "hint_upload":      "ℹ️ Silakan upload file yang Anda terima dari email. Cukup upload saja — JANGAN dibuka atau dijalankan.\n\nAnda juga bisa upload isi email secara keseluruhan dengan mengunduh email menjadi file .eml: di sebagian besar aplikasi email, pilih 'Simpan Sebagai' atau 'Unduh' → '.eml', lalu upload di sini. Ini memungkinkan analisis link tersembunyi yang lebih mendalam.",
        "sender_required":  "Email pengirim wajib diisi",
        "sender_invalid":   "Format email tidak valid (contoh: nama@email.com)",
        "low_risk":         "Risiko rendah terdeteksi",
        "some_suspicious":  "Beberapa indikasi mencurigakan ditemukan",
        "high_risk":        "Indikasi phishing berisiko tinggi terdeteksi",
        "no_suspicious":    "Tidak ditemukan pola mencurigakan",
        "no_malicious":     "Tidak ada link atau file berbahaya",
        "sender_normal":    "Pengirim terlihat normal",
        "ai_score":         "🤖 Skor AI",
        "rule_score":       "📋 Skor Rule",
    }
}

def t(key, lang):
    return TRANSLATIONS[lang].get(key, key)

# =========================
# SIDEBAR
# =========================
with st.sidebar:
    st.markdown("""
    <div style='text-align:center; margin-top:10px; margin-bottom:10px;'>
        <div style='font-size:40px; font-weight:bold'>🛡️ SIEVRA</div>
        <div style='font-size:13px; color:gray;'>Smart Email Verification & Risk Analyzer</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    lang = st.selectbox(
        t("language", "English"),   # label always shown as Language icon + word
        ["English", "Indonesia"],
        key="lang_select"
    )
    # Re-render label in chosen language after selection
    # (Streamlit re-renders automatically on next run)

    st.markdown("---")
    st.markdown(f"## {t('history', lang)}")
    
    LOG_FILE = "logs.csv"
    current_user = st.session_state.current_user
    
    if os.path.exists(LOG_FILE):
        df_all = pd.read_csv(LOG_FILE)
    
        if not df_all.empty:
            # Kolom yang mau ditampilkan
            display_cols = [
                "time", "sender", "body", "url",
                "file_ext", "risk_score", "status"
            ]
    
            existing_cols = [c for c in display_cols if c in df_all.columns]
    
            # ✅ Tampilkan SEMUA history (public)
            st.dataframe(
                df_all[existing_cols].tail(20),
                use_container_width=True
            )
        else:
            st.info(t("no_logs", lang))
    else:
        st.info(t("no_logs", lang))

    # =========================
    # CLEAR ONLY OWN LOGS
    # =========================
    if st.button(t("clear_history", lang)):
        if os.path.exists(LOG_FILE):
            df_all = pd.read_csv(LOG_FILE)
            if "user_id" in df_all.columns:
                df_kept = df_all[df_all["user_id"] != current_user]
                if len(df_kept) == len(df_all):
                    st.info(t("no_logs_delete", lang))
                else:
                    if df_kept.empty:
                        os.remove(LOG_FILE)
                    else:
                        df_kept.to_csv(LOG_FILE, index=False)
                    st.success(t("logs_cleared", lang))
                    st.rerun()
            else:
                # Old format: clear all (backward compat)
                os.remove(LOG_FILE)
                st.success(t("logs_cleared", lang))
                st.rerun()
        else:
            st.info(t("no_logs_delete", lang))

    st.markdown("---")
    st.markdown("<div class='footer'>SIEVRA v1.1.0-beta</div>", unsafe_allow_html=True)

# =========================
# MAIN HEADER
# =========================
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
MODEL_DIR   = "phishing_hybrid_model"
ZIP_FILE    = "phishing_model.zip"
FILE_ID     = "1IJ1PoXkq_6GGT8vFvYVyQCAgnYAbVfsO"
GDRIVE_URL  = f"https://drive.google.com/uc?id={FILE_ID}"

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
    path      = f"{MODEL_DIR}/indobert"
    model     = AutoModelForSequenceClassification.from_pretrained(path)
    tokenizer = AutoTokenizer.from_pretrained(path)
    device    = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)
    model.eval()
    return model, tokenizer, device

model, tokenizer, device = load_model()

# =========================
# RULE-BASED CONFIG  (aligned with notebook v5)
# =========================
LEGIT_TLDS = {
    'ac.id','go.id','sch.id','ponpes.id','mil.id','or.id','co.id',
    'ac.uk','gov.uk','nhs.uk','gov','mil','edu','ac.au','gov.au',
}

SUSPICIOUS_TLDS = {
    'xin','bond','cfd','today','lol','top','best','buzz','shop',
    'online','xyz','icu','sbs','cyou','info','biz','click','link',
    'live','cloud','my.id','biz.id','zip','mov','tk','pw','ml','ga',
    'cf','gq','ru','cn','me','site','store','fun','rehab','skin',
    'associates','club','cc','to','ws','gq',
}

SHORTENERS = {
    'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly',
    'is.gd','rb.gy','shorturl.at','cutt.ly','rebrand.ly',
}

DANGEROUS_EXTENSIONS = {
    '.exe','.bat','.cmd','.com','.scr','.pif',
    '.vbs','.vbe','.js','.jse','.wsf','.wsh',
    '.apk','.ipa',
    '.msi','.dll','.sys',
    '.ps1','.psm1',
    '.jar','.class',
    '.hta',
}

URGENCY_KW = [
    'urgent','immediately','suspended','verify now','action required',
    'account disabled','click here','limited time','expires',
    'segera','gratis','hadiah','promo','menang','klik sekarang',
    'verifikasi','dibekukan','terpilih','klaim','berakhir','darurat',
]

FREE_MAIL = {'gmail.com','yahoo.com','hotmail.com','ymail.com','outlook.com'}
INST_KW   = ['bank','paypal','shopee','tokopedia','bca','bri',
              'mandiri','pemerintah','kpu','bawaslu','ojk','bpjs']

# =========================
# EML PARSER
# =========================
def parse_eml(file_bytes):
    """
    Parse raw .eml bytes → dict with:
      - subject, from_, to_, body_plain, body_html, attachments, raw_html
    """
    msg = email.message_from_bytes(file_bytes, policy=email.policy.default)
    result = {
        "subject":     msg.get("Subject", ""),
        "from_":       msg.get("From", ""),
        "to_":         msg.get("To", ""),
        "body_plain":  "",
        "body_html":   "",
        "attachments": [],
        "raw_html":    "",
    }
    for part in msg.walk():
        ct = part.get_content_type()
        cd = str(part.get("Content-Disposition", ""))
        fn = part.get_filename()
        if fn:
            result["attachments"].append(fn)
            continue
        if ct == "text/plain" and not result["body_plain"]:
            try:
                result["body_plain"] = part.get_content()
            except Exception:
                result["body_plain"] = part.get_payload(decode=True).decode("utf-8", errors="replace")
        elif ct == "text/html" and not result["body_html"]:
            try:
                raw = part.get_content()
            except Exception:
                raw = part.get_payload(decode=True).decode("utf-8", errors="replace")
            result["body_html"] = raw
            result["raw_html"]  = raw
    # Fallback: extract text from HTML if plain is empty
    if not result["body_plain"] and result["body_html"]:
        soup = BeautifulSoup(result["body_html"], "html.parser")
        result["body_plain"] = soup.get_text(separator=" ")
    return result


def check_eml_structure(raw_html):
    """
    Bedah HTML email untuk deteksi:
    1. Hidden link  : anchor text domain ≠ href domain
    2. Gambar berbahaya: img src dengan ekstensi berbahaya
    3. URL over-encoding: terlalu banyak %xx
    Returns: (score 0-100, list[findings])
    """
    score    = 0
    findings = []
    if not raw_html:
        return score, findings

    soup = BeautifulSoup(raw_html, "html.parser")

    # --- Hidden links ---
    for tag in soup.find_all("a", href=True):
        href        = tag["href"]
        anchor_text = tag.get_text()
        try:
            href_domain = tldextract.extract(href).registered_domain
        except Exception:
            href_domain = ""
        text_domains = re.findall(r'[\w-]+\.[a-z]{2,}', anchor_text.lower())
        for td in text_domains:
            try:
                td_reg = tldextract.extract(td).registered_domain
            except Exception:
                td_reg = ""
            if td_reg and href_domain and td_reg != href_domain:
                score += 40
                findings.append(
                    f"Hidden link: teks '{anchor_text.strip()[:40]}' → href '{href[:60]}'"
                )
                break

    # --- Dangerous img src ---
    for tag in soup.find_all("img", src=True):
        src = tag["src"]
        lower = src.lower().split("?")[0].split("#")[0]
        for ext in DANGEROUS_EXTENSIONS:
            if lower.endswith(ext):
                score += 30
                findings.append(f"Gambar dengan ekstensi berbahaya: {ext} ({src[:60]})")
                break

    # --- Over-encoded URLs ---
    for url in re.findall(r'https?://[^\s<>"]+', raw_html):
        if url.count("%") > 3:
            score += 20
            findings.append(f"URL over-encoded ({url.count('%')}x %%): {url[:60]}")
            break

    return min(score, 100), findings


# =========================
# DOMAIN / TLD HELPERS
# =========================
def get_registered_domain(domain):
    try:
        ext = tldextract.extract(domain)
        return ext.registered_domain.lower()
    except:
        return ""

def is_trusted_domain(domain):
    try:
        suffix = tldextract.extract(domain).suffix.lower()
        return suffix in LEGIT_TLDS
    except:
        return False

def check_dangerous_ext_url(url_or_path):
    lower = url_or_path.lower().split("?")[0].split("#")[0]
    for ext in DANGEROUS_EXTENSIONS:
        if lower.endswith(ext):
            return True, ext
    return False, None


def check_domain_tld(domain):
    """Analisis domain: TLD, typosquatting, IP, depth. Returns (risk 0-100, reasons)."""
    risk    = 0
    reasons = []
    try:
        parsed = tldextract.extract(domain)
        suffix = parsed.suffix.lower()
        reg    = parsed.registered_domain.lower()
        full   = domain.lower()
    except Exception:
        return 0, []

    if suffix in SUSPICIOUS_TLDS:
        risk += 40
        reasons.append(f"TLD mencurigakan: .{suffix}")

    # valid suffix → langsung skip typosquatting check
    if suffix in LEGIT_TLDS:
        pass  # skip
    else:
        # jalankan typosquatting check
    
        # Typosquatting TLD (FIXED)
        for legit in LEGIT_TLDS:
            # split domain jadi bagian
            parts = full.split(".")
            
            # contoh: studentsite.gunadarma.ac.id → ['studentsite','gunadarma','ac','id']
            legit_parts = legit.split(".")  # ['ac','id']
            
            # cek apakah legit muncul tapi BUKAN di posisi akhir
            if len(parts) > len(legit_parts):
                if parts[-len(legit_parts):] != legit_parts and legit in full:
                    risk += 50
                    reasons.append(f"TLD resmi '{legit}' disisipkan di tengah (typosquatting)")
                    break

    if len(full.split(".")) > 5 and suffix not in LEGIT_TLDS:
        risk += 20
        reasons.append(f"Domain {len(full.split('.'))} level (terlalu dalam)")

    if re.search(r'\d{4,}', reg):
        risk += 15
        reasons.append("Domain mengandung banyak digit")

    if "-" in reg and len(reg) > 20:
        risk += 15
        reasons.append("Domain panjang berisi tanda hubung")

    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        risk += 60
        reasons.append("Domain berupa IP address")

    return min(risk, 100), reasons


def extract_urls(text):
    return re.findall(r'https?://\S+|www\.\S+', text)

# =========================
# RULE-BASED SCORE  (aligned with notebook v5)
# =========================
def rule_based_score(text, sender_email, raw_html=None):
    """
    Hitung skor rule-based [0.0–1.0].
    Returns: (score, list[reasons])
    """
    score   = 0
    reasons = []
    t_lower = text.lower()

    # --- SENDER DOMAIN ---
    sender_domain = sender_email.split("@")[-1].strip().lower() \
                    if "@" in sender_email else sender_email.lower()
    try:
        s_suffix = tldextract.extract(sender_domain).suffix.lower()
    except Exception:
        s_suffix = ""

    if s_suffix in LEGIT_TLDS:
        score -= 30
        reasons.append(f"Domain pengirim resmi: .{s_suffix}")

    if sender_domain in FREE_MAIL and any(kw in t_lower for kw in INST_KW):
        score += 45
        reasons.append("Klaim dari institusi tapi pakai email gratis")

    s_tld_score, s_tld_reasons = check_domain_tld(sender_domain)
    score   += s_tld_score * 0.5
    reasons += [f"[Sender] {r}" for r in s_tld_reasons]

    # --- URL DI BODY ---
    urls = extract_urls(text)

    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', t_lower):
        score += 50
        reasons.append("URL menggunakan IP address")

    for url in urls:
        if any(s in url.lower() for s in SHORTENERS):
            score += 25
            reasons.append("URL shortener terdeteksi")
            break

    for url in urls:
        ok, ext = check_dangerous_ext_url(url)
        if ok:
            score += 55
            reasons.append(f"URL ekstensi berbahaya: {ext}")
            break

    for url in urls:
        ud = re.sub(r'https?://', '', url).split('/')[0].replace('www.', '')
        tld_s, tld_r = check_domain_tld(ud)
        if tld_s > 0:
            score   += tld_s
            reasons += [f"[URL] {r}" for r in tld_r]
            break

    # Sender–URL domain mismatch (smart version)
    if urls and sender_domain:
        s_reg = get_registered_domain(sender_domain)
        sender_trusted = is_trusted_domain(sender_domain)
    
        for url in urls:
            ud = re.sub(r'https?://', '', url).split('/')[0].replace('www.', '')
            u_reg = get_registered_domain(ud)
    
            if not s_reg or not u_reg:
                continue
    
            # ✅ SAME ROOT DOMAIN → AMAN (subdomain beda gapapa)
            if s_reg == u_reg:
                continue
    
            # ✅ Kalau sender trusted → jangan terlalu keras
            if sender_trusted:
                score += 10   # ringan aja
                reasons.append(f"External link from trusted domain: {u_reg}")
            else:
                score += 30   # tetap keras kalau bukan trusted
                reasons.append(f"Mismatch: sender={s_reg} ≠ url={u_reg}")
    
            break

    if len(urls) > 4:
        score += 20
        reasons.append(f"Terlalu banyak link ({len(urls)})")

    # Dangerous extension mention in body
    for ext in DANGEROUS_EXTENSIONS:
        if ext in t_lower:
            score += 35
            reasons.append(f"Mention ekstensi berbahaya: {ext}")
            break

    # EML HTML structure check
    if raw_html:
        eml_s, eml_f = check_eml_structure(raw_html)
        score   += eml_s
        reasons += eml_f

    # Urgency keywords
    uc = sum(1 for kw in URGENCY_KW if kw in t_lower)
    if uc >= 2:
        score += 20
        reasons.append(f"Banyak kata urgensi ({uc})")
    elif uc == 1:
        score += 10
        reasons.append("Kata urgensi terdeteksi")

    if re.search(r'[a-z]+[0-9]+[a-z]+', t_lower):
        score += 10
        reasons.append("Pola leet/typo mencurigakan")

    score = max(0.0, min(float(score), 100.0)) / 100.0
    return score, reasons


# =========================
# FILE ATTACHMENT CHECK
# =========================
def check_uploaded_file(filename):
    """Check an uploaded file's name for dangerous extensions."""
    fn     = filename.lower()
    score  = 0
    reasons = []

    is_double = bool(re.search(r'\.(pdf|docx|jpg|png)\.(exe|bat|js|scr|vbs)', fn))
    is_multi  = len(fn.split(".")) > 2

    if any(fn.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
        score += 55
        reasons.append(f"Ekstensi file berbahaya: {fn.split('.')[-1]}")

    if is_double:
        score += 50
        reasons.append("Ekstensi ganda (penyamaran file)")
    elif is_multi and not fn.endswith(".eml"):
        score += 20
        reasons.append("File dengan banyak ekstensi mencurigakan")

    return score, reasons


# =========================
# HYBRID INFERENCE
# (AI=0.70, Rule=0.30 — dinaikkan sesuai catatan notebook: Streamlit rule lebih kaya)
# =========================
AI_WEIGHT   = 0.55
RULE_WEIGHT = 0.45

def hybrid_predict(text, sender, raw_html=None, uploaded_file=None):
    """
    Returns: (final_score, ai_score, rule_score, reasons)
    """
    # AI score via XLM-R / IndoBERT
    inputs = tokenizer(
        text, return_tensors="pt",
        truncation=True, padding=True, max_length=512
    )
    inputs = {k: v.to(device) for k, v in inputs.items()}
    with torch.no_grad():
        out   = model(**inputs)
        probs = torch.softmax(out.logits, dim=1).cpu().numpy()[0]
    ai_score = float(probs[1])

    # Rule-based score
    rule_score, reasons = rule_based_score(text, sender, raw_html=raw_html)

    # Uploaded file check (non-EML)
    if uploaded_file and not uploaded_file.name.lower().endswith(".eml"):
        fscore, freasons = check_uploaded_file(uploaded_file.name)
        rule_score = min(1.0, rule_score + fscore / 100.0)
        reasons   += freasons
        if fscore > 0 and not text.strip():
            rule_score = min(1.0, rule_score + 0.40)
            reasons.append("Pesan hanya berisi file berbahaya (file-only attack)")

    final = AI_WEIGHT * ai_score + RULE_WEIGHT * rule_score
    return float(final), float(ai_score), float(rule_score), reasons


# =========================
# REASON TRANSLATION
# =========================
REASON_MAP_ID = {
    "Domain pengirim resmi":                "Domain pengirim resmi",
    "Klaim dari institusi tapi pakai email gratis": "Klaim dari institusi tapi pakai email gratis",
    "URL menggunakan IP address":           "URL menggunakan IP address",
    "URL shortener terdeteksi":             "URL shortener terdeteksi",
    "Terlalu banyak link":                  "Terlalu banyak link",
    "Mismatch":                             "Ketidaksesuaian domain pengirim & URL",
    "Banyak kata urgensi":                  "Banyak kata urgensi",
    "Kata urgensi terdeteksi":              "Kata urgensi terdeteksi",
    "Pola leet/typo mencurigakan":          "Pola leet/typo mencurigakan",
    "TLD mencurigakan":                     "TLD mencurigakan",
    "typosquatting":                        "Typosquatting TLD",
    "Domain berupa IP address":             "Domain berupa IP address",
    "Domain panjang berisi tanda hubung":   "Domain panjang berisi tanda hubung",
    "Domain mengandung banyak digit":       "Domain mengandung banyak digit",
    "terlalu dalam":                        "Domain terlalu banyak level",
    "Hidden link":                          "Link tersembunyi",
    "Gambar dengan ekstensi berbahaya":     "Gambar dengan ekstensi berbahaya",
    "URL over-encoded":                     "URL di-encoding berlebihan (obfuscation)",
    "Ekstensi file berbahaya":              "Ekstensi file berbahaya",
    "Ekstensi ganda":                       "Ekstensi ganda (penyamaran file)",
    "Mention ekstensi berbahaya":           "Penyebutan ekstensi file berbahaya",
    "Pesan hanya berisi file berbahaya":    "Pesan hanya berisi file berbahaya",
    "URL ekstensi berbahaya":               "URL mengarah ke file berbahaya",
}

REASON_MAP_EN = {
    "Domain pengirim resmi":                "Trusted sender domain",
    "Klaim dari institusi tapi pakai email gratis": "Institution impersonation via free email",
    "URL menggunakan IP address":           "URL uses raw IP address",
    "URL shortener terdeteksi":             "URL shortener detected",
    "Terlalu banyak link":                  "Too many links in body",
    "Mismatch":                             "Sender domain ≠ URL domain",
    "Banyak kata urgensi":                  "Multiple urgency keywords",
    "Kata urgensi terdeteksi":              "Urgency keyword detected",
    "Pola leet/typo mencurigakan":          "Suspicious leet/typo pattern",
    "TLD mencurigakan":                     "Suspicious TLD",
    "typosquatting":                        "TLD typosquatting detected",
    "Domain berupa IP address":             "Domain is an IP address",
    "Domain panjang berisi tanda hubung":   "Long domain with hyphens",
    "Domain mengandung banyak digit":       "Domain contains many digits",
    "terlalu dalam":                        "Too many domain levels",
    "Hidden link":                          "Hidden link (anchor mismatch)",
    "Gambar dengan ekstensi berbahaya":     "Image with dangerous extension",
    "URL over-encoded":                     "Over-encoded URL (obfuscation)",
    "Ekstensi file berbahaya":              "Dangerous file extension",
    "Ekstensi ganda":                       "Double extension (file disguise)",
    "Mention ekstensi berbahaya":           "Mention of dangerous extension",
    "Pesan hanya berisi file berbahaya":    "File-only message with malicious attachment",
    "URL ekstensi berbahaya":               "URL points to dangerous file",
}

def translate_reason(r, lang):
    mapping = REASON_MAP_EN if lang == "English" else REASON_MAP_ID
    for key, val in mapping.items():
        if key.lower() in r.lower():
            # Preserve bracketed prefix like [Sender], [URL]
            prefix = ""
            if r.startswith("["):
                prefix = r[:r.index("]")+2]
                r_rest = r[len(prefix):]
                for k2, v2 in mapping.items():
                    if k2.lower() in r_rest.lower():
                        return prefix + v2
            return prefix + val
    return r  # fallback: original

# =========================
# LOGGING
# =========================
def log_data(sender, text, file, score, ai_score, rule_score, status, user_id):
    urls    = extract_urls(text)
    url_str = ", ".join(urls) if urls else "-"
    file_ext = "-"
    if file:
        file_ext = file.name.split(".")[-1]

    new = pd.DataFrame([{
        "time":       datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user_id":    user_id,
        "sender":     sender,
        "body":       text[:200],
        "url":        url_str,
        "file_ext":   file_ext,
        "ai_score":   round(ai_score, 4),
        "rule_score": round(rule_score, 4),
        "risk_score": round(score, 4),
        "status":     status,
    }])

    if os.path.exists("logs.csv"):
        old = pd.read_csv("logs.csv")
        new = pd.concat([old, new], ignore_index=True)
    new.to_csv("logs.csv", index=False)


# =========================
# MAIN UI
# =========================
st.markdown("<div class='main-card'>", unsafe_allow_html=True)

# --- Sender Email ---
# col_sender, col_hint = st.columns([10,1])

# with col_sender:
sender = st.text_input(
    t("sender", lang) + " *",
    placeholder="example@company.com" if lang=="English" else "contoh@email.com"
)

# with col_hint:
#     with st.popover("ⓘ"):
#         st.write(t("hint_sender", lang))

# if st.session_state.show_hint_sender:
#     st.markdown(
#         f"<div class='hint-popup'>{t('hint_sender', lang)}</div>",
#         unsafe_allow_html=True
#     )

# Real-time email validation
email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
email_valid   = bool(re.match(email_pattern, sender)) if sender else False

if not sender:
    st.markdown(
        f"<p style='color:#f59e0b; font-size:13px; margin-top:-10px; font-style:italic;'>"
        f"{t('sender_required', lang)}</p>",
        unsafe_allow_html=True
    )
elif not email_valid:
    st.markdown(
        f"<p style='color:#f59e0b; font-size:13px; margin-top:-10px; font-style:italic;'>"
        f"{t('sender_invalid', lang)}</p>",
        unsafe_allow_html=True
    )

# --- Email Content ---
# col_content, col_hint = st.columns([10,1])

# with col_content:
text = st.text_area(
    t("content", lang),
    height=180,
    placeholder="e.g. Your account will be suspended..."
)

# with col_hint:
#     with st.popover("ⓘ"):
#         st.write(t("hint_content", lang))

# if st.session_state.show_hint_content:
#     st.markdown(
#         f"<div class='hint-popup'>{t('hint_content', lang)}</div>",
#         unsafe_allow_html=True
#    )

# --- File Upload ---
# col_upload, col_hint = st.columns([10,1])

uploaded_file = st.file_uploader(t("upload", lang))

# with col_hint:
#     with st.popover("ⓘ"):
#         st.write(t("hint_upload", lang))

# if st.session_state.show_hint_upload:
#     st.markdown(
#         f"<div class='hint-popup'>{t('hint_upload', lang).replace(chr(10), '<br>')}</div>",
#         unsafe_allow_html=True
#     )

analyze = st.button(t("analyze", lang), use_container_width=True)
st.markdown("</div>", unsafe_allow_html=True)

# =========================
# ANALYSIS
# =========================
if analyze:
    if not sender:
        st.warning(t("sender_required", lang))
        st.stop()
    if not re.match(email_pattern, sender):
        st.warning(t("sender_invalid", lang))
        st.stop()

    # --- EML handling ---
    eml_data  = None
    raw_html  = None
    eml_info  = {}

    if uploaded_file and uploaded_file.name.lower().endswith(".eml"):
        file_bytes = uploaded_file.read()
        eml_data   = parse_eml(file_bytes)
        raw_html   = eml_data.get("raw_html", "")
        # Auto-populate text from EML if text area is empty
        if not text.strip():
            text = eml_data.get("body_plain", "")
        # Auto-populate sender if still default
        eml_from = eml_data.get("from_", "")
        if eml_from and not re.match(email_pattern, sender):
            sender = re.search(r'[\w\.\-]+@[\w\.\-]+\.\w+', eml_from)
            sender = sender.group(0) if sender else sender

    with st.spinner("Analyzing..." if lang == "English" else "Menganalisis..."):
        final_score, ai_score, rule_score, reasons = hybrid_predict(
            text, sender,
            raw_html=raw_html,
            uploaded_file=uploaded_file
        )

    final_score = max(0.0, min(float(final_score), 1.0))

    # --- Contextual reason enrichment (strict by status) ---
    if final_score < 0.3:
        # SAFE → hanya alasan aman
        if not reasons:
            reasons = [
                t("no_suspicious", lang),
                t("no_malicious", lang),
                t("sender_normal", lang),
            ]
        else:
            reasons = [t("no_suspicious", lang)] + reasons[:2]
    
    elif final_score < 0.6:
        # SUSPICIOUS → hanya alasan mencurigakan
        reasons = [t("some_suspicious", lang)] + reasons
    
    else:
        # PHISHING → alasan kuat phishing
        reasons = [t("high_risk", lang)] + reasons

    # --- Status ---
    if final_score < 0.3:
        status = t("safe", lang)
        css    = "status-safe"
        emoji  = "✅"
    elif final_score < 0.6:
        status = t("suspicious", lang)
        css    = "status-warn"
        emoji  = "⚠️"
    else:
        status = t("phishing", lang)
        css    = "status-danger"
        emoji  = "🚨"

    # --- Result display ---
    st.markdown(t("result", lang))
    st.markdown(f"<p class='{css}'>{emoji} Status: {status}</p>", unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    col1.metric(t("score", lang).replace("⚠️ ", ""), f"{final_score*100:.1f}%")
    col2.metric(t("ai_score", lang), f"{ai_score*100:.1f}%")
    col3.metric(t("rule_score", lang), f"{rule_score*100:.1f}%")

    st.progress(final_score)

    st.markdown(t("reasons", lang))
    for r in reasons:
        st.write(f"• {translate_reason(r, lang)}")

    # --- EML structural details ---
    if eml_data:
        with st.expander(t("eml_section", lang)):
            st.markdown(f"**From:** {eml_data['from_']}")
            st.markdown(f"**Subject:** {eml_data['subject']}")
            if eml_data["attachments"]:
                att_list = ", ".join(eml_data["attachments"])
                st.markdown(
                    f"**{'Attachments' if lang=='English' else 'Lampiran'}:** {att_list}"
                )
            # Show all links found in HTML
            if eml_data["raw_html"]:
                soup_links = BeautifulSoup(eml_data["raw_html"], "html.parser")
                all_links  = [(a.get_text(strip=True), a["href"])
                              for a in soup_links.find_all("a", href=True)]
                if all_links:
                    st.markdown(
                        f"**{'Links found' if lang=='English' else 'Link ditemukan'} ({len(all_links)}):**"
                    )
                    for txt_lnk, href_lnk in all_links[:20]:
                        st.write(f"  • `{href_lnk}` ← {txt_lnk[:60]}")

    # --- Log ---
    log_data(
        sender, text, uploaded_file,
        final_score, ai_score, rule_score, status,
        st.session_state.current_user
    )

# =========================
# FOOTER
# =========================
st.markdown("---")
st.markdown(
    "<div class='footer'>Copyright © 2026 Vicky Chandra. Some Rights Reserved.</div>",
    unsafe_allow_html=True
)
