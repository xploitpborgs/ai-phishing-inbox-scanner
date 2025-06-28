# live_email_scanner.py

import imaplib
import email
import time
import os
import re
import requests
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from urllib.parse import urlparse
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import tldextract

# === CONFIG ===
EMAIL_CHECK_INTERVAL = 60  # seconds
OUTPUT_FILE = "output/scan_report.txt"
PHISHING_KEYWORDS_URL = "https://raw.githubusercontent.com/x0rz/phishing_catcher/master/wordlist.txt"
PHISHING_DOMAINS_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

# === Load AI Model ===
model_name = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)
classifier = pipeline("text-classification", model=model, tokenizer=tokenizer)

# === Online Feed Functions ===
def fetch_online_keywords():
    try:
        response = requests.get(PHISHING_KEYWORDS_URL, timeout=10)
        if response.status_code == 200:
            return [kw.strip().lower() for kw in response.text.splitlines() if kw.strip()]
    except:
        pass
    return [
        "verify", "update password", "reset your password", "login now",
        "urgent", "invoice", "bank", "confirm your account", "security alert"
    ]

def fetch_online_domains():
    try:
        response = requests.get(PHISHING_DOMAINS_URL, timeout=10)
        if response.status_code == 200:
            return [d.strip().lower() for d in response.text.splitlines() if d.strip()]
    except:
        pass
    return ["g00gle.com", "paypa1.com", "faceb00k.com", "secure-mail.net", "bank-login.net"]

# === Email Alert ===
def send_phishing_alert(to_email, subject, sender, verdict, urls):
    try:
        smtp_server = "smtp.gmail.com"
        smtp_port = 587
        from_email = to_email
        app_password = input("Enter your Gmail App Password again for alerts: ").strip()

        body = f"""
\u26a0\ufe0f Phishing Alert Detected

From: {sender}
Subject: {subject}
AI Verdict: {verdict}
Dangerous Links: {', '.join(urls) if urls else 'None'}

See full details in output/scan_report.txt
"""

        msg = MIMEText(body)
        msg['Subject'] = "\ud83d\udea8 Phishing Alert: Suspicious Email Detected"
        msg['From'] = from_email
        msg['To'] = to_email

        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(from_email, app_password)
        server.sendmail(from_email, to_email, msg.as_string())
        server.quit()
        print("\u2705 Alert email sent.")
    except Exception as e:
        print(f"\u274c Failed to send alert email: {e}")

# === Utilities ===
def extract_urls(text):
    return re.findall(r'https?://[^\s>\)"]+', text)

def extract_domain(email_address):
    match = re.search(r'[\w\.-]+@([\w\.-]+)', email_address or "")
    if match:
        return tldextract.extract(match.group(1)).registered_domain
    return ""

def classify_email_ai(body):
    result = classifier(body[:512])[0]
    label = result["label"]
    confidence = result["score"]
    return f"{label} (Confidence: {confidence:.2f})", label.upper()

def scan_email(uid, mail, output_path, keywords, domains, user_email):
    _, msg_data = mail.fetch(uid, '(RFC822)')
    raw_email = msg_data[0][1]
    msg = email.message_from_bytes(raw_email)

    sender = msg.get("From")
    subject = msg.get("Subject")
    sender_domain = extract_domain(sender)
    sender_name = re.sub(r"<.*?>", "", sender or "")
    date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Get body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")

    # Checks
    ai_verdict, label = classify_email_ai(body)
    found_keywords = [kw for kw in keywords if re.search(rf"\b{re.escape(kw)}\b", body, re.IGNORECASE)]
    urls = extract_urls(body)
    impersonation = None
    for brand, legit_domain in {"paypal": "paypal.com", "google": "google.com", "facebook": "facebook.com"}.items():
        if brand.lower() in sender_name.lower() and legit_domain not in sender_domain:
            impersonation = f"\u26a0\ufe0f Brand impersonation: '{brand}' name used but domain is {sender_domain}"

    with open(output_path, "a", encoding="utf-8") as f:
        f.write("\n" + "="*60 + f"\n\ud83d\udce8 Scan Time: {date_str}\n")
        f.write(f"From: {sender}\nSubject: {subject}\nAI Verdict: {ai_verdict}\n")
        f.write(f"Sender Domain: {sender_domain}\n")
        f.write(f"Phishing Keywords: {', '.join(found_keywords) if found_keywords else 'None'}\n")
        f.write(f"URLs: {', '.join(urls) if urls else 'None'}\n")
        if impersonation:
            f.write(f"{impersonation}\n")
        f.write("="*60 + "\n")

    if label == "SPAM":
        send_phishing_alert(user_email, subject, sender, ai_verdict, urls)

# === Monitor ===
def monitor_inbox(email_user, email_pass):
    if not os.path.exists("output"):
        os.makedirs("output")

    print("\ud83d\udcc0 Connecting to Gmail IMAP...")
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(email_user, email_pass)
    mail.select("inbox")

    seen_uids = set()
    phishing_keywords = fetch_online_keywords()
    phishing_domains = fetch_online_domains()

    print("\u2705 Connected. Monitoring inbox...")

    while True:
        mail.select("inbox")
        result, data = mail.search(None, '(UNSEEN)')
        if result == "OK":
            for uid in data[0].split():
                if uid not in seen_uids:
                    seen_uids.add(uid)
                    scan_email(uid, mail, OUTPUT_FILE, phishing_keywords, phishing_domains, email_user)
        time.sleep(EMAIL_CHECK_INTERVAL)

# === Main ===
if __name__ == "__main__":
    print("\ud83d\udd10 Enter your email credentials:")
    email_user = input("Email: ").strip()
    email_pass = input("App Password: ").strip()

    try:
        monitor_inbox(email_user, email_pass)
    except Exception as e:
        print(f"\u274c Error: {e}")
