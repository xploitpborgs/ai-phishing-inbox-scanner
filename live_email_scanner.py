import imaplib
import email
import time
import os
import re
from datetime import datetime
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from urllib.parse import urlparse
import tldextract

# === CONFIG ===
EMAIL_CHECK_INTERVAL = 60  # seconds
OUTPUT_FILE = "output/scan_report.txt"

# === Load AI Model ===
model_name = "mrm8488/bert-tiny-finetuned-sms-spam-detection"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)
classifier = pipeline("text-classification", model=model, tokenizer=tokenizer)

# === Define phishing checks ===
PHISHING_KEYWORDS = [
    "verify", "update password", "reset your password", "login now", "urgent", "invoice",
    "bank", "confirm your account", "security alert", "click here", "account will be closed"
]
SUSPICIOUS_DOMAINS = ["g00gle.com", "paypa1.com", "secure-mail.net"]
LEGIT_BRANDS = {"paypal": "paypal.com", "google": "google.com", "facebook": "facebook.com"}

# === Utility Functions ===
def classify_email_ai(body):
    result = classifier(body[:512])[0]
    label = result["label"]
    confidence = result["score"]
    return f"{label} (Confidence: {confidence:.2f})"

def extract_urls(text):
    return re.findall(r'https?://[^\s>\)\"]+', text)

def extract_domain(email_address):
    match = re.search(r'[\w\.-]+@([\w\.-]+)', email_address or "")
    if match:
        return tldextract.extract(match.group(1)).registered_domain
    return ""

def scan_email(uid, mail, output_path):
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

    # Run checks
    ai_verdict = classify_email_ai(body)
    keywords = [kw for kw in PHISHING_KEYWORDS if re.search(rf"\b{kw}\b", body, re.IGNORECASE)]
    urls = extract_urls(body)
    impersonation = None
    for brand, legit_domain in LEGIT_BRANDS.items():
        if brand.lower() in sender_name.lower() and legit_domain not in sender_domain.lower():
            impersonation = f"⚠️ Brand mismatch: '{brand}' name but domain is {sender_domain}"

    # Write result
    with open(output_path, "a", encoding="utf-8") as f:
        f.write("\n" + "="*60 + f"\n📬 Scan Time: {date_str}\n")
        f.write(f"From: {sender}\nSubject: {subject}\nAI Verdict: {ai_verdict}\n")
        f.write(f"Sender Domain: {sender_domain}\n")
        f.write(f"Phishing Keywords: {', '.join(keywords) if keywords else 'None'}\n")
        f.write(f"URLs: {', '.join(urls) if urls else 'None'}\n")
        if impersonation:
            f.write(f"{impersonation}\n")
        f.write("="*60 + "\n")

# === IMAP Monitor ===
def monitor_inbox(email_user, email_pass):
    if not os.path.exists("output"):
        os.makedirs("output")

    print("📡 Connecting to Gmail IMAP...")
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(email_user, email_pass)
    mail.select("inbox")

    seen_uids = set()

    print("✅ Connected. Monitoring inbox...")

    while True:
        mail.select("inbox")
        result, data = mail.search(None, '(UNSEEN)')
        if result == "OK":
            for uid in data[0].split():
                if uid not in seen_uids:
                    seen_uids.add(uid)
                    scan_email(uid, mail, OUTPUT_FILE)
        time.sleep(EMAIL_CHECK_INTERVAL)

# === Main Entry ===
if __name__ == "__main__":
    print("🔐 Enter your email credentials:")
    email_user = input("Email: ").strip()
    email_pass = input("App Password: ").strip()

    try:
        monitor_inbox(email_user, email_pass)
    except Exception as e:
        print(f"❌ Error: {e}")
