import os
import imaplib
import email
import re
import tldextract
from urllib.parse import urlparse
from datetime import datetime
import openai
import requests
import getpass

# === Hardcoded API Key ===
openai.api_key = "sk-REPLACE-WITH-YOUR-KEY"  # Replace during testing

# === Prompt User Email Login ===
print("🔐 Email Scanner Setup")
EMAIL = input("Enter your email address: ").strip()
APP_PASSWORD = getpass.getpass("Enter your app password: ")

if not EMAIL or not APP_PASSWORD:
    print("❌ Missing credentials. Exiting.")
    exit(1)

# === Live phishing data ===
def get_phishing_keywords():
    try:
        r = requests.get("https://raw.githubusercontent.com/marshyski/phishing-keywords/main/keywords.json", timeout=10)
        return r.json()
    except:
        return ["urgent", "verify", "click here", "bank", "login"]

def get_phishing_domains():
    try:
        r = requests.get("https://openphish.com/feed.txt", timeout=10)
        return {url.split("/")[2] for url in r.text.splitlines() if "://" in url}
    except:
        return {"g00gle.com", "secure-mail.net", "paypa1.com"}

def get_brands():
    return {
        "paypal": "paypal.com",
        "google": "google.com",
        "facebook": "facebook.com",
        "apple": "apple.com",
        "amazon": "amazon.com"
    }

# === Utilities ===
def extract_email_info(msg):
    sender = msg.get("From", "")
    subject = msg.get("Subject", "")
    body = ""

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors='ignore')
    else:
        body = msg.get_payload(decode=True).decode(errors='ignore')

    return sender, subject, body

def extract_urls(text):
    url_pattern = r'https?://[^\s)>\"]+'
    return re.findall(url_pattern, text)

def check_with_ai(email_body):
    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert."},
                {"role": "user", "content": f"Is this email a phishing or scam attempt? Reply only with: Safe, Phishing, or Scam.\n\n{email_body}"}
            ]
        )
        return response['choices'][0]['message']['content'].strip()
    except Exception as e:
        return f"AI error: {e}"

# === Scanner Core ===
def scan_email(sender, subject, body, keywords, bad_domains, brands):
    report = []
    verdict = check_with_ai(body)

    report.append(f"📨 From: {sender}")
    report.append(f"📝 Subject: {subject}")
    report.append(f"🤖 GPT Verdict: {verdict}")

    domain_match = re.search(r'@([\w\.-]+)', sender)
    domain = tldextract.extract(domain_match.group(1)).registered_domain if domain_match else None

    found_keywords = [k for k in keywords if k.lower() in body.lower()]
    if found_keywords:
        report.append(f"⚠️ Phishing Keywords: {found_keywords}")

    urls = extract_urls(body)
    if urls:
        report.append(f"🔗 URLs: {urls}")
        for u in urls:
            parsed = tldextract.extract(urlparse(u).hostname or "").registered_domain
            if parsed and parsed in bad_domains:
                report.append(f"🚨 Suspicious Domain: {u}")

    for brand, legit in brands.items():
        if brand in sender.lower() and legit not in (domain or ""):
            report.append(f"⚠️ Brand Impersonation: '{brand}' in sender, but domain ≠ {legit}")
            break

    return "\n".join(report)

def save_output(content):
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"output/email_scan_{now}.txt"
    with open(filename, 'w') as f:
        f.write(content)
    print(f"📁 Saved to: {filename}")

# === Main ===
def main():
    print("\n📬 Connecting to inbox...")
    try:
        imap = imaplib.IMAP4_SSL("imap.gmail.com")
        imap.login(EMAIL, APP_PASSWORD)
    except Exception as e:
        print("❌ Login failed:", e)
        return

    imap.select("INBOX")
    _, messages = imap.search(None, 'UNSEEN')
    email_ids = messages[0].split()[-5:]  # last 5 unread emails

    phishing_keywords = get_phishing_keywords()
    phishing_domains = get_phishing_domains()
    brands = get_brands()

    print(f"\n📥 Scanning {len(email_ids)} unread emails...\n")

    for eid in email_ids:
        _, data = imap.fetch(eid, "(RFC822)")
        msg = email.message_from_bytes(data[0][1])
        sender, subject, body = extract_email_info(msg)
        result = scan_email(sender, subject, body, phishing_keywords, phishing_domains, brands)
        print(result)
        print("=" * 50)
        save_output(result)
        imap.store(eid, '+FLAGS', '\\Seen')

    imap.logout()
    print("✅ Scan complete.")

if __name__ == "__main__":
    main()

