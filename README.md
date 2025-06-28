# 🛡️ AI-Powered Live Email Phishing Scanner

This Python tool connects to your **live email inbox using IMAP**, fetches the most recent unread messages, and uses **OpenAI's ChatGPT API** to intelligently determine if an email is a **phishing** or **scam** attempt.

> Built for sales, marketing, and security-conscious professionals — no prior machine learning required.

---

## 🚀 Features

- 🔐 Prompts for secure email login (no hardcoded passwords)
- 📬 Connects directly to Gmail or any IMAP-supported inbox
- 🧠 Uses ChatGPT (GPT-3.5 Turbo) to classify emails: `Safe`, `Phishing`, or `Scam`
- ⚠️ Scans for phishing keywords, suspicious domains, and brand impersonation
- 📄 Saves clear text reports for each scan in the `/output/` folder
- ☁️ Pulls real phishing domain feeds and keyword lists live from the internet

---

## 🧑‍💻 Requirements

- Python 3.8 or higher
- An [OpenAI API key](https://platform.openai.com/account/api-keys)
- A Gmail account with [App Password enabled](https://myaccount.google.com/apppasswords)

---

## 📦 Installation
```bash
git clone https://github.com/xploitpborgs/ai-phishing-inbox-scanner.git
cd ai-phishing-inbox-scanner
pip install -r requirements.txt
```

## 🔧 Usage
Run the script:

python3 imap_scanner.py

You will be prompted to enter:

Your email address

Your app password

(The OpenAI API key is hardcoded in the script during testing)

The scanner will:

Connect to your inbox

Analyze the latest 5 unread emails

Output results in /output/email_scan_YYYYMMDD_HHMMSS.txt


## 🧠 How AI Analysis Works
Each email body is sent to ChatGPT with this prompt:

“Is this email a phishing or scam attempt? Reply only with: Safe, Phishing, or Scam.”

ChatGPT’s answer is then added as a final verdict to your scan report.


## 📁 Output Structure
All scanned results are saved automatically in the output/ folder.
Each file is timestamped and includes:

Sender and subject

GPT verdict

Found phishing keywords

Suspicious URLs or domains

Brand impersonation warnings

##⚠️ Disclaimer
This tool is intended for educational and awareness purposes only.
AI predictions are not always 100% accurate — always validate manually.

## 📄 License
This project is licensed under the MIT License. See LICENSE for details.

## ❤️ Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you’d like to change.

✨ Author
Built by @xploitpborgs
Cybersecurity Intern @ ICDFA – International Cybersecurity and Digital Forensics Academy

