# 🛡️ Phishing Domain Analysis Tool

A comprehensive Python-based command-line tool to analyze suspicious domains and help identify potential phishing websites. Designed for cybersecurity enthusiasts, researchers, and analysts.

## 🚀 Features

- ✅ WHOIS lookup to detect recently registered domains
- 🌐 DNS resolution and IP extraction
- ⚠️ IP reputation check using [AbuseIPDB](https://www.abuseipdb.com/)
- 🕵️‍♂️ URLScan integration to detect shared hosting
- 🔒 SSL certificate validity check (duration and vulnerability)
- 📍 IP geolocation to flag suspicious hosting countries
- 💣 JavaScript inspection for known malicious libraries
- 🧠 Shodan integration for additional IP intelligence
- 📝 Automated takedown letter generation (`takedown_letter.txt`)

## 🔧 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/n0obcoders/PhishWebDetect.git
cd PhishWebDetect
pip install -r requirements.txt

▶️ Usage
Run the analyzer script:

python phishing_detector_advanced.py
