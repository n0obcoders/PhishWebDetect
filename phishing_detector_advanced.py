
import whois
import requests
import datetime
import socket
import json

# API keys
ABUSEIPDB_API_KEY = "0018b5611a35cdeade80bbf56d25ed06944bde106fb463f7e5587cb48c3ef64ae9a30411132ba84f"
URLSCAN_API_KEY = "01973120-2bc1-71af-b13f-9c9ed9d97b2f"

def is_recent_domain(domain):
    try:
        w = whois.whois(domain)
        if isinstance(w.creation_date, list):
            creation_date = w.creation_date[0]
        else:
            creation_date = w.creation_date
        expiry_date = w.expiration_date if isinstance(w.expiration_date, datetime.datetime) else w.expiration_date[0]
        age = (datetime.datetime.now() - creation_date).days
        print(f"[i] Domain age: {age} days")
        print(f"[i] Domain expiry: {expiry_date.strftime('%Y-%m-%d')}")
        if age < 180:
            print("⚠️ Domain was recently created.")
            return True, w.emails, expiry_date
        return False, w.emails, expiry_date
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")
        return True, "", "Unknown"

def check_dns(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[i] IP Address: {ip}")
        return ip
    except socket.gaierror:
        print("[!] DNS resolution failed.")
        return None

def check_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip}
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        count = data["data"]["totalReports"]
        print(f"[i] IP has been reported {count} times on AbuseIPDB.")
        return count > 0, count
    except Exception as e:
        print(f"[!] Error checking AbuseIPDB: {e}")
        return False, 0

def check_ssl_cert_duration(domain):
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url)
        certs = json.loads(response.text)
        if certs:
            valid_from = datetime.datetime.strptime(certs[0]['not_before'], "%Y-%m-%dT%H:%M:%S")
            valid_to = datetime.datetime.strptime(certs[0]['not_after'], "%Y-%m-%dT%H:%M:%S")
            duration = (valid_to - valid_from).days
            print(f"[i] SSL certificate is valid for {duration} days.")
            return duration < 90, duration
        else:
            print("[!] No certificate found.")
            return True, 0
    except Exception as e:
        print(f"[!] SSL cert check failed: {e}")
        return True, 0

def check_urlscan(ip):
    try:
        headers = {'API-Key': URLSCAN_API_KEY}
        response = requests.get(f'https://urlscan.io/api/v1/search/?q=ip:{ip}', headers=headers)
        results = response.json()
        total = results.get('total', 0)
        print(f"[i] {total} domains found hosted on the same IP.")
        return total > 10, total
    except Exception as e:
        print(f"[!] URLScan lookup failed: {e}")
        return False, 0

def generate_takedown_template(domain, abuse_email, expiry_date, abuse_count, cert_days):
    content = f"""Subject: Phishing Website Takedown Request - {domain}

To Whom It May Concern,

The domain {domain} appears to be hosting a phishing website targeting users. Please take immediate action to investigate and disable this site.

Indicators of abuse:
- Domain registered recently and expires on {expiry_date}
- IP has been reported {abuse_count} times on AbuseIPDB
- SSL Certificate duration: {cert_days} days
- Additional domains hosted on same IP

Please respond with any actions taken.

Sincerely,
Nitin Shukla
"""
    with open("takedown_letter.txt", "w") as f:
        f.write(content)
    print("[✓] Takedown letter saved to 'takedown_letter.txt'.")

def analyze_domain(domain):
    print(f"\n=== Analyzing: {domain} ===")
    flags = 0
    recent, abuse_contact, expiry_date = is_recent_domain(domain)
    if recent: flags += 1
    ip = check_dns(domain)
    if ip:
        abuse, abuse_count = check_abuseipdb(ip)
        if abuse: flags += 1
        urlscan_flag, hosted_count = check_urlscan(ip)
        if urlscan_flag: flags += 1
    else:
        abuse_count = 0
        hosted_count = 0
    cert_flag, cert_days = check_ssl_cert_duration(domain)
    if cert_flag: flags += 1

    print(f"\n[✓] Final phishing score: {flags}/4")
    if flags >= 2:
        print("⚠️ This site is likely a phishing site!")
    else:
        print("✅ This site appears to be safe.")

    # Generate takedown letter
    generate_takedown_template(domain, abuse_contact, expiry_date, abuse_count, cert_days)

# Example use
domain = input("Enter domain to analyze (e.g., example.com): ")
analyze_domain(domain)
