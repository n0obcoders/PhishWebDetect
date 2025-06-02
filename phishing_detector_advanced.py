import whois
import requests
import datetime
import socket
import json
import re
import ssl
import dns.resolver

# API keys
ABUSEIPDB_API_KEY = "0018b5611a35cdeade80bbf56d25ed06944bde106fb463f7e5587cb48c3ef64ae9a30411132ba84f"
URLSCAN_API_KEY = "01973120-2bc1-71af-b13f-9c9ed9d97b2f"
SHODAN_API_KEY = "xtnMzl1rtZ4B6P6j74HEwNrKV1W6jPIP"

def is_recent_domain(domain):
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiry_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        if not creation_date:
            raise ValueError("Missing creation date in WHOIS info")
        age = (datetime.datetime.now() - creation_date).days
        print(f"[i] Domain age: {age} days")
        if expiry_date:
            print(f"[i] Domain expiry: {expiry_date.strftime('%Y-%m-%d')}")
        return age < 180, w.emails, expiry_date
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
            cert = certs[0]
            valid_from = datetime.datetime.strptime(cert['not_before'], "%Y-%m-%dT%H:%M:%S")
            valid_to = datetime.datetime.strptime(cert['not_after'], "%Y-%m-%dT%H:%M:%S")
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

def check_suspicious_url_patterns(domain):
    suspicious_patterns = [
        r'%[0-9A-Fa-f]{2}',
        r'[a-z0-9]{3,5}\.[a-z]{2,5}',
        r'[a-z]{1,3}\.[a-z]{1,3}\.[a-z]{2,3}',
        r'([a-z]+[0-9]+){2,}',
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, domain):
            print(f"[!] Suspicious URL pattern detected: {domain}")
            return True
    return False

def check_dangerous_js(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        scripts = ["phishing.js", "malicious-library.js", "stealth.js"]
        for s in scripts:
            if s in response.text:
                print(f"[!] Dangerous JavaScript detected: {s}")
                return True
        return False
    except Exception as e:
        print(f"[!] JavaScript check failed: {e}")
        return False

def check_ssl_vulnerability(domain):
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        if not cert:
            print("[!] No SSL certificate found.")
            return True
        print(f"[i] SSL Certificate Information: {cert}")
        return False
    except Exception as e:
        print(f"[!] SSL vulnerability check failed: {e}")
        return True

def check_ip_geolocation(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        data = requests.get(url).json()
        if data["country"] not in ["United States", "Canada", "Germany", "France"]:
            print(f"[!] Suspicious IP geolocation: {data['country']}")
            return True
        return False
    except Exception as e:
        print(f"[!] IP geolocation check failed: {e}")
        return False

def generate_takedown_template(domain, abuse_email, expiry_date, abuse_count, cert_days):
    expiry_str = expiry_date.strftime('%Y-%m-%d') if isinstance(expiry_date, datetime.datetime) else str(expiry_date)
    contact = abuse_email if abuse_email else "abuse@registrar.example"
    content = f"""Subject: Phishing Website Takedown Request - {domain}

To Whom It May Concern,

The domain {domain} appears to be hosting a phishing website targeting users. Please take immediate action to investigate and disable this site.

Indicators of abuse:
- Recently registered domain (Expires on: {expiry_str})
- IP has been reported {abuse_count} times on AbuseIPDB
- SSL Certificate validity duration: {cert_days} days
- Suspicious URL pattern, JavaScript, SSL issues, and geolocation

Please respond with any actions taken.

Sincerely,
Nitin Shukla
(Contact: {contact})
"""
    try:
        with open("takedown_letter.txt", "w") as f:
            f.write(content)
        print("[✓] Takedown letter saved to 'takedown_letter.txt'.")
    except Exception as e:
        print(f"[!] Failed to write takedown letter: {e}")

def analyze_and_identify_phishing(domain):
    print(f"\n=== Analyzing: {domain} ===")
    phishing_flags = 0
    recent, abuse_contact, expiry_date = is_recent_domain(domain)
    if recent: phishing_flags += 1
    ip = check_dns(domain)
    abuse_count = 0
    cert_days = 0

    if ip:
        abuse, abuse_count = check_abuseipdb(ip)
        if abuse: phishing_flags += 1
        urlscan_flag, _ = check_urlscan(ip)
        if urlscan_flag: phishing_flags += 1
        if check_ip_geolocation(ip): phishing_flags += 1
    else:
        print("[!] Skipping AbuseIPDB and URLScan due to missing IP.")

    cert_flag, cert_days = check_ssl_cert_duration(domain)
    if cert_flag: phishing_flags += 1
    if check_suspicious_url_patterns(domain): phishing_flags += 1
    if check_dangerous_js(domain): phishing_flags += 1
    if check_ssl_vulnerability(domain): phishing_flags += 1

    print(f"\n[✓] Final phishing score: {phishing_flags}/7")
    if phishing_flags >= 3:
        print("⚠ This site is likely a phishing site!")
    else:
        print("✅ This site appears to be safe.")

    generate_takedown_template(domain, abuse_contact, expiry_date, abuse_count, cert_days)

if __name__ == "__main__":
    domain = input("Enter domain to analyze (e.g., example.com): ").strip()
    if domain:
        analyze_and_identify_phishing(domain)
    else:
        print("[!] No domain entered.")
