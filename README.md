# DomainSnoop-Pro

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg">
  <img src="https://img.shields.io/badge/License-MIT-green.svg">
  <img src="https://img.shields.io/badge/Version-2.2-red.svg">
</p>

**DomainSnoop-Pro** is an advanced, enterprise-grade domain intelligence and reconnaissance tool for security professionals, researchers, sysadmins, and anyone needing in-depth information about internet domains. It combines a broad set of reconnaissance, security, and intelligence features in a single, concurrent, and highly extensible platform.

---

## 🚀 What Does DomainSnoop-Pro Do?

DomainSnoop-Pro offers a full suite of domain intelligence and reconnaissance checks, including:

### 🔎 Domain & Infrastructure Analysis

- **DNS Record Analysis**: Fetches all key DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME)
- **IP & ASN Intelligence**: Finds IP addresses, ASN, geolocation, organization, and abuse contacts
- **SSL/TLS Inspection**: Retrieves certificate details, issuer, validity, and alternative names
- **Port Scanning**: Scans the target for open common ports and services
- **Technology Detection**: Identifies frameworks, server software, and web technologies
- **Subdomain Enumeration**: Discovers active subdomains using DNS, heuristics, and CT logs
- **Wayback Machine Integration**: Recovers historical URLs and snapshots for the domain

### 🛡️ Security & Threat Assessment

- **SSL/TLS Security Analysis**: Checks for insecure protocols, ciphers, certificate expiry, and vulnerabilities
- **HTTP Security Headers**: Assesses presence and configuration of all major security headers
- **Email Security**: Verifies SPF, DKIM, DMARC, and MTA-STS DNS records
- **DNSSEC Validation**: Checks if the domain uses DNSSEC for integrity protection
- **WAF Detection**: Identifies common Web Application Firewalls and their vendors
- **Typosquatting Detection**: Scans for active typo-variant domains to spot phishing risk
- **Domain Reputation**: Checks if the domain appears on major DNS blacklists
- **Certificate Transparency Monitoring**: Reviews recent CT log entries for suspicious certificates
- **Shodan Integration**: Gathers external threat intelligence and vulnerability data via Shodan API

### ⚡ Performance & Usability

- **Concurrent Analysis**: Runs multiple checks in parallel for speed
- **Error Handling**: Clear, colorized, and robust error reporting
- **Progress Tracking**: See real-time status, completion percentage, and estimates
- **Data Export**: Save results as JSON for compliance or integration
- **Web UI**: A Flask-based web interface for easy, interactive use

---

## 🖥️ Installation

1. **Clone the repository:**
    ```bash
    git clone https://github.com/masterpiper211/DomainSnoop-Pro.git
    cd DomainSnoop-Pro
    ```

2. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

---

## 🛠️ Usage Examples

### Basic Scan
```bash
python domainsnoop_pro.py example.com --dns --ssl --ip
Security Scan
bash
python domainsnoop_pro.py example.com --ssl-security --http-security --email-security --waf
Reconnaissance Scan
bash
python domainsnoop_pro.py example.com --subdomains --headers --wayback --shodan --shodan-key YOUR_API_KEY
Full Scan & Save to JSON
bash
python domainsnoop_pro.py example.com --all --output results.json
Launch the Web UI
bash
python domainsnoop_pro.py --web
# Then open http://localhost:5000 in your browser
🧩 Command Line Options
Code
Basic Analysis:
  domain              Target domain to analyze
  --dns               Fetch DNS records
  --ssl               Fetch SSL certificate information
  --ip                Fetch IP and ASN information

Security Analysis:
  --ssl-security      Analyze SSL/TLS security configuration
  --http-security     Analyze HTTP security headers
  --email-security    Check email security (SPF, DKIM, DMARC, MTA-STS)
  --dnssec            Check DNSSEC configuration

Reconnaissance:
  --subdomains        Enumerate subdomains
  --headers           Analyze HTTP headers / detect technologies
  --wayback           Get URLs from Wayback Machine
  --shodan            Query Shodan for external exposure and vulnerabilities
  --shodan-key        Provide Shodan API key

Threat Intelligence:
  --reputation        Check domain reputation against blacklists
  --typosquatting     Scan for active typo-variant domains
  --waf               Detect Web Application Firewall

Output Options:
  --output FILE       Save results to file (JSON format)
  --all               Run all checks
  --web               Launch the DomainSnoop-Pro web UI
🌐 Web User Interface
DomainSnoop-Pro includes an interactive web UI built with Flask.

To launch:
bash
python domainsnoop_pro.py --web
Visit http://localhost:5000 in your browser
Select checks and input your domain right from your browser
📊 Comparison With Similar Tools
Feature	DomainSnoop-Pro	Amass	DNSRecon	theHarvester
DNS Enumeration	✅	✅	✅	✅
SSL/TLS Certificate Analysis	✅	❌	❌	❌
SSL/TLS Security Check	✅	❌	❌	❌
Port Scanning	✅	❌	❌	❌
Technology Detection	✅	❌	❌	❌
Subdomain Enumeration	✅	✅	✅	✅
HTTP Header Analysis	✅	❌	❌	❌
Wayback Machine Integration	✅	❌	❌	❌
Shodan Integration	✅	✅	❌	❌
WAF Detection	✅	❌	❌	❌
Email Security (SPF, DKIM...)	✅	❌	❌	❌
DNSSEC Validation	✅	✅	✅	❌
Reputation Checks	✅	❌	❌	❌
Typosquatting Detection	✅	❌	❌	❌
Certificate Transparency Logs	✅	❌	❌	❌
Concurrent Analysis	✅	✅	❌	❌
Colorized Output / Progress	✅	✅	❌	✅
JSON Export	✅	✅	✅	✅
Web UI	✅	❌	❌	❌
🔒 Security & Ethics
Only use DomainSnoop-Pro for domains you have permission to scan
Respect rate limits and target policies
Use responsibly and legally
📝 License
MIT License — see LICENSE for full details.

🤝 Contributing
Contributions are welcome!

Fork the repo
Create a feature branch
Submit your pull request
For bigger changes, please open an issue to discuss first
🙏 Acknowledgments
Inspired by and builds upon:

Amass
DNSRecon
theHarvester
Nmap
DomainSnoop-Pro: Your all-in-one toolkit for domain intelligence, security, and reconnaissance
