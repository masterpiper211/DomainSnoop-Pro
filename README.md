# DomainSnoop Pro

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue.svg">
  <img src="https://img.shields.io/badge/License-MIT-green.svg">
  <img src="https://img.shields.io/badge/Version-2.2-red.svg">
</p>

DomainSnoop Pro is a powerful, enterprise-grade domain intelligence tool that provides comprehensive analysis of internet domains. Whether you're a security professional, system administrator, or researcher, DomainSnoop Pro helps you gather detailed insights about domain infrastructure, assess security posture, and identify potential threats.

## 🎯 What Can DomainSnoop Pro Do?

### Core Intelligence
- **DNS Infrastructure**: Complete DNS record analysis (A, AAAA, MX, NS, TXT, SOA, CNAME)
- **SSL/TLS Assessment**: In-depth certificate analysis and security evaluation
- **IP Intelligence**: Comprehensive IP information with ASN details
- **Port Scanning**: Fast and efficient port scanning with service detection
- **Technology Detection**: Advanced web technology and framework identification
- **HTTP Headers**: Detailed analysis of HTTP headers and security configurations
- **Subdomain Enumeration**: Comprehensive subdomain discovery and validation
- **Historical Analysis**: Wayback Machine integration for URL discovery
- **Shodan Intelligence**: Advanced host and service information via Shodan API

### 1. Domain Infrastructure Analysis
- Map out complete DNS infrastructure (A, AAAA, MX, NS, TXT, SOA, CNAME records)
- Analyze SSL/TLS certificates and configurations
- Identify IP addresses and gather ASN information
- Discover open ports and running services
- Detect web technologies and frameworks
- Enumerate subdomains using multiple techniques
- Analyze HTTP headers and security configurations
- Historical URL analysis through Wayback Machine
- Shodan integration for additional intelligence

### 2. Security Assessment
- **WAF Detection**: Identifies and fingerprints 10+ Web Application Firewalls
- **SSL/TLS Security**: Analyzes protocols, ciphers, and known vulnerabilities
- **Security Headers**: Comprehensive HTTP security header analysis
- **DNSSEC**: DNSSEC validation and configuration checks
- **Email Security**: SPF, DMARC, DKIM, and MTA-STS verification
- **Typosquatting Detection**: Identifies potential domain squatting attempts
- Identify and fingerprint Web Application Firewalls (WAFs)
- Analyze SSL/TLS security configurations
- Check HTTP security headers
- Validate DNSSEC implementation
- Verify email security (SPF, DMARC, DKIM, MTA-STS)
- Detect potential typosquatting attempts

### 3. Threat Intelligence
- **Domain Reputation**: Checks against multiple reputation databases
- **Certificate Transparency**: Monitors CT logs for suspicious certificates
- **Security Scoring**: Risk assessment based on security configurations
- **Infrastructure Analysis**: Port scanning and service identification
- Check domain reputation against multiple databases
- Monitor Certificate Transparency logs
- Generate security risk scores
- Analyze infrastructure for potential threats

### 4. Performance Features
- **Concurrent Analysis**: High-performance parallel processing with smart rate limiting
- **Error Handling**: Robust error recovery and reporting
- **Color-Coded Output**: Clean, colorized, and structured output
- **Progress Tracking**: Real-time progress indication
- **Data Export**: JSON export for integration
- Fast, concurrent analysis with smart rate limiting
- Color-coded, easy-to-read output
- Real-time progress tracking
- JSON export for integration with other tools
- Extensive subdomain enumeration capabilities
- Historical data analysis
- Advanced HTTP header analysis

## 🔄 Comparison with Similar Tools

| Feature                    | DomainSnoop Pro | Amass     | DNSRecon | theHarvester |
|---------------------------|-----------------|-----------|-----------|--------------|
| **Core Features**         |                |           |           |              |
| DNS Enumeration           | ✅             | ✅        | ✅        | ✅           |
| SSL/TLS Analysis          | ✅             | ❌        | ❌        | ❌           |
| Port Scanning             | ✅             | ❌        | ❌        | ❌           |
| Technology Detection      | ✅             | ❌        | ❌        | ❌           |
| **Advanced Features**     |                |           |           |              |
| Subdomain Enumeration     | ✅             | ✅        | ✅        | ✅           |
| HTTP Header Analysis      | ✅             | ❌        | ❌        | ❌           |
| Historical Data (Wayback) | ✅             | ❌        | ❌        | ❌           |
| Shodan Integration        | ✅             | ✅        | ❌        | ❌           |
| **Security Features**     |                |           |           |              |
| WAF Detection             | ✅             | ❌        | ❌        | ❌           |
| Security Headers Analysis | ✅             | ❌        | ❌        | ❌           |
| Email Security Checks     | ✅             | ❌        | ❌        | ❌           |
| DNSSEC Validation        | ✅             | ✅        | ✅        | ❌           |
| **Threat Intelligence**   |                |           |           |              |
| Domain Reputation         | ✅             | ❌        | ❌        | ❌           |
| CT Log Monitoring        | ✅             | ❌        | ❌        | ❌           |
| Typosquatting Detection  | ✅             | ❌        | ❌        | ❌           |
| **Usability**            |                |           |           |              |
| Concurrent Analysis      | ✅             | ✅        | ❌        | ❌           |
| Color-Coded Output       | ✅             | ✅        | ❌        | ✅           |
| Progress Tracking        | ✅             | ✅        | ❌        | ❌           |
| JSON Export             | ✅             | ✅        | ✅        | ✅           |

## 💻 Installation

```bash
# Clone the repository
git clone https://github.com/masterpiper211/DomainSnoop-Pro.git
cd DomainSnoop-Pro

# Install dependencies
pip install -r requirements.txt

## 🛠️ Usage Examples

### Basic Domain Analysis
```bash
python domainsnoop-pro.py example.com --dns --ssl --ip
```

### Advanced Reconnaissance
```bash
python domainsnoop-pro.py example.com --subdomains --headers --wayback --shodan
```

### Security Analysis
```bash
python domainsnoop-pro.py example.com --ssl-security --http-security --email-security --waf
```

### Threat Intelligence
```bash
python domainsnoop-pro.py example.com --reputation --typosquatting --ct-logs
```

### Full Analysis
```bash
python domainsnoop-pro.py example.com --all --output results.json
```

## 🔧 Command Line Options

```
Basic Analysis:
  domain              Target domain to analyze
  --dns               Fetch DNS records
  --ssl               Fetch SSL certificate information
  --ip                Fetch IP and ASN information

Security Analysis:
  --ssl-security      Analyze SSL/TLS security configuration
  --http-security     Analyze HTTP security headers
  --email-security    Check email security
  --dnssec            Check DNSSEC configuration

Reconnaissance:
  --subdomains        Enumerate subdomains
  --headers           Analyze HTTP headers
  --wayback           Check Wayback Machine URLs
  --shodan            Query Shodan for information

Threat Intelligence:
  --reputation        Check domain reputation
  --typosquatting     Check for typosquatting domains

Additional Features:
  --ports             Scan common ports
  --tech              Detect web technologies
  --ct-logs           Check Certificate Transparency logs
  --waf               Detect Web Application Firewall
  --all               Run all checks

Output Options:
  --output FILE       Save results to file (JSON format)
  --quiet             Suppress progress bar
```

## 🎯 Features in Detail

### HTTP Headers Analysis
- Complete header security assessment
- Information leakage detection
- Security header recommendations
- Technology stack identification
- Server configuration analysis

### Subdomain Enumeration
- DNS zone transfer attempts
- Common subdomain discovery
- Certificate Transparency log analysis
- Active subdomain validation
- IP resolution for discovered subdomains

### Historical Data Analysis
- Wayback Machine integration with:
  - Comprehensive URL categorization
  - Status code analysis
  - MIME type tracking
  - Temporal analysis
  - Year-by-year statistics
  - Advanced error handling and retry mechanism
- Historical URL discovery with smart filtering
- Content type analysis and categorization
- Status code distribution analysis
- Temporal analysis of domain changes

### Progress Tracking
- Real-time progress indication with:
  - Percentage completion
  - Visual progress bar
  - Task completion counter
  - Elapsed time tracking
  - Estimated time remaining
- Smart concurrent task tracking
- Detailed progress for each analysis type

### Shodan Integration
```bash
# Using command line argument
python domainsnoop-pro.py example.com --shodan --shodan-key YOUR_API_KEY

# Using environment variable
set SHODAN_API_KEY=YOUR_API_KEY
python domainsnoop-pro.py example.com --shodan
```

The Shodan integration can be used in two ways:
1. Pass your API key directly using the `--shodan-key` argument
2. Set the `SHODAN_API_KEY` environment variable

- Service enumeration
- Vulnerability detection
- Banner grabbing
- Port mapping
- Security insight generation

## 🔒 Security Considerations

DomainSnoop Pro is designed for legitimate security assessment and research purposes. When using this tool:

1. Ensure you have permission to scan the target domain
2. Be mindful of rate limits and server load
3. Follow responsible disclosure practices
4. Comply with all applicable laws and regulations

## 📈 Performance

- Concurrent analysis for faster results
- Smart rate limiting to prevent server overload
- Efficient resource utilization
- Typical scan times:
  - Basic scan: 15-30 seconds
  - Security scan: 30-60 seconds
  - Full scan: 1-2 minutes

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

We welcome contributions! Whether it's bug fixes, new features, or documentation improvements, please feel free to:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

For major changes, please open an issue first to discuss your proposed changes.

## 🌟 Acknowledgments

Special thanks to the open-source community and the following projects that inspired DomainSnoop Pro:
- Amass
- DNSRecon
- theHarvester
- Nmap
