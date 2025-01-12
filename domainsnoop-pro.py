import argparse
import concurrent.futures
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import dns.resolver
import dns.zone
import dns.query
import ipwhois
import requests
import whois
import shodan
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from pyfiglet import figlet_format
from datetime import datetime
from tqdm import tqdm
from functools import wraps
import textwrap
from urllib3.util import Retry
from requests.adapters import HTTPAdapter

# Initialize colorama for cross-platform colored output
init()

# Configure logging
logging.basicConfig(level=logging.INFO)

class DomainSnoopError(Exception):
    """Base exception class for DomainSnoop Pro"""
    pass

class DNSError(DomainSnoopError):
    """DNS-related errors"""
    pass

class SSLError(DomainSnoopError):
    """SSL/TLS-related errors"""
    pass

class SecurityError(DomainSnoopError):
    """Security analysis related errors"""
    pass

class NetworkError(DomainSnoopError):
    """Network-related errors"""
    pass

class ValidationError(DomainSnoopError):
    """Input validation errors"""
    pass

class RateLimitError(DomainSnoopError):
    """Raised when rate limit is exceeded"""
    pass

class APIError(DomainSnoopError):
    """Raised when an API request fails"""
    pass

class TimeoutError(DomainSnoopError):
    """Raised when operations timeout"""
    pass

def is_valid_domain(domain):
    """Custom domain validation"""
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def validate_domain(domain):
    """Validate domain name format"""
    try:
        if not domain:
            raise ValidationError("Domain name cannot be empty")
        if len(domain) > 253:
            raise ValidationError("Domain name too long (max 253 characters)")
        if not all(len(part) <= 63 for part in domain.split('.')):
            raise ValidationError("Domain label too long (max 63 characters)")
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', domain):
            raise ValidationError("Invalid domain name format")
    except Exception as e:
        raise ValidationError(f"Domain validation failed: {str(e)}")

def handle_request_error(func):
    """Decorator for handling network request errors"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except requests.exceptions.SSLError:
            raise NetworkError("SSL certificate verification failed")
        except requests.exceptions.ConnectionError:
            raise NetworkError("Failed to establish connection")
        except requests.exceptions.Timeout:
            raise NetworkError("Request timed out")
        except requests.exceptions.RequestException as e:
            raise NetworkError(f"Request failed: {str(e)}")
    return wrapper

def handle_dns_error(func):
    """Decorator for handling DNS-related errors"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except dns.resolver.NXDOMAIN:
            raise DNSError("Domain does not exist")
        except dns.resolver.NoAnswer:
            raise DNSError("No DNS records found")
        except dns.resolver.NoNameservers:
            raise DNSError("No nameservers available")
        except dns.exception.Timeout:
            raise DNSError("DNS query timed out")
        except dns.exception.DNSException as e:
            raise DNSError(f"DNS query failed: {str(e)}")
    return wrapper

def handle_ssl_error(func):
    """Decorator for handling SSL-related errors"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ssl.SSLError as e:
            raise SSLError(f"SSL error: {str(e)}")
        except ssl.CertificateError as e:
            raise SSLError(f"Certificate error: {str(e)}")
        except socket.gaierror:
            raise SSLError("Failed to resolve hostname")
        except socket.timeout:
            raise SSLError("Connection timed out")
        except Exception as e:
            raise SSLError(f"SSL analysis failed: {str(e)}")
    return wrapper

def print_colored(text, color=Fore.WHITE, style=Style.NORMAL, prefix=''):
    """Print colored and styled text"""
    print(f"{style}{color}{prefix}{text}{Style.RESET_ALL}")

def print_section_header(section):
    """Print a formatted section header"""
    print("\n" + "="*50)
    print_colored(f" {section} ", Fore.CYAN, Style.BRIGHT, "")
    print("="*50)

def print_result(key, value, indent=0, status=None):
    """Print a key-value result with optional status coloring"""
    indent_str = "  " * indent
    if isinstance(value, dict):
        print_colored(f"{indent_str}{key}:", Fore.YELLOW, Style.BRIGHT)
        for k, v in value.items():
            print_result(k, v, indent + 1)
    elif isinstance(value, list):
        print_colored(f"{indent_str}{key}:", Fore.YELLOW, Style.BRIGHT)
        for item in value:
            if isinstance(item, dict):
                for k, v in item.items():
                    print_result(k, v, indent + 1)
            else:
                status_color = Fore.GREEN if 'configured' in str(item).lower() else Fore.RED
                print_colored(f"{indent_str}  - {item}", status_color)
    else:
        if status == 'error':
            color = Fore.RED
        elif status == 'warning':
            color = Fore.YELLOW
        elif status == 'success':
            color = Fore.GREEN
        else:
            if 'error' in str(value).lower():
                color = Fore.RED
            elif any(word in str(value).lower() for word in ['not configured', 'failed', 'invalid']):
                color = Fore.RED
            elif any(word in str(value).lower() for word in ['warning', 'medium']):
                color = Fore.YELLOW
            elif any(word in str(value).lower() for word in ['configured', 'success', 'good', 'low']):
                color = Fore.GREEN
            else:
                color = Fore.WHITE
        print_colored(f"{indent_str}{key}: {value}", color)

def format_results(results):
    """Format and color-code the results"""
    formatted = {}
    for section, data in results.items():
        if isinstance(data, dict):
            if 'error' in data:
                formatted[section] = {'status': 'error', 'message': data['error']}
            else:
                formatted[section] = data
        else:
            formatted[section] = data
    return formatted

def print_banner():
    """Print the tool's banner"""
    banner = figlet_format("DomainSnoop-Pro", font="slant")
    print_colored(banner, Fore.CYAN, Style.BRIGHT)
    print_colored("A Comprehensive Domain Intelligence Tool", Fore.CYAN)
    print_colored("=" * 60 + "\n", Fore.CYAN)

def log_error(error, severity="ERROR"):
    """Enhanced error logging with severity levels"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    error_msg = f"[{timestamp}] {severity}: {str(error)}"

    if severity == "CRITICAL":
        logging.critical(error_msg)
    elif severity == "ERROR":
        logging.error(error_msg)
    elif severity == "WARNING":
        logging.warning(error_msg)
    else:
        logging.info(error_msg)

    if severity in ["CRITICAL", "ERROR"]:
        print_colored(f"\nCritical error: {str(error)}", Fore.RED, Style.BRIGHT)

def fetch_ip_info(domain):
    """Fetch IP information for a domain"""
    try:
        # Get IP address
        ip = socket.gethostbyname(domain)

        # Get WHOIS information for the IP
        obj = ipwhois.IPWhois(ip)
        results = obj.lookup_rdap(depth=1)

        # Format the results
        ip_info = {
            'IP Address': ip,
            'ASN': results.get('asn', 'Unknown'),
            'ASN Description': results.get('asn_description', 'Unknown'),
            'Organization': results.get('network', {}).get('name', 'Unknown'),
            'Country': results.get('asn_country_code', 'Unknown'),
            'CIDR': results.get('network', {}).get('cidr', 'Unknown'),
            'Abuse Contact': results.get('network', {}).get('abuse_emails', ['Unknown'])[0]
        }

        return ip_info

    except socket.gaierror:
        return {'error': f"Could not resolve domain {domain}"}
    except Exception as e:
        return {'error': f"Error fetching IP info: {str(e)}"}

def fetch_ssl(domain):
    """Fetch SSL certificate information"""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()

        ssl_data = {
            'Subject': dict(x[0] for x in cert['subject']),
            'Issuer': dict(x[0] for x in cert['issuer']),
            'Version': cert['version'],
            'Serial Number': cert['serialNumber'],
            'Not Before': cert['notBefore'],
            'Not After': cert['notAfter'],
            'Subject Alternative Names': cert.get('subjectAltName', [])
        }
        logging.info(f"SSL certificate data retrieved for {domain}")
        return ssl_data
    except Exception as e:
        logging.error(f"Error fetching SSL certificate data for {domain}: {e}")
        return {"error": f"Error fetching SSL certificate data: {e}"}

def check_ct_logs(domain):
    """Check Certificate Transparency logs"""
    try:
        url = f"https://crt.sh/?q={domain}&output=json"
        response = requests.get(url)
        certs = response.json()
        return [{'issuer': cert['issuer_name'],
                'not_before': cert['not_before'],
                'not_after': cert['not_after']}
               for cert in certs[:5]]
    except Exception as e:
        return {'error': f"Error checking CT logs: {str(e)}"}

def scan_ports(domain, timeout=2):
    """Scan common ports"""
    try:
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            465: 'SMTPS',
            587: 'SMTP',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt'
        }

        open_ports = []
        ip = socket.gethostbyname(domain)

        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(f"{port}/tcp ({common_ports[port]})")
            sock.close()

        return open_ports if open_ports else ["No open ports found"]

    except socket.gaierror:
        return {"error": "Failed to resolve domain"}
    except socket.error as e:
        return {"error": f"Socket error: {str(e)}"}
    except Exception as e:
        return {"error": f"Port scan failed: {str(e)}"}

def detect_technologies(domain):
    """Detect web technologies"""
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        technologies = []

        # Check headers
        headers = response.headers
        server = headers.get('Server')
        if server:
            technologies.append(f"Server: {server}")

        powered_by = headers.get('X-Powered-By')
        if powered_by:
            technologies.append(f"Powered by: {powered_by}")

        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')

        # Check meta tags
        generator = soup.find('meta', attrs={'name': 'generator'})
        if generator:
            technologies.append(f"Generator: {generator.get('content', '')}")

        # Check for common frameworks
        frameworks = {
            'bootstrap.min.css': 'Bootstrap',
            'jquery.min.js': 'jQuery',
            'react.': 'React',
            'vue.': 'Vue.js',
            'angular.': 'Angular'
        }

        for script in soup.find_all(['script', 'link']):
            src = script.get('src', '') or script.get('href', '')
            for key, value in frameworks.items():
                if key in str(src).lower():
                    technologies.append(value)

        return list(set(technologies)) if technologies else ["No technologies detected"]
    except Exception as e:
        return {"error": f"Technology detection failed: {str(e)}"}

@handle_ssl_error
def analyze_ssl_security(domain):
    """Detailed SSL/TLS security analysis"""
    validate_domain(domain)
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()

                if not cert:
                    raise SSLError("No certificate found")

                vulnerabilities = []
                if version in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                    vulnerabilities.append(f"Insecure protocol: {version}")
                if cipher[0] in ['RC4', 'DES', '3DES', 'NULL']:
                    vulnerabilities.append(f"Weak cipher: {cipher[0]}")
                if 'sha1' in str(cipher).lower():
                    vulnerabilities.append("Weak hash algorithm: SHA1")

                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y GMT')
                if not_after < datetime.now():
                    vulnerabilities.append("Certificate expired")
                elif (not_after - datetime.now()).days < 30:
                    vulnerabilities.append("Certificate expiring soon")

                return {
                    'Protocol': version,
                    'Cipher Suite': cipher[0],
                    'Key Exchange': cipher[1],
                    'MAC': cipher[2],
                    'Perfect Forward Secrecy': 'DHE' in cipher[1] or 'ECDHE' in cipher[1],
                    'Vulnerabilities': vulnerabilities if vulnerabilities else ['No known vulnerabilities'],
                    'Certificate Valid Until': not_after.strftime('%Y-%m-%d %H:%M:%S GMT')
                }

    except SSLError:
        raise
    except Exception as e:
        raise SSLError(f"SSL security analysis failed: {str(e)}")

@handle_request_error
def analyze_http_security(domain):
    """Analyze HTTP security headers"""
    validate_domain(domain)
    try:
        response = requests.get(f"https://{domain}", timeout=10)
        headers = response.headers

        if response.status_code != 200:
            raise SecurityError(f"HTTP request failed with status code: {response.status_code}")

        security_headers = {
            'Strict-Transport-Security': ('HSTS', headers.get('Strict-Transport-Security', 'Not set')),
            'Content-Security-Policy': ('CSP', headers.get('Content-Security-Policy', 'Not set')),
            'X-Frame-Options': ('Clickjacking Protection', headers.get('X-Frame-Options', 'Not set')),
            'X-Content-Type-Options': ('MIME Sniffing Protection', headers.get('X-Content-Type-Options', 'Not set')),
            'X-XSS-Protection': ('XSS Protection', headers.get('X-XSS-Protection', 'Not set')),
            'Referrer-Policy': ('Referrer Policy', headers.get('Referrer-Policy', 'Not set')),
            'Permissions-Policy': ('Permissions Policy', headers.get('Permissions-Policy', 'Not set')),
            'Cross-Origin-Opener-Policy': ('COOP', headers.get('Cross-Origin-Opener-Policy', 'Not set')),
            'Cross-Origin-Resource-Policy': ('CORP', headers.get('Cross-Origin-Resource-Policy', 'Not set')),
            'Cross-Origin-Embedder-Policy': ('COEP', headers.get('Cross-Origin-Embedder-Policy', 'Not set'))
        }

        issues = []
        critical_headers = {
            'Strict-Transport-Security': 'HSTS not implemented',
            'Content-Security-Policy': 'CSP not implemented',
            'X-Frame-Options': 'Clickjacking protection not implemented',
            'X-Content-Type-Options': 'MIME sniffing protection not implemented'
        }

        for header, message in critical_headers.items():
            if header not in headers:
                issues.append(message)

        security_score = 100 - (len(issues) * 25)  # Deduct 25 points for each missing critical header

        return {
            'Security Headers': {name: value for header, (name, value) in security_headers.items()},
            'Security Issues': issues if issues else ['No major security issues found'],
            'Security Score': f"{max(0, security_score)}%",
            'Risk Level': 'High' if security_score < 50 else 'Medium' if security_score < 75 else 'Low'
        }

    except SecurityError:
        raise
    except Exception as e:
        raise SecurityError(f"HTTP security analysis failed: {str(e)}")

@handle_dns_error
def check_email_security(domain):
    """Check email security configurations"""
    validate_domain(domain)
    try:
        results = {}
        errors = []

        # Check SPF
        try:
            spf_records = dns.resolver.resolve(domain, 'TXT')
            spf = [str(r) for r in spf_records if 'v=spf1' in str(r)]
            results['SPF'] = spf[0] if spf else 'Not configured'
            if not spf:
                errors.append("SPF record not found")
        except dns.resolver.NXDOMAIN:
            results['SPF'] = 'Not configured'
            errors.append("Domain does not exist")
        except Exception as e:
            results['SPF'] = 'Error'
            errors.append(f"SPF check failed: {str(e)}")

        # Check DMARC
        try:
            dmarc_records = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            dmarc = [str(r) for r in dmarc_records if 'v=DMARC1' in str(r)]
            results['DMARC'] = dmarc[0] if dmarc else 'Not configured'
            if not dmarc:
                errors.append("DMARC record not found")
        except dns.resolver.NXDOMAIN:
            results['DMARC'] = 'Not configured'
            errors.append("DMARC record not found")
        except Exception as e:
            results['DMARC'] = 'Error'
            errors.append(f"DMARC check failed: {str(e)}")

        # Check DKIM
        try:
            dkim_selectors = ['default', 'google', 'k1', 'mail', 'selector1']
            dkim_results = []
            for selector in dkim_selectors:
                try:
                    dkim_record = dns.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                    dkim_results.append(f"{selector}: Configured")
                except:
                    continue
            results['DKIM'] = dkim_results if dkim_results else 'Not configured'
            if not dkim_results:
                errors.append("No DKIM records found")
        except Exception as e:
            results['DKIM'] = 'Error'
            errors.append(f"DKIM check failed: {str(e)}")

        # Check MTA-STS
        try:
            mta_sts = requests.get(f"https://mta-sts.{domain}/.well-known/mta-sts.txt", timeout=5)
            results['MTA-STS'] = 'Configured' if mta_sts.status_code == 200 else 'Not configured'
            if mta_sts.status_code != 200:
                errors.append("MTA-STS not configured")
        except:
            results['MTA-STS'] = 'Not configured'
            errors.append("MTA-STS not configured")

        # Overall assessment
        security_score = 0
        if results['SPF'] != 'Not configured' and results['SPF'] != 'Error': security_score += 25
        if results['DMARC'] != 'Not configured' and results['DMARC'] != 'Error': security_score += 25
        if results['DKIM'] != 'Not configured' and results['DKIM'] != 'Error': security_score += 25
        if results['MTA-STS'] == 'Configured': security_score += 25

        results['Security Score'] = f"{security_score}%"
        results['Assessment'] = 'Good' if security_score >= 75 else 'Fair' if security_score >= 50 else 'Poor'
        results['Errors'] = errors if errors else ['No errors found']

        return results

    except DNSError:
        raise
    except Exception as e:
        raise DNSError(f"Email security check failed: {str(e)}")

def check_typosquatting(domain):
    """Check for potential typosquatting domains"""
    try:
        base_name = domain.split('.')[0]
        tld = domain[len(base_name)+1:]
        variants = set()

        # Character swapping
        for i in range(len(base_name)-1):
            variant = base_name[:i] + base_name[i+1] + base_name[i] + base_name[i+2:]
            variants.add(f"{variant}.{tld}")

        # Character duplication
        for i in range(len(base_name)):
            variant = base_name[:i] + base_name[i] + base_name[i:]
            variants.add(f"{variant}.{tld}")

        # Character omission
        for i in range(len(base_name)):
            variant = base_name[:i] + base_name[i+1:]
            variants.add(f"{variant}.{tld}")

        # Common replacements
        replacements = {
            'a': ['4', '@'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            'l': ['1'],
            'b': ['8'],
            't': ['7']
        }

        for char, replacements in replacements.items():
            if char in base_name:
                for replacement in replacements:
                    variant = base_name.replace(char, replacement)
                    variants.add(f"{variant}.{tld}")

        # Check domain availability
        active_variants = []
        for variant in variants:
            try:
                ip = socket.gethostbyname(variant)
                whois_info = whois.whois(variant)
                creation_date = whois_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]

                active_variants.append({
                    'domain': variant,
                    'ip': ip,
                    'registrar': whois_info.registrar,
                    'creation_date': creation_date.strftime('%Y-%m-%d') if creation_date else 'Unknown'
                })
            except:
                continue

        return {
            'Original Domain': domain,
            'Variants Checked': len(variants),
            'Active Variants': active_variants,
            'Risk Level': 'High' if len(active_variants) > 5 else 'Medium' if len(active_variants) > 0 else 'Low'
        }

    except Exception as e:
        return {'error': f"Typosquatting check failed: {str(e)}"}

def enumerate_subdomains(domain):
    """Enumerate subdomains using various techniques"""
    try:
        subdomains = set()
        
        # DNS enumeration
        try:
            # Get NS records and try zone transfer
            ns_records = dns.resolver.resolve(domain, 'NS')
            for ns in ns_records:
                try:
                    z = dns.zone.from_xfr(dns.query.xfr(str(ns), domain))
                    names = z.nodes.keys()
                    subdomains.update([str(name) + '.' + domain for name in names])
                except:
                    continue
        except:
            pass
        
        # Common subdomain enumeration
        common_subdomains = ['www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2', 
                           'webmail', 'admin', 'dev', 'test', 'portal', 'vpn', 
                           'api', 'cdn', 'stage', 'app', 'blog', 'shop', 'forum']
        
        for sub in common_subdomains:
            try:
                answers = dns.resolver.resolve(f"{sub}.{domain}", 'A')
                subdomains.add(f"{sub}.{domain}")
            except:
                continue
        
        # Certificate Transparency logs
        try:
            ct_subdomains = check_ct_logs(domain)
            if isinstance(ct_subdomains, dict) and 'domains' in ct_subdomains:
                subdomains.update(ct_subdomains['domains'])
        except:
            pass
        
        # Validate all found subdomains
        valid_subdomains = []
        for subdomain in subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
                valid_subdomains.append({
                    'subdomain': subdomain,
                    'ip': ip,
                    'status': 'Active'
                })
            except:
                continue
        
        return {
            'total_found': len(valid_subdomains),
            'subdomains': valid_subdomains
        }
    except Exception as e:
        return {"error": f"Error enumerating subdomains: {str(e)}"}

def get_wayback_urls(domain):
    """Get historical URLs from Wayback Machine"""
    try:
        wayback_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&collapse=urlkey"
        
        # Increased timeout and added retries with backoff
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retries))
        
        response = session.get(wayback_url, timeout=60)
        
        if response.status_code != 200:
            return {"error": "Failed to retrieve Wayback Machine data"}
        
        data = response.json()
        if not data or len(data) < 2:  # First row is header
            return {"urls": [], "total": 0}
        
        # Process URLs
        urls = []
        seen_urls = set()
        
        # Skip header row
        for item in data[1:]:
            url = item[2]  # URL is in the third column
            if url not in seen_urls:
                seen_urls.add(url)
                try:
                    timestamp = item[1]
                    status = item[4]
                    mime_type = item[3]
                    
                    # Convert timestamp to readable format
                    timestamp_str = timestamp[:4] + '-' + timestamp[4:6] + '-' + timestamp[6:8]
                    
                    urls.append({
                        'url': url,
                        'timestamp': timestamp_str,
                        'status': status,
                        'mime_type': mime_type
                    })
                except:
                    continue
        
        # Sort URLs by timestamp
        urls.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Categorize URLs
        categories = {
            'total': len(urls),
            'by_status': {},
            'by_mime_type': {},
            'by_year': {},
            'urls': urls[:100]  # Return only the most recent 100 URLs
        }
        
        for url in urls:
            # Count by status code
            status = url['status']
            categories['by_status'][status] = categories['by_status'].get(status, 0) + 1
            
            # Count by MIME type
            mime = url['mime_type']
            categories['by_mime_type'][mime] = categories['by_mime_type'].get(mime, 0) + 1
            
            # Count by year
            year = url['timestamp'][:4]
            categories['by_year'][year] = categories['by_year'].get(year, 0) + 1
        
        # Add summary statistics
        categories['summary'] = {
            'total_urls': len(urls),
            'unique_mime_types': len(categories['by_mime_type']),
            'years_archived': len(categories['by_year']),
            'earliest_year': min(categories['by_year'].keys()) if categories['by_year'] else 'N/A',
            'latest_year': max(categories['by_year'].keys()) if categories['by_year'] else 'N/A'
        }
        
        return categories
    except requests.Timeout:
        return {"error": "Wayback Machine request timed out. Try again later."}
    except Exception as e:
        return {"error": f"Error retrieving Wayback URLs: {str(e)}"}

def simulate_progress(total_steps):
    """Simulate progress bar for better UX"""
    for _ in tqdm(range(total_steps), desc="Processing", ascii=True, ncols=100):
        time.sleep(0.1)

def save_to_file(filename, data):
    """Save results to a file"""
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(data)
    logging.info(f"Results saved to {filename}")

def get_dns_records(domain):
    """Fetch DNS records"""
    try:
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [answer.to_text() for answer in answers]
            except dns.resolver.NoAnswer:
                dns_records[record_type] = ["No records found"]
            except Exception as e:
                dns_records[record_type] = [f"Error: {str(e)}"]

        return dns_records
    except Exception as e:
        return {'error': f"Error fetching DNS records: {str(e)}"}

def check_dnssec(domain):
    """Check DNSSEC validation"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.use_dnssec = True

        # Check for DNSKEY records
        try:
            dnskey = resolver.resolve(domain, 'DNSKEY')
            has_dnskey = True
        except:
            has_dnskey = False

        # Check for DS records
        try:
            ds = resolver.resolve(domain, 'DS')
            has_ds = True
        except:
            has_ds = False

        if has_dnskey and has_ds:
            return "DNSSEC is enabled and validated"
        elif has_dnskey or has_ds:
            return "DNSSEC is partially configured"
        else:
            return "DNSSEC is not enabled"

    except Exception as e:
        return f'Error: {str(e)}'

def check_reputation(domain):
    """Check domain reputation"""
    try:
        blacklists = ['zen.spamhaus.org', 'bl.spamcop.net']
        results = {}

        for bl in blacklists:
            try:
                query = f"{domain}.{bl}"
                socket.gethostbyname(query)
                results[bl] = "Listed"
            except:
                results[bl] = "Not listed"

        return results
    except Exception as e:
        return {'error': f"Error checking reputation: {str(e)}"}

def check_waf(domain):
    """Detect Web Application Firewall"""
    try:
        waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
            'AWS WAF': ['x-amzn-RequestId', 'x-amz-cf-id'],
            'Akamai': ['akamai-origin-hop', 'akamai-grn'],
            'Imperva': ['incap_ses_', '_incap_'],
            'F5 BIG-IP': ['BigIP', 'F5'],
            'Sucuri': ['sucuri-', 'x-sucuri'],
            'ModSecurity': ['mod_security', 'NAXSI'],
            'Barracuda': ['barra_counter_session'],
            'Citrix NetScaler': ['ns_af=', 'citrix_ns_id'],
            'FortiWeb': ['FORTIWAFSID']
        }

        headers = {}
        cookies = {}

        # Try different HTTP methods to trigger WAF
        for method in ['GET', 'POST', 'OPTIONS']:
            try:
                response = requests.request(method, f"https://{domain}", timeout=10)
                headers.update(response.headers)
                cookies.update(response.cookies.get_dict())
            except:
                continue

        detected_wafs = []
        for waf, signatures in waf_signatures.items():
            for sig in signatures:
                if any(sig.lower() in str(v).lower() for v in headers.values()) or \
                   any(sig.lower() in str(v).lower() for v in cookies.values()):
                    detected_wafs.append(waf)
                    break

        if detected_wafs:
            return {
                'WAF Detected': True,
                'Vendors': list(set(detected_wafs)),
                'Confidence': 'High' if len(detected_wafs) > 1 else 'Medium'
            }
        else:
            return {
                'WAF Detected': False,
                'Note': 'No WAF signature detected, but WAF might still be present with different configuration'
            }

    except Exception as e:
        return {'error': f"WAF detection failed: {str(e)}"}

def check_shodan(domain, api_key=None):
    """Query Shodan for information about the domain"""
    try:
        # Get Shodan API key from argument or environment variable
        SHODAN_API_KEY = api_key or os.getenv('SHODAN_API_KEY')
        if not SHODAN_API_KEY:
            return {"error": "Shodan API key not provided. Use --shodan-key or set SHODAN_API_KEY environment variable."}
        
        api = shodan.Shodan(SHODAN_API_KEY)

        # Get IP address
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return {"error": f"Could not resolve domain {domain} to IP address"}

        # Search Shodan
        try:
            host = api.host(ip)
        except shodan.APIError as e:
            return {"error": f"Shodan API error: {str(e)}"}

        # Process results
        results = {
            'ip': ip,
            'hostnames': host.get('hostnames', []),
            'organization': host.get('org', 'N/A'),
            'operating_system': host.get('os', 'N/A'),
            'ports': host.get('ports', []),
            'vulnerabilities': host.get('vulns', []),
            'services': [],
            'total_services': len(host.get('data', [])),
            'last_update': host.get('last_update', 'N/A'),
            'country': host.get('country_name', 'N/A'),
            'city': host.get('city', 'N/A'),
            'isp': host.get('isp', 'N/A')
        }

        # Process each service
        for item in host.get('data', []):
            service = {
                'port': item.get('port'),
                'protocol': item.get('transport', 'N/A'),
                'service': item.get('product', 'N/A'),
                'version': item.get('version', 'N/A'),
                'cpe': item.get('cpe', []),
                'banner': item.get('data', '').split('\n')[0][:100] if item.get('data') else 'N/A'
            }
            results['services'].append(service)

        # Add security insights
        security_insights = []
        if host.get('vulns'):
            security_insights.append(f"Found {len(host['vulns'])} potential vulnerabilities")

        # Check for common security issues
        common_ports = {
            21: "FTP",
            23: "Telnet",
            3389: "RDP",
            445: "SMB"
        }

        for port, service in common_ports.items():
            if port in host.get('ports', []):
                security_insights.append(f"{service} port ({port}) is open - consider security implications")

        results['security_insights'] = security_insights

        return results
    except Exception as e:
        return {"error": f"Error checking Shodan: {str(e)}"}

def main():
    """Main function to run the tool"""
    try:
        parser = argparse.ArgumentParser(
            description='DomainSnoop Pro - A comprehensive domain intelligence tool',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=textwrap.dedent('''
                Examples:
                  Basic scan:
                    %(prog)s example.com --dns --ssl --ip
                  Security scan:
                    %(prog)s example.com --ssl-security --http-security --email-security
                  Reconnaissance scan:
                    %(prog)s example.com --subdomains --headers --wayback --shodan --shodan-key YOUR_API_KEY
                  Full scan:
                    %(prog)s example.com --all
                ''')
        )
        
        # Add argument groups for better organization
        basic_group = parser.add_argument_group('Basic Analysis')
        basic_group.add_argument('domain', help='Target domain to analyze')
        basic_group.add_argument('--dns', action='store_true', help='Fetch DNS records')
        basic_group.add_argument('--ssl', action='store_true', help='Fetch SSL certificate information')
        basic_group.add_argument('--ip', action='store_true', help='Fetch IP and ASN information')
        
        security_group = parser.add_argument_group('Security Analysis')
        security_group.add_argument('--ssl-security', action='store_true', help='Analyze SSL/TLS security configuration')
        security_group.add_argument('--http-security', action='store_true', help='Analyze HTTP security headers')
        security_group.add_argument('--email-security', action='store_true', help='Check email security')
        security_group.add_argument('--dnssec', action='store_true', help='Check DNSSEC configuration')
        
        recon_group = parser.add_argument_group('Reconnaissance')
        recon_group.add_argument('--subdomains', action='store_true', help='Enumerate subdomains')
        recon_group.add_argument('--headers', action='store_true', help='Analyze HTTP headers')
        recon_group.add_argument('--wayback', action='store_true', help='Check Wayback Machine URLs')
        recon_group.add_argument('--shodan', action='store_true', help='Query Shodan for information')
        recon_group.add_argument('--shodan-key', help='Shodan API key (required for --shodan)')
        
        threat_group = parser.add_argument_group('Threat Intelligence')
        threat_group.add_argument('--reputation', action='store_true', help='Check domain reputation')
        threat_group.add_argument('--typosquatting', action='store_true', help='Check for typosquatting domains')
        threat_group.add_argument('--waf', action='store_true', help='Detect Web Application Firewall')
        
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument('--output', help='Save results to file (JSON format)')
        output_group.add_argument('--all', action='store_true', help='Run all available checks')

        args = parser.parse_args()

        # Validate domain
        if not is_valid_domain(args.domain):
            raise ValidationError(f"Invalid domain name: {args.domain}")

        # Print banner
        print_banner()
        print("\nA Comprehensive Domain Intelligence Tool")
        print("="*60 + "\n")

        # Determine which checks to run
        checks = []
        if args.all:
            checks = ['DNS', 'SSL', 'IP', 'SSL Security', 'HTTP Security', 
                     'Email Security', 'DNSSEC', 'Subdomains', 'Headers', 
                     'Wayback', 'Shodan', 'Reputation', 'Typosquatting', 'WAF']
        else:
            if args.dns: checks.append('DNS')
            if args.ssl: checks.append('SSL')
            if args.ip: checks.append('IP')
            if args.ssl_security: checks.append('SSL Security')
            if args.http_security: checks.append('HTTP Security')
            if args.email_security: checks.append('Email Security')
            if args.dnssec: checks.append('DNSSEC')
            if args.subdomains: checks.append('Subdomains')
            if args.headers: checks.append('Headers')
            if args.wayback: checks.append('Wayback')
            if args.shodan: checks.append('Shodan')
            if args.reputation: checks.append('Reputation')
            if args.typosquatting: checks.append('Typosquatting')
            if args.waf: checks.append('WAF')

        if not checks:
            print("No checks selected. Use --help to see available options.")
            return

        results = {}

        # Initialize progress bar
        total_tasks = len(checks)
        progress_bar = tqdm(total=total_tasks, desc="Analyzing", ascii=True, ncols=100, 
                          bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]')
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            # Submit tasks
            for section in checks:
                if section == 'DNS':
                    futures.append((executor.submit(get_dns_records, args.domain), section))
                elif section == 'SSL':
                    futures.append((executor.submit(fetch_ssl, args.domain), section))
                elif section == 'IP':
                    futures.append((executor.submit(fetch_ip_info, args.domain), section))
                elif section == 'SSL Security':
                    futures.append((executor.submit(analyze_ssl_security, args.domain), section))
                elif section == 'HTTP Security':
                    futures.append((executor.submit(analyze_http_security, args.domain), section))
                elif section == 'Email Security':
                    futures.append((executor.submit(check_email_security, args.domain), section))
                elif section == 'DNSSEC':
                    futures.append((executor.submit(check_dnssec, args.domain), section))
                elif section == 'Subdomains':
                    futures.append((executor.submit(enumerate_subdomains, args.domain), section))
                elif section == 'Headers':
                    futures.append((executor.submit(detect_technologies, args.domain), section))
                elif section == 'Wayback':
                    futures.append((executor.submit(get_wayback_urls, args.domain), section))
                elif section == 'Shodan':
                    futures.append((executor.submit(check_shodan, args.domain, args.shodan_key), section))
                elif section == 'Reputation':
                    futures.append((executor.submit(check_reputation, args.domain), section))
                elif section == 'Typosquatting':
                    futures.append((executor.submit(check_typosquatting, args.domain), section))
                elif section == 'WAF':
                    futures.append((executor.submit(check_waf, args.domain), section))
            
            # Process results as they complete
            for future, section in futures:
                try:
                    result = future.result()
                    results[section] = result
                    progress_bar.update(1)  # Update progress
                    progress_bar.refresh()  # Force refresh of the progress bar
                    print("\n" + "="*50)  # Add spacing between sections
                    print_section_header(section)
                    print_result(section, result)
                except Exception as e:
                    results[section] = {"error": str(e)}
                    progress_bar.update(1)
                    progress_bar.refresh()
                    print("\n" + "="*50)
                    print_section_header(section)
                    print_result(section, {"error": str(e)})
        
        progress_bar.close()
        
        # Save results if output file specified
        if args.output:
            save_to_file(args.output, json.dumps(results, indent=2))
            
    except Exception as e:
        log_error(e)
        return 1
    
    return 0

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        log_error(e, "CRITICAL")
        sys.exit(1)
