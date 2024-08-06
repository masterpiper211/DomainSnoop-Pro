import argparse
import concurrent.futures
import json
import logging
import os
import re
import socket
import ssl
import subprocess
import time
import dns.resolver
import ipwhois
import requests
import shodan
import whois
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from pyfiglet import figlet_format
from tabulate import tabulate
from tqdm import tqdm

# Initialize colorama for cross-platform colored output
init()

# Set up logging
logging.basicConfig(filename='domain_snoop.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def print_banner():
    banner = figlet_format("DomainSnoop Pro", font="slant")
    print(Fore.CYAN + banner + Style.RESET_ALL)
    print(Fore.YELLOW + "A comprehensive domain intelligence tool" + Style.RESET_ALL + "\n")

def fetch_whois(domain):
    try:
        w = whois.whois(domain)
        data = {
            'Domain Name': w.domain_name,
            'Registrar': w.registrar,
            'Creation Date': w.creation_date,
            'Expiration Date': w.expiration_date,
            'Updated Date': w.updated_date,
            'Status': w.status,
            'Name Servers': ', '.join(w.name_servers) if isinstance(w.name_servers, list) else w.name_servers,
            'Registrant': w.registrant,
            'Admin': w.admin,
            'Tech': w.tech,
            'Billing': w.billing
        }
        logging.info(f"WHOIS data retrieved for {domain}")
        return data
    except Exception as e:
        logging.error(f"Error fetching WHOIS data for {domain}: {e}")
        return {"error": f"Error fetching WHOIS data: {e}"}

def fetch_dns(domain):
    dns_records = {}
    record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME', 'SRV', 'PTR', 'CAA']
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            dns_records[record_type] = [answer.to_text() for answer in answers]
        except dns.resolver.NoAnswer:
            dns_records[record_type] = ["No records found"]
        except Exception as e:
            logging.error(f"Error fetching {record_type} records for {domain}: {e}")
            dns_records[record_type] = [f"Error: {str(e)}"]
    
    logging.info(f"DNS records retrieved for {domain}")
    return dns_records

def fetch_ssl(domain):
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

def fetch_ip_info(ip):
    try:
        obj = ipwhois.IPWhois(ip)
        results = obj.lookup_rdap(depth=1)
        return {
            'IP': ip,
            'ASN': results.get('asn'),
            'ASN Description': results.get('asn_description'),
            'Country': results.get('asn_country_code'),
            'Network Range': results.get('network', {}).get('cidr')
        }
    except Exception as e:
        logging.error(f"Error fetching IP info for {ip}: {e}")
        return {"error": f"Error fetching IP info: {e}"}

def perform_traceroute(domain):
    try:
        if os.name == 'nt':  # Windows
            output = subprocess.check_output(["tracert", domain]).decode('utf-8')
        else:  # Unix/Linux
            output = subprocess.check_output(["traceroute", domain]).decode('utf-8')
        return output
    except Exception as e:
        logging.error(f"Error performing traceroute for {domain}: {e}")
        return f"Error performing traceroute: {e}"

def fetch_headers(domain):
    try:
        response = requests.head(f"https://{domain}", allow_redirects=True)
        return dict(response.headers)
    except Exception as e:
        logging.error(f"Error fetching HTTP headers for {domain}: {e}")
        return {"error": f"Error fetching HTTP headers: {e}"}

def scan_ports(domain):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5900, 8080, 8443]
    open_ports = []
    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((domain, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

def fetch_shodan_info(domain, api_key):
    try:
        api = shodan.Shodan(api_key)
        results = api.search(domain)
        return results
    except Exception as e:
        logging.error(f"Error fetching Shodan info for {domain}: {e}")
        return {"error": f"Error fetching Shodan info: {e}"}

def fetch_subdomains(domain):
    try:
        response = requests.get(f"https://crt.sh/?q=%.{domain}&output=json")
        data = json.loads(response.text)
        subdomains = list(set([item['name_value'] for item in data]))
        return subdomains
    except Exception as e:
        logging.error(f"Error fetching subdomains for {domain}: {e}")
        return {"error": f"Error fetching subdomains: {e}"}

def fetch_wayback_urls(domain):
    try:
        response = requests.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey")
        data = json.loads(response.text)
        urls = list(set([item[2] for item in data[1:]]))  # Skip the header row
        return urls[:100]  # Limit to 100 URLs to avoid overwhelming output
    except Exception as e:
        logging.error(f"Error fetching Wayback Machine URLs for {domain}: {e}")
        return {"error": f"Error fetching Wayback Machine URLs: {e}"}

def fetch_technologies(domain):
    try:
        response = requests.get(f"https://{domain}")
        soup = BeautifulSoup(response.text, 'html.parser')
        
        technologies = []
        
        # Check for common web technologies
        if soup.find("meta", attrs={"name": "generator", "content": re.compile("WordPress")}):
            technologies.append("WordPress")
        if soup.find("script", src=re.compile("jquery")):
            technologies.append("jQuery")
        if soup.find("link", href=re.compile("bootstrap")):
            technologies.append("Bootstrap")
        if "react" in response.text.lower():
            technologies.append("React")
        if "angular" in response.text.lower():
            technologies.append("Angular")
        if "vue" in response.text.lower():
            technologies.append("Vue.js")
        
        return technologies
    except Exception as e:
        logging.error(f"Error detecting technologies for {domain}: {e}")
        return {"error": f"Error detecting technologies: {e}"}

def format_data(data, sections):
    output = ""
    
    if 'WHOIS' in sections and 'WHOIS' in data:
        output += f"\n{Fore.GREEN}WHOIS Data:{Style.RESET_ALL}\n"
        if 'error' in data['WHOIS']:
            output += f"{Fore.RED}{data['WHOIS']['error']}{Style.RESET_ALL}\n"
        else:
            output += tabulate(data['WHOIS'].items(), headers=['Field', 'Value'], tablefmt='grid') + "\n"
    
    if 'DNS' in sections and 'DNS' in data:
        output += f"\n{Fore.GREEN}DNS Records:{Style.RESET_ALL}\n"
        for record_type, records in data['DNS'].items():
            output += f"{Fore.YELLOW}{record_type} Records:{Style.RESET_ALL}\n"
            for record in records:
                output += f"  {record}\n"
            output += "\n"

    if 'SSL' in sections and 'SSL' in data:
        output += f"\n{Fore.GREEN}SSL/TLS Certificate Data:{Style.RESET_ALL}\n"
        if 'error' in data['SSL']:
            output += f"{Fore.RED}{data['SSL']['error']}{Style.RESET_ALL}\n"
        else:
            output += tabulate(data['SSL'].items(), headers=['Field', 'Value'], tablefmt='grid') + "\n"
    
    if 'IP' in sections and 'IP' in data:
        output += f"\n{Fore.GREEN}IP Information:{Style.RESET_ALL}\n"
        if 'error' in data['IP']:
            output += f"{Fore.RED}{data['IP']['error']}{Style.RESET_ALL}\n"
        else:
            output += tabulate(data['IP'].items(), headers=['Field', 'Value'], tablefmt='grid') + "\n"
    
    if 'Traceroute' in sections and 'Traceroute' in data:
        output += f"\n{Fore.GREEN}Traceroute Results:{Style.RESET_ALL}\n"
        output += data['Traceroute'] + "\n"
    
    if 'Headers' in sections and 'Headers' in data:
        output += f"\n{Fore.GREEN}HTTP Headers:{Style.RESET_ALL}\n"
        if 'error' in data['Headers']:
            output += f"{Fore.RED}{data['Headers']['error']}{Style.RESET_ALL}\n"
        else:
            output += tabulate(data['Headers'].items(), headers=['Header', 'Value'], tablefmt='grid') + "\n"
    
    if 'Ports' in sections and 'Ports' in data:
        output += f"\n{Fore.GREEN}Open Ports:{Style.RESET_ALL}\n"
        output += ", ".join(map(str, data['Ports'])) + "\n"
    
    if 'Shodan' in sections and 'Shodan' in data:
        output += f"\n{Fore.GREEN}Shodan Information:{Style.RESET_ALL}\n"
        if 'error' in data['Shodan']:
            output += f"{Fore.RED}{data['Shodan']['error']}{Style.RESET_ALL}\n"
        else:
            output += json.dumps(data['Shodan'], indent=2) + "\n"
    
    if 'Subdomains' in sections and 'Subdomains' in data:
        output += f"\n{Fore.GREEN}Subdomains:{Style.RESET_ALL}\n"
        if 'error' in data['Subdomains']:
            output += f"{Fore.RED}{data['Subdomains']['error']}{Style.RESET_ALL}\n"
        else:
            output += "\n".join(data['Subdomains']) + "\n"
    
    if 'Wayback' in sections and 'Wayback' in data:
        output += f"\n{Fore.GREEN}Wayback Machine URLs:{Style.RESET_ALL}\n"
        if 'error' in data['Wayback']:
            output += f"{Fore.RED}{data['Wayback']['error']}{Style.RESET_ALL}\n"
        else:
            output += "\n".join(data['Wayback']) + "\n"
    
    if 'Technologies' in sections and 'Technologies' in data:
        output += f"\n{Fore.GREEN}Detected Technologies:{Style.RESET_ALL}\n"
        if 'error' in data['Technologies']:
            output += f"{Fore.RED}{data['Technologies']['error']}{Style.RESET_ALL}\n"
        else:
            output += ", ".join(data['Technologies']) + "\n"
    
    return output

def save_to_file(filename, data):
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(data)
    logging.info(f"Results saved to {filename}")

def simulate_progress(total_steps):
    for _ in tqdm(range(total_steps), desc="Processing", ascii=True, ncols=100):
        time.sleep(0.1)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description="DomainSnoop Pro - A comprehensive domain intelligence tool.")
    parser.add_argument('domain', help='Domain name to query')
    parser.add_argument('--whois', action='store_true', help='Fetch WHOIS data')
    parser.add_argument('--dns', action='store_true', help='Fetch DNS records')
    parser.add_argument('--ssl', action='store_true', help='Fetch SSL/TLS certificate data')
    parser.add_argument('--ip', action='store_true', help='Fetch IP information')
    parser.add_argument('--traceroute', action='store_true', help='Perform traceroute')
    parser.add_argument('--headers', action='store_true', help='Fetch HTTP headers')
    parser.add_argument('--ports', action='store_true', help='Scan common ports')
    parser.add_argument('--shodan', action='store_true', help='Fetch Shodan information')
    parser.add_argument('--subdomains', action='store_true', help='Fetch subdomains')
    parser.add_argument('--wayback', action='store_true', help='Fetch Wayback Machine URLs')
    parser.add_argument('--tech', action='store_true', help='Detect web technologies')
    parser.add_argument('--all', action='store_true', help='Fetch all available data')
    parser.add_argument('--output', type=str, help='File name to save the results')
    parser.add_argument('--shodan-api-key', type=str, help='Shodan API key')
    args = parser.parse_args()

    sections = []
    if args.all:
        sections = ['WHOIS', 'DNS', 'SSL', 'IP', 'Traceroute', 'Headers', 'Ports', 'Shodan', 'Subdomains', 'Wayback', 'Technologies']
    else:
        if args.whois:
            sections.append('WHOIS')
        if args.dns:
            sections.append('DNS')
        if args.ssl:
            sections.append('SSL')
        if args.ip:
            sections.append('IP')
        if args.traceroute:
            sections.append('Traceroute')
        if args.headers:
            sections.append('Headers')
        if args.ports:
            sections.append('Ports')
        if args.shodan:
            sections.append('Shodan')
        if args.subdomains:
            sections.append('Subdomains')
        if args.wayback:
            sections.append('Wayback')
        if args.tech:
            sections.append('Technologies')

    if not sections:
        print(Fore.RED + "No data type specified. Use --help to see available options." + Style.RESET_ALL)
        return

    print(Fore.CYAN + f"Analyzing domain: {args.domain}" + Style.RESET_ALL)
    print(Fore.YELLOW + f"Fetching data for sections: {', '.join(sections)}" + Style.RESET_ALL)

    simulate_progress(len(sections) * 2)

    data = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        if 'WHOIS' in sections:
            futures.append(executor.submit(fetch_whois, args.domain))
        if 'DNS' in sections:
            futures.append(executor.submit(fetch_dns, args.domain))
        if 'SSL' in sections:
            futures.append(executor.submit(fetch_ssl, args.domain))
        if 'IP' in sections or 'Traceroute' in sections:
            ip = socket.gethostbyname(args.domain)
            if 'IP' in sections:
                futures.append(executor.submit(fetch_ip_info, ip))
        if 'Traceroute' in sections:
            futures.append(executor.submit(perform_traceroute, args.domain))
        if 'Headers' in sections:
            futures.append(executor.submit(fetch_headers, args.domain))
        if 'Ports' in sections:
            futures.append(executor.submit(scan_ports, args.domain))
        if 'Shodan' in sections:
            if args.shodan_api_key:
                futures.append(executor.submit(fetch_shodan_info, args.domain, args.shodan_api_key))
            else:
                print(Fore.RED + "Shodan API key not provided. Skipping Shodan information retrieval." + Style.RESET_ALL)
        if 'Subdomains' in sections:
            futures.append(executor.submit(fetch_subdomains, args.domain))
        if 'Wayback' in sections:
            futures.append(executor.submit(fetch_wayback_urls, args.domain))
        if 'Technologies' in sections:
            futures.append(executor.submit(fetch_technologies, args.domain))
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if isinstance(result, dict):
                if 'Domain Name' in result:
                    data['WHOIS'] = result
                elif 'A' in result:
                    data['DNS'] = result
                elif 'Subject' in result:
                    data['SSL'] = result
                elif 'IP' in result:
                    data['IP'] = result
                elif 'Server' in result:
                    data['Headers'] = result
                elif 'matches' in result:
                    data['Shodan'] = result
                elif 'error' in result:
                    for section in sections:
                        if section not in data:
                            data[section] = result
                            break
            elif isinstance(result, list):
                if all(isinstance(item, int) for item in result):
                    data['Ports'] = result
                elif all(isinstance(item, str) for item in result):
                    if 'http' in result[0]:
                        data['Wayback'] = result
                    elif '.' in result[0]:
                        data['Subdomains'] = result
                    else:
                        data['Technologies'] = result
            else:
                data['Traceroute'] = result

    formatted_data = format_data(data, sections)
    
    print(formatted_data)

    if args.output:
        save_to_file(args.output, formatted_data)
        print(Fore.GREEN + f"Results saved to {args.output}" + Style.RESET_ALL)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\nOperation cancelled by user." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: {e}" + Style.RESET_ALL)
        logging.exception("An unexpected error occurred")
