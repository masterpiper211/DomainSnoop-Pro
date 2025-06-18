from flask import Flask, render_template, request
import domainsnoop_pro  # or 'import domainsnoop-pro' if your Python supports it

SCAN_OPTIONS = [
    ('dns', 'DNS Records'),
    ('ssl', 'SSL Certificate'),
    ('ip', 'IP Information'),
    ('ssl_security', 'SSL Security'),
    ('http_security', 'HTTP Security'),
    ('email_security', 'Email Security'),
    ('dnssec', 'DNSSEC'),
    ('subdomains', 'Subdomains'),
    ('headers', 'HTTP Headers'),
    ('wayback', 'Wayback URLs'),
    ('shodan', 'Shodan'),
    ('reputation', 'Reputation'),
    ('typosquatting', 'Typosquatting'),
    ('waf', 'Web Application Firewall'),
]

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    results = {}
    error = None
    if request.method == 'POST':
        domain = request.form['domain']
        selected_checks = request.form.getlist('checks')
        shodan_key = request.form.get('shodan_key', None)
        if not domainsnoop_pro.is_valid_domain(domain):
            error = "Invalid domain."
        else:
            try:
                if 'dns' in selected_checks:
                    results['DNS'] = domainsnoop_pro.get_dns_records(domain)
                if 'ssl' in selected_checks:
                    results['SSL'] = domainsnoop_pro.fetch_ssl(domain)
                if 'ip' in selected_checks:
                    results['IP'] = domainsnoop_pro.fetch_ip_info(domain)
                if 'ssl_security' in selected_checks:
                    results['SSL Security'] = domainsnoop_pro.analyze_ssl_security(domain)
                if 'http_security' in selected_checks:
                    results['HTTP Security'] = domainsnoop_pro.analyze_http_security(domain)
                if 'email_security' in selected_checks:
                    results['Email Security'] = domainsnoop_pro.check_email_security(domain)
                if 'dnssec' in selected_checks:
                    results['DNSSEC'] = domainsnoop_pro.check_dnssec(domain)
                if 'subdomains' in selected_checks:
                    results['Subdomains'] = domainsnoop_pro.enumerate_subdomains(domain)
                if 'headers' in selected_checks:
                    results['Headers'] = domainsnoop_pro.detect_technologies(domain)
                if 'wayback' in selected_checks:
                    results['Wayback'] = domainsnoop_pro.get_wayback_urls(domain)
                if 'shodan' in selected_checks:
                    results['Shodan'] = domainsnoop_pro.check_shodan(domain, shodan_key)
                if 'reputation' in selected_checks:
                    results['Reputation'] = domainsnoop_pro.check_reputation(domain)
                if 'typosquatting' in selected_checks:
                    results['Typosquatting'] = domainsnoop_pro.check_typosquatting(domain)
                if 'waf' in selected_checks:
                    results['WAF'] = domainsnoop_pro.check_waf(domain)
            except Exception as e:
                error = str(e)
    return render_template('index.html', scan_options=SCAN_OPTIONS, results=results, error=error)

def run():
    app.run(debug=True, port=5000)

if __name__ == "__main__":
    run()