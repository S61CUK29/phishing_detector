# Import necessary libraries
import requests
from urllib.parse import urlparse
import re
from datetime import datetime
import socket
import ssl
import tldextract
import whois  # Using python-whois package (install with: pip install python-whois)

def analyze_url(url):
    """
    Analyzes a URL for common phishing indicators.
    Args:
        url (str): The URL to check.
    Returns:
        dict: Analysis results with warnings and scores.
    """
    results = {
        'warnings': [],
        'score': 0,
        'is_phishing': False,
        'domain': '',
        'url_length': len(url)
    }

    # === 1. Basic URL Validation ===
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url  # Add scheme if missing

    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        results['domain'] = domain
    except Exception as e:
        results['warnings'].append(f"Invalid URL format: {str(e)}")
        return results

    # === 2. Check URL Length ===
    if len(url) > 75:
        results['warnings'].append("Long URL (phishing sites often use lengthy URLs)")
        results['score'] += 1

    # === 3. Check if domain is an IP address ===
    def is_ip_address(domain_part):
        try:
            socket.inet_aton(domain_part)
            return True
        except (socket.error, ValueError):
            return False

    domain_parts = domain.split('.')
    if len(domain_parts) == 4 and all(part.isdigit() for part in domain_parts):
        results['warnings'].append("URL uses an IP address instead of a domain")
        results['score'] += 2
    elif is_ip_address(domain.split(':')[0]):  # Handle cases with port numbers
        results['warnings'].append("URL uses an IP address instead of a domain")
        results['score'] += 2

    # === 4. Check for HTTPS ===
    if not url.startswith("https://"):
        results['warnings'].append("No HTTPS (phishing sites may avoid SSL certificates)")
        results['score'] += 1

    # === 5. Check for excessive subdomains ===
    extracted = tldextract.extract(url)
    if extracted.subdomain.count('.') > 1:
        results['warnings'].append(f"Multiple subdomains ({extracted.subdomain})")
        results['score'] += 1

    # === 6. Check domain age ===
    try:
        domain_info = whois.whois(extracted.registered_domain)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            age = (datetime.now() - creation_date).days
            results['domain_age_days'] = age
            if age < 365:
                results['warnings'].append(f"Domain is only {age} days old")
                results['score'] += 1
    except Exception as e:
        results['warnings'].append(f"WHOIS lookup failed: {str(e)}")

    # === 7. Check for suspicious keywords in domain ===
    suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify', 'security', 'auth',  'login', 'secure', 'account', 'update', 'verify', 'security', 'auth',
    'paypal', 'google', 'apple', 'ebay', 'bank', 'amazon', 'outlook', 'office']
    found_keywords = [kw for kw in suspicious_keywords if kw in domain.lower()]
    if found_keywords:
        results['warnings'].append(f"Suspicious keywords in domain: {', '.join(found_keywords)}")
        results['score'] += 1

    # === 8. Check for URL shortening services ===
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co']
    if any(shortener in domain for shortener in shorteners):
        results['warnings'].append("URL shortening service detected")
        results['score'] += 1

    # Determine if likely phishing
    if results['score'] >= 3:
        results['is_phishing'] = True

    return results

if __name__ == "__main__":
    # Install required packages if missing
    try:
        import whois
        import tldextract
    except ImportError:
        print("Installing required packages...")
        import subprocess
        subprocess.run(['pip', 'install', 'python-whois', 'tldextract'], check=True)
        import whois
        import tldextract

    test_urls = [
        "http://142.250.190.78.login.security-update.com",
        "https://www.google.com",
        "https://paypal.com.security-login.verify-user.com",
        "http://example.com",
        "https://bit.ly/3xample", 
        "ebayisapidlld.altervista.org/" # URL shortener test
    ]

    for url in test_urls:
        print(f"\n{'='*50}")
        print(f"Analyzing URL: {url}")
        analysis = analyze_url(url)
        
        print(f"\nDomain: {analysis.get('domain', 'N/A')}")
        print(f"URL Length: {analysis.get('url_length', 'N/A')} characters")
        if 'domain_age_days' in analysis:
            print(f"Domain Age: {analysis['domain_age_days']} days")
        
        if analysis['warnings']:
            print("\n[!] Warnings:")
            for warning in analysis['warnings']:
                print(f"  - {warning}")
        
        print(f"\nPhishing Score: {analysis['score']}/10")
        print(f"Verdict: {'LIKELY PHISHING' if analysis['is_phishing'] else 'Probably Safe'}")
        print(f"{'='*50}")

    print("\nAnalysis complete. Scores 3+ indicate likely phishing.")
