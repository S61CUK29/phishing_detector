# phishing_detector

URL Phishing Analyzer
A Python script that analyzes URLs for common phishing indicators and provides a risk assessment.

Features
Detects multiple phishing indicators including:

Long URLs

IP address domains

Missing HTTPS

Excessive subdomains

Newly registered domains

Suspicious keywords in domains

URL shortening services

Provides a weighted phishing score

Gives detailed warnings about detected issues

Works with both complete URLs and domain names

Requirements
Python 3.6+

Required packages:

requests

python-whois

tldextract

Installation
Clone the repository:

bash
git clone https://github.com/yourusername/url-phishing-analyzer.git
cd url-phishing-analyzer
Install required packages:

bash
pip install -r requirements.txt
Or install them manually:

bash
pip install python-whois tldextract requests
Usage
Command Line
Run the script with test URLs:

bash
python url_phishing_analyzer.py
As a Module
Import and use the analyzer in your own Python code:

python
from url_phishing_analyzer import analyze_url

result = analyze_url("https://example.com")
print(result)
Interpretation of Results
Score: A weighted sum of detected phishing indicators

0-2: Probably safe

3+: Likely phishing

Warnings: Specific issues detected in the URL

Domain Age: Newer domains (especially <1 year) are more suspicious

Example Output
text
==================================================
Analyzing URL: http://142.250.190.78.login.security-update.com

Domain: 142.250.190.78.login.security-update.com
URL Length: 52 characters

[!] Warnings:
  - URL uses an IP address instead of a domain
  - Multiple subdomains (142.250.190.78.login)
  - Suspicious keywords in domain: login, security, update

Phishing Score: 4/10
Verdict: LIKELY PHISHING
==================================================
Limitations
WHOIS lookups may fail for some domains

Some legitimate services use URL shorteners

New domains aren't always malicious

The script doesn't actually visit the URLs (no content analysis)

Contributing
Contributions are welcome! Please open an issue or pull request for any improvements.

License
MIT License
