# SubRecon 2026 ELITE

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey)](https://github.com/Anurag666-bot/subrecon2026)

**SubRecon 2026** is a next‑generation subdomain discovery tool built for bug bounty hunters and security researchers. It combines **15+ passive sources**, **JavaScript crawling**, **intelligent permutations**, and **async DNS probing** to find subdomains that traditional tools miss.

## ✨ Features

| Category | Details |
|----------|---------|
| **Passive Sources** | crt.sh, AlienVault OTX, SecurityTrails, VirusTotal, Shodan, Chaos Project, Anubis, ThreatCrowd, BufferOver, URLScan, Wayback Machine, RapidDNS |
| **Active Techniques** | Recursive permutations, JS crawling (Playwright), massive wordlist brute‑force |
| **Performance** | Fully async I/O, thread‑pool DNS resolution (no `aiodns` issues) |
| **Output** | Live subdomain table with HTTP/HTTPS status, HTML report, resolved subdomain list |
| **Extensible** | Easy to add new sources or API keys |

## 🚀 Quick Start

### Prerequisites
- Python 3.9+
- `pip` and `venv`

### Installation

```bash
git clone https://github.com/Anurag666-bot/subrecon2026.git
cd subrecon2026
python3 -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install aiohttp rich playwright
playwright install chromium
```


Basic Usage
```
python subrecon_elite.py example.com
```

Advanced Usage
```
python subrecon_elite.py hackerone.com -t 300 -o report.html --no-crawler
```
Option	Description
-t, --threads	Number of concurrent DNS resolutions (default: 200)
-o, --output	Generate an HTML report
--no-crawler	Disable JavaScript crawling (faster, fewer results)


```

🔑 API Keys (Optional)

To enable premium sources (SecurityTrails, VirusTotal, Shodan), create a config.json file in the same directory:

{
    "securitytrails": "your_api_key_here",
    "virustotal": "your_api_key_here",
    "shodan": "your_api_key_here"
}

```
You can get free API keys from:

    SecurityTrails – 50 requests/month free

    VirusTotal – 500 requests/day free

    Shodan – free tier with limitations

🚀 SubRecon 2026 ELITE — Targeting hackerone.com

✓ Found 147 unique subdomains from passive sources
[*] Launching JS crawler (30s timeout)...
✓ Crawler added 23 more
[*] Total candidates to resolve: 2391
[*] Resolving DNS...
✓ 312 subdomains resolved to IP
✓ 189 live web servers

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ Subdomain                   ┃ HTTPS Status ┃ HTTP Status ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ api.hackerone.com           │ 200          │ 200         │
│ docs.hackerone.com          │ 200          │ 200         │
│ mta-sts.hackerone.com       │ 404          │ 404         │
│ www.hackerone.com           │ 200          │ 200         │
└──────────────────────────────┴──────────────┴─────────────┘


🗂️ Output Files
File	Content
{domain}_resolved.txt	All subdomains that resolved to an IP (even if no web server)
report.html (if -o used)	Interactive HTML report with clickable URLs
config.json	Your API keys (never committed to Git)

🛠️ Troubleshooting
Problem	Solution
ModuleNotFoundError	Run pip install -r requirements.txt or manually install missing modules
DNS resolution returns 0	Your system DNS works (we use socket.gethostbyname), but target may have rate limiting – try a different domain
JS crawler timeout	Increase timeout in crawl_subdomains() or use --no-crawler
GitHub push failed (large file)	Never commit venv/ – our .gitignore excludes it. Follow the cleanup steps in the repo’s wiki.

📦 Requirements


aiohttp>=3.8.0
rich>=13.0.0
playwright>=1.40.0

🧠 How It Works

    Passive Collection – Queries 15+ APIs/datasets for known subdomains.

    JS Crawling – Launches headless Chromium to extract subdomains from network requests and inline JavaScript.

    Permutation Engine – Mutates existing subdomains (e.g., admin → admin-api, admin-stage).

    DNS Resolution – Uses Python’s socket.gethostbyname in a thread pool (fast and reliable).

    HTTP Probing – Checks both HTTPS and HTTP, follows redirects, records status codes.

    Reporting – Prints a table, saves resolved list, and optionally generates an HTML report.

👤 Author

Anurag Kumar Das

    GitHub: @Anurag666-bot

    Project Link: https://github.com/Anurag666-bot/subrecon2026


✓ Saved 312 resolved subdomains to hackerone.com_resolved.txt
✓ HTML report saved to report.html
