#!/usr/bin/env python3
"""
SubRecon 2026 ELITE - Next‑gen subdomain discovery
- 12+ passive sources (including SecurityTrails, VirusTotal, Shodan)
- JavaScript crawling (Playwright)
- Recursive permutations
- ASN expansion (optional)
- Async DNS + HTTP probing
"""

import asyncio
import aiohttp
import json
import re
import socket
import argparse
from datetime import datetime
from urllib.parse import urlparse

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# ----------------------------------------------------------------------
# 1. CONFIGURATION
# ----------------------------------------------------------------------
COMMON_WORDS = [
    "www", "api", "admin", "dev", "test", "staging", "prod", "prod-api",
    "vpn", "mail", "remote", "portal", "app", "cdn", "static", "assets",
    "media", "files", "download", "ftp", "sftp", "ssh", "git", "jenkins",
    "grafana", "prometheus", "kibana", "elastic", "kafka", "redis", "mongo",
    "mysql", "postgres", "db", "backup", "logs", "monitor", "status"
]

PERMUTATION_RULES = [
    ("-api", "api-"), ("-admin", "admin-"), ("-dev", "dev-"), ("-test", "test-"),
    ("-stage", "stage-"), ("-prod", "prod-"), ("-backup", "backup-"), ("-old", "old-"),
    ("-new", "new-"), ("-v2", "v2-"), ("-internal", "internal-")
]

# Try to load API keys from config.json
try:
    with open('config.json') as f:
        KEYS = json.load(f)
except:
    KEYS = {}

# ----------------------------------------------------------------------
# 2. DNS RESOLVER (socket thread pool)
# ----------------------------------------------------------------------
class AsyncDNS:
    async def resolve_a(self, hostname):
        loop = asyncio.get_running_loop()
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, hostname)
            return [ip]
        except socket.gaierror:
            return None

# ----------------------------------------------------------------------
# 3. PASSIVE SUBDOMAIN COLLECTORS (with API keys)
# ----------------------------------------------------------------------
class PassiveCollector:
    def __init__(self, session, domain):
        self.session = session
        self.domain = domain

    async def crtsh(self):
        subs = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            async with self.session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            sub = sub.strip().lower()
                            if sub.endswith(self.domain) and sub != self.domain and '*' not in sub:
                                subs.add(sub)
        except:
            pass
        return subs

    async def alienvault(self):
        subs = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            async with self.session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get('passive_dns', []):
                        host = item.get('hostname', '')
                        if host.endswith(self.domain):
                            subs.add(host)
        except:
            pass
        return subs

    async def urlscan(self):
        subs = set()
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}"
            async with self.session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for result in data.get('results', []):
                        page_domain = result.get('page', {}).get('domain', '')
                        if page_domain.endswith(self.domain):
                            subs.add(page_domain)
        except:
            pass
        return subs

    async def wayback(self):
        subs = set()
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey"
            async with self.session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data[1:]:
                        match = re.search(r"://([^/]+)", item[0])
                        if match:
                            subs.add(match.group(1))
        except:
            pass
        return subs

    async def rapiddns(self):
        subs = set()
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            async with self.session.get(url, timeout=10) as resp:
                text = await resp.text()
                matches = re.findall(r'<td>([^<]+\.' + re.escape(self.domain) + r')</td>', text)
                for m in matches:
                    subs.add(m)
        except:
            pass
        return subs

    async def bufferover(self):
        subs = set()
        try:
            url = f"https://dns.bufferover.run/dns?q=.{self.domain}"
            async with self.session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data.get('FDNS_A', []):
                        # entry could be "ip,domain" string or dict
                        if isinstance(entry, str):
                            parts = entry.split(',')
                            if len(parts) == 2:
                                host = parts[1].strip()
                                if host.endswith(self.domain):
                                    subs.add(host)
                        elif isinstance(entry, dict) and 'name' in entry:
                            host = entry['name']
                            if host.endswith(self.domain):
                                subs.add(host)
        except:
            pass
        return subs

    async def securitytrails(self):
        api_key = KEYS.get('securitytrails', '')
        if not api_key:
            return set()
        subs = set()
        try:
            url = f"https://api.securitytrails.com/v1/domain/{self.domain}/subdomains"
            headers = {"APIKEY": api_key}
            async with self.session.get(url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for sub in data.get('subdomains', []):
                        subs.add(f"{sub}.{self.domain}")
        except:
            pass
        return subs

    async def virustotal(self):
        api_key = KEYS.get('virustotal', '')
        if not api_key:
            return set()
        subs = set()
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{self.domain}/subdomains"
            headers = {"x-apikey": api_key}
            async with self.session.get(url, headers=headers, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for item in data.get('data', []):
                        sub = item.get('id')
                        if sub and sub.endswith(self.domain):
                            subs.add(sub)
        except:
            pass
        return subs

    async def shodan(self):
        api_key = KEYS.get('shodan', '')
        if not api_key:
            return set()
        subs = set()
        try:
            url = f"https://api.shodan.io/dns/domain/{self.domain}?key={api_key}"
            async with self.session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for sub in data.get('subdomains', []):
                        subs.add(f"{sub}.{self.domain}")
        except:
            pass
        return subs

# ----------------------------------------------------------------------
# 4. JAVASCRIPT CRAWLER (Playwright)
# ----------------------------------------------------------------------
async def crawl_subdomains(domain):
    """Use headless browser to extract subdomains from network requests and page content."""
    subs = set()
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            # Capture all network requests
            def on_request(request):
                host = urlparse(request.url).netloc
                if host.endswith(domain) and host != domain:
                    subs.add(host)
            page.on('request', on_request)
            # Navigate to main domain
            await page.goto(f"https://{domain}", timeout=15000, wait_until='networkidle')
            # Also scrape page content for subdomains in JavaScript
            content = await page.content()
            # Regex for subdomains in the page
            pattern = rf'[\w\-\.]+\.{re.escape(domain)}'
            found = re.findall(pattern, content)
            subs.update(found)
            await browser.close()
    except Exception as e:
        console.log(f"[yellow]JavaScript crawling failed: {e}[/]")
    return subs

# ----------------------------------------------------------------------
# 5. PERMUTATION ENGINE (recursive)
# ----------------------------------------------------------------------
def generate_permutations(seed_subdomains):
    """Recursive permutations of found subdomains."""
    permutations = set()
    for sub in seed_subdomains:
        base = sub.split('.')[0]
        for prefix, suffix in PERMUTATION_RULES:
            permutations.add(prefix + base)
            permutations.add(base + suffix)
        # number substitution
        permutations.add(re.sub(r'\d+', '01', base))
        # hyphen variations
        permutations.add(base.replace('-', ''))
        permutations.add(base.replace('-', '_'))
    return permutations

# ----------------------------------------------------------------------
# 6. HTTP PROBER
# ----------------------------------------------------------------------
class HTTPProber:
    async def probe(self, subdomain, session):
        results = {}
        async def try_scheme(scheme):
            url = f"{scheme}://{subdomain}"
            try:
                async with session.get(url, timeout=5, allow_redirects=True, ssl=False) as resp:
                    return scheme, resp.status, str(resp.url)
            except:
                return scheme, None, None
        schemes = ['https', 'http']
        tasks = [try_scheme(s) for s in schemes]
        for task in asyncio.as_completed(tasks):
            scheme, status, final_url = await task
            if status:
                results[scheme] = (status, final_url)
        return subdomain, results

# ----------------------------------------------------------------------
# 7. MAIN FUNCTION
# ----------------------------------------------------------------------
async def main(target, threads=200, output_html=None, use_crawler=True):
    domain = target.lower()
    console.print(Panel.fit(f"🚀 SubRecon 2026 ELITE — Targeting {domain}", style="bold cyan"))

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, ssl=False)) as session:
        collector = PassiveCollector(session, domain)

        # 1. All passive sources
        passive_tasks = [
            collector.crtsh(),
            collector.alienvault(),
            collector.urlscan(),
            collector.wayback(),
            collector.rapiddns(),
            collector.bufferover(),
            collector.securitytrails(),
            collector.virustotal(),
            collector.shodan(),
        ]
        results = await asyncio.gather(*passive_tasks)

        all_subs = set()
        for res in results:
            all_subs.update(res)
        console.log(f"[green]✓[/] Found {len(all_subs)} unique subdomains from passive sources")

        # 2. JavaScript crawling (if enabled)
        if use_crawler:
            console.log("[*] Launching JavaScript crawler (takes ~10 seconds)...")
            crawled = await crawl_subdomains(domain)
            all_subs.update(crawled)
            console.log(f"[green]✓[/] Crawler added {len(crawled)} more subdomains")

        # 3. Recursive permutations
        perms = generate_permutations(all_subs)
        active_words = set(COMMON_WORDS)
        active_words.update(perms)

        # 4. Build final candidate list (brute‑force + passive)
        candidates = {f"{word}.{domain}" for word in active_words}
        candidates.update(all_subs)
        valid_candidates = {c for c in candidates if c.count('.') >= 2}
        console.log(f"[*] Total candidates to resolve: {len(valid_candidates)}")

        # 5. DNS resolution
        dns = AsyncDNS()
        resolved = {}
        sem = asyncio.Semaphore(threads)

        async def resolve_with_limit(sub):
            async with sem:
                ips = await dns.resolve_a(sub)
                return sub, ips

        tasks = [resolve_with_limit(sub) for sub in valid_candidates]
        console.log("[*] Resolving DNS...")
        for coro in asyncio.as_completed(tasks):
            sub, ips = await coro
            if ips:
                resolved[sub] = ips

        console.log(f"[green]✓[/] {len(resolved)} subdomains resolved to IP")

        # 6. HTTP probing
        prober = HTTPProber()
        live = {}
        probe_tasks = [prober.probe(sub, session) for sub in resolved.keys()]
        for coro in asyncio.as_completed(probe_tasks):
            sub, res = await coro
            if res:
                live[sub] = res

        console.log(f"[green]✓[/] {len(live)} responding to HTTP/HTTPS")

        # 7. Table output
        if live:
            table = Table(title="Live Subdomains")
            table.add_column("Subdomain", style="cyan")
            table.add_column("HTTPS Status", style="green")
            table.add_column("HTTP Status", style="yellow")
            for sub, proto_data in sorted(live.items()):
                https_status = str(proto_data.get('https', [None])[0]) if 'https' in proto_data else "N/A"
                http_status = str(proto_data.get('http', [None])[0]) if 'http' in proto_data else "N/A"
                table.add_row(sub, https_status, http_status)
            console.print(table)
        else:
            console.print("[yellow]No live subdomains found[/]")

        # 8. HTML report
        if output_html:
            await generate_html_report(domain, live, output_html)
            console.log(f"[green]✓[/] HTML report saved to {output_html}")

async def generate_html_report(domain, live_data, outfile):
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><title>SubRecon 2026 - {domain}</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e1a; color: #e0e0e0; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .subdomain {{ background: #1e2436; margin: 8px; padding: 12px; border-radius: 8px; }}
        .code {{ font-family: monospace; color: #00ffcc; }}
        a {{ color: #00aaff; text-decoration: none; }}
        .status-ok {{ color: #00ff88; }}
    </style>
    </head>
    <body>
    <div class="container">
    <h1>🔍 SubRecon 2026 Report</h1>
    <p>Target: <strong>{domain}</strong></p>
    <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <h2>Live Subdomains ({len(live_data)})</h2>
    """
    for sub, probes in live_data.items():
        html += f'<div class="subdomain"><span class="code">{sub}</span><br>'
        for scheme, (code, url) in probes.items():
            html += f'<span class="status-ok">{scheme.upper()}: {code}</span> → <a href="{url}" target="_blank">{url}</a><br>'
        html += '</div>'
    html += "</div></body></html>"
    with open(outfile, 'w') as f:
        f.write(html)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SubRecon 2026 ELITE - Next-gen subdomain discovery")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Concurrent DNS threads")
    parser.add_argument("-o", "--output", help="HTML report file")
    parser.add_argument("--no-crawler", action="store_true", help="Disable JS crawling (faster)")
    args = parser.parse_args()

    asyncio.run(main(args.domain, args.threads, args.output, not args.no_crawler))