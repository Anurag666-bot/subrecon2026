"""
Passive sources module for SubRecon 2026.
"""
import asyncio
import json
import re
from typing import Set
from ..config import KEYS


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