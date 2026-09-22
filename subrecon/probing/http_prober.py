"""
HTTP prober module for SubRecon 2026.
"""
import asyncio
from typing import Dict, Tuple, Optional


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