"""
JavaScript crawler module for SubRecon 2026.
"""
import asyncio
import re
from urllib.parse import urlparse
from rich.console import Console

console = Console()


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