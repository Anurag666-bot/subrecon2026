"""
Command-line interface for SubRecon 2026.
"""
import asyncio
import argparse
import aiohttp
from typing import Optional

from .config import COMMON_WORDS, PERMUTATION_RULES
from .dns.resolver import AsyncDNS
from .sources.passive import PassiveCollector
from .crawler.js_crawler import crawl_subdomains
from .permutation.engine import generate_permutations
from .probing.http_prober import HTTPProber
from .reporting.html_reporter import generate_html_report
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()


async def main(target: str, threads: int = 200, output_html: Optional[str] = None, use_crawler: bool = True):
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SubRecon 2026 ELITE - Next-gen subdomain discovery")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Concurrent DNS threads")
    parser.add_argument("-o", "--output", help="HTML report file")
    parser.add_argument("--no-crawler", action="store_true", help="Disable JS crawling (faster)")
    args = parser.parse_args()

    asyncio.run(main(args.domain, args.threads, args.output, not args.no_crawler))