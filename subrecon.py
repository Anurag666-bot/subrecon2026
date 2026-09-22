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
import argparse
from subrecon.cli import main as async_main

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SubRecon 2026 ELITE - Next-gen subdomain discovery")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Concurrent DNS threads")
    parser.add_argument("-o", "--output", help="HTML report file")
    parser.add_argument("--no-crawler", action="store_true", help="Disable JS crawling (faster)")
    args = parser.parse_args()

    asyncio.run(async_main(args.domain, args.threads, args.output, not args.no_crawler))