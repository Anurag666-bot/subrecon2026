"""
DNS resolver module for SubRecon 2026.
"""
import asyncio
import socket
from typing import List, Optional


class AsyncDNS:
    async def resolve_a(self, hostname: str) -> Optional[List[str]]:
        loop = asyncio.get_running_loop()
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, hostname)
            return [ip]
        except socket.gaierror:
            return None