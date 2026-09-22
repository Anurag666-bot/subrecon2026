"""
HTML reporting module for SubRecon 2026.
"""
from datetime import datetime


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