import urllib.request
import re
import sys

urls = [
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/http.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks4.txt",
    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt"
]

proxy_rx = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})")

with open(r'f:\ZHCraking\JB\UPO\alilapro_summary.txt', 'w', encoding='utf-8') as out_f:
    for u in urls:
        try:
            req = urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8').strip()
                matches = proxy_rx.findall(content)
                if matches:
                    msg = f"OK: {u} -> Found {len(matches)} proxies. Sample: {matches[0][0]}:{matches[0][1]}"
                else:
                    msg = f"WARN: {u} -> No ip:port pairs found. Content starts with: {content[:50]}..."
        except Exception as e:
            msg = f"FAIL: {u} - {e}"
        
        print(msg)
        out_f.write(msg + '\n')
