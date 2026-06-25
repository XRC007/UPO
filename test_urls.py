import urllib.request
import re

urls = [
    "https://cdn.jsdelivr.net/gh/ObcbO/getproxy/file/http.txt",
    "https://cdn.jsdelivr.net/gh/ObcbO/getproxy/file/https.txt",
    "https://cdn.jsdelivr.net/gh/ObcbO/getproxy/file/socks4.txt",
    "https://cdn.jsdelivr.net/gh/ObcbO/getproxy/file/socks5.txt"
]

proxy_rx = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})")

with open(r'f:\ZHCraking\JB\UPO\summary3.txt', 'w', encoding='utf-8') as out_f:
    for u in urls:
        try:
            req = urllib.request.Request(u, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8').strip()
                matches = proxy_rx.findall(content)
                if matches:
                    out_f.write(f"OK: {u} -> Found {len(matches)} proxies. Sample: {matches[0][0]}:{matches[0][1]}\n")
                else:
                    out_f.write(f"WARN: {u} -> No ip:port pairs found. Content starts with: {content[:50]}...\n")
        except Exception as e:
            out_f.write(f"FAIL: {u} - {e}\n")
