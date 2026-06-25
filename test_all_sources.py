import sys
import asyncio
import aiohttp
import re
from pathlib import Path

# Extract URLs directly from UPO.py to avoid import errors
upo_path = Path(r"f:\ZHCraking\JB\UPO\UPO.py")
content = upo_path.read_text(encoding="utf-8")

sources = {"HTTP": [], "SOCKS4": [], "SOCKS5": []}

for list_name, key in [("GITHUB_HTTP_SOURCES", "HTTP"), ("GITHUB_SOCKS4_SOURCES", "SOCKS4"), ("GITHUB_SOCKS5_SOURCES", "SOCKS5")]:
    m = re.search(fr"{list_name}\s*=\s*\[(.*?)\]", content, re.DOTALL)
    if m:
        urls = re.findall(r'"([^"]+)"', m.group(1))
        sources[key].extend(urls)

proxy_rx = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})")

async def test_url(session, url, name):
    try:
        async with session.get(url, timeout=15) as r:
            if r.status != 200:
                return (url, name, False, f"HTTP {r.status}")
            txt = await r.text()
            matches = proxy_rx.findall(txt)
            if matches:
                return (url, name, True, f"Found {len(matches)}")
            else:
                return (url, name, False, "No proxies found")
    except Exception as e:
        return (url, name, False, str(e))

async def main():
    urls = []
    for k, v in sources.items():
        for u in v:
            urls.append((u, k))
            
    print(f"Testing {len(urls)} total URLs asynchronously...")
    
    conn = aiohttp.TCPConnector(limit=50)
    async with aiohttp.ClientSession(connector=conn) as session:
        tasks = [test_url(session, u, name) for u, name in urls]
        results = await asyncio.gather(*tasks)

    working = []
    failed = []
    
    for r in results:
        if r[2]: working.append(r)
        else: failed.append(r)
        
    out_path = r"f:\ZHCraking\JB\UPO\summary_all.txt"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(f"Total: {len(urls)} | Working: {len(working)} | Failed: {len(failed)}\n\n")
        f.write("--- WORKING SOURCES (Sample) ---\n")
        for u, name, status, msg in working[:5]:
            f.write(f"[{name}] {u} -> {msg}\n")
            
        f.write("\n--- FAILED SOURCES ---\n")
        for u, name, status, msg in failed:
            f.write(f"[{name}] {str(msg).strip()} -> {u}\n")
            
    print(f"Done! {len(failed)} failed. Details saved to {out_path}")

if __name__ == "__main__":
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
