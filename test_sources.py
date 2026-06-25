"""Quick test: hit each URL and report status, size, proxy count."""
import asyncio, aiohttp, re, sys

PROXY_RX = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}")

URLS = {
    # ── Already added (L207-L222) ──
    "zevtyardt/http":   "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/http.txt",
    "zevtyardt/socks4": "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks4.txt",
    "zevtyardt/socks5": "https://raw.githubusercontent.com/zevtyardt/proxy-list/main/socks5.txt",
    "HyperBeats/http":  "https://raw.githubusercontent.com/HyperBeats/proxy-list/main/http.txt",
    "HyperBeats/socks4":"https://raw.githubusercontent.com/HyperBeats/proxy-list/main/socks4.txt",
    "HyperBeats/socks5":"https://raw.githubusercontent.com/HyperBeats/proxy-list/main/socks5.txt",
    "rx443/http":       "https://raw.githubusercontent.com/rx443/proxy-list/online/http.txt",
    "rx443/socks5":     "https://raw.githubusercontent.com/rx443/proxy-list/online/socks5.txt",
    "im-razvan/http":   "https://raw.githubusercontent.com/im-razvan/proxy_list/main/http.txt",
    "im-razvan/socks5": "https://raw.githubusercontent.com/im-razvan/proxy_list/main/socks5.txt",
    "andigwandi":       "https://raw.githubusercontent.com/andigwandi/free-proxy/main/proxy_list.txt",
    "Nspired1":         "https://raw.githubusercontent.com/Nspired1/free-proxies/main/proxies.txt",
    "mertguvencli":     "https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt",
    "casals-ar/http":   "https://raw.githubusercontent.com/casals-ar/proxy-list/main/http",
    "casals-ar/socks4": "https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks4",
    "casals-ar/socks5": "https://raw.githubusercontent.com/casals-ar/proxy-list/main/socks5",

    # ── Proposed new sources ──
    "redscrape/http":   "https://free.redscrape.com/api/proxies?type=http&format=txt",
    "redscrape/socks4": "https://free.redscrape.com/api/proxies?type=socks4&format=txt",
    "redscrape/socks5": "https://free.redscrape.com/api/proxies?type=socks5&format=txt",
    "proxyscrape-ext/http":  "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_type=http&timeout=10000&country=all&ssl=all&anonymity=all",
    "proxyscrape-ext/socks4":"https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_type=socks4&timeout=10000&country=all",
    "proxyscrape-ext/socks5":"https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_type=socks5&timeout=10000&country=all",
    "proxyspace/http":  "https://proxyspace.pro/http.txt",
    "proxyspace/socks4":"https://proxyspace.pro/socks4.txt",
    "proxyspace/socks5":"https://proxyspace.pro/socks5.txt",
    "proxy-list.download/http":  "https://www.proxy-list.download/api/v1/get?type=http",
    "proxy-list.download/https": "https://www.proxy-list.download/api/v1/get?type=https",
    "proxy-list.download/socks4":"https://www.proxy-list.download/api/v1/get?type=socks4",
    "proxy-list.download/socks5":"https://www.proxy-list.download/api/v1/get?type=socks5",
    "hidemy.io":        "https://hidemy.io/en/proxy-list/?type=hs#list",
    "openproxy/http":   "https://openproxy.space/list/http",
    "openproxy/socks4": "https://openproxy.space/list/socks4",
    "openproxy/socks5": "https://openproxy.space/list/socks5",
}

async def test_url(session, name, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as r:
            text = await r.text()
            proxies = PROXY_RX.findall(text)
            status = "✓" if r.status == 200 and len(proxies) > 0 else "⚠"
            return name, r.status, len(text), len(proxies), status
    except Exception as e:
        return name, 0, 0, 0, f"✗ {type(e).__name__}"

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [test_url(session, n, u) for n, u in URLS.items()]
        results = await asyncio.gather(*tasks)

    print(f"\n{'Source':<30} {'Status':>6} {'Size':>8} {'Proxies':>8} {'Result'}")
    print("-" * 75)

    added = []
    proposed = []
    for name, status, size, count, result in sorted(results, key=lambda x: x[0]):
        line = f"{name:<30} {status:>6} {size:>8} {count:>8} {result}"
        print(line)

        # Separate categories
        if name in list(URLS.keys())[:16]:
            added.append((name, status, count, result))
        else:
            proposed.append((name, status, count, result))

    print("\n=== SUMMARY: Already Added (L207-222) ===")
    live = sum(1 for _, s, c, _ in added if s == 200 and c > 0)
    dead = len(added) - live
    print(f"  Live: {live}/{len(added)}  |  Dead: {dead}")
    for name, status, count, result in added:
        if status != 200 or count == 0:
            print(f"  ✗ DEAD: {name} (status={status}, proxies={count})")

    print("\n=== SUMMARY: Proposed New Sources ===")
    for name, status, count, result in proposed:
        verdict = "ADD ✓" if status == 200 and count > 5 else "SKIP ✗"
        print(f"  {verdict}: {name} (status={status}, proxies={count})")

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
asyncio.run(main())
