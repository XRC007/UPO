import asyncio, aiohttp

async def fetch_count(session, url):
    try:
        async with session.get(url, timeout=10) as r:
            text = await r.text()
            lines = [line.strip() for line in text.split("\n") if ":" in line]
            return len(lines)
    except Exception as e:
        return f"Error: {e}"

async def main():
    async with aiohttp.ClientSession() as session:
        url_all = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_type=http&country=all"
        all_count = await fetch_count(session, url_all)
        print(f"Proxyscrape ALL HTTP: {all_count}")

        countries = ["US", "DE", "KR", "CN", "RU", "FR", "GB"]
        for c in countries:
            url_c = f"https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_type=http&country={c}"
            c_count = await fetch_count(session, url_c)
            print(f"Proxyscrape {c} HTTP: {c_count}")

if __name__ == "__main__":
    import sys
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(main())
