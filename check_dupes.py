import sys
from pathlib import Path

# Load UPO.py module
sys.path.insert(0, str(Path(r"f:\ZHCraking\JB\UPO")))
import UPO

lists_to_check = [
    ("GITHUB_HTTP_SOURCES", UPO.GITHUB_HTTP_SOURCES),
    ("GITHUB_SOCKS4_SOURCES", UPO.GITHUB_SOCKS4_SOURCES),
    ("GITHUB_SOCKS5_SOURCES", UPO.GITHUB_SOCKS5_SOURCES),
]

# Extract URLs from API_SOURCES
api_urls = [src["url"] for src in UPO.API_SOURCES]
lists_to_check.append(("API_SOURCES", api_urls))

all_urls = []
has_dupes = False

for name, lst in lists_to_check:
    print(f"\nChecking {name}...")
    seen = set()
    dupes = set()
    for url in lst:
        url = url.strip()
        all_urls.append(url)
        if url in seen:
            dupes.add(url)
        seen.add(url)
    
    if dupes:
        has_dupes = True
        print(f"  [!] Found {len(dupes)} exact duplicates in {name}:")
        for d in dupes:
            print(f"      - {d}")
    else:
        print("  ✓ No duplicates found.")

print("\nChecking across ALL lists (Global duplicates)...")
seen_global = set()
dupes_global = set()
for url in all_urls:
    if url in seen_global:
        dupes_global.add(url)
    seen_global.add(url)

if dupes_global:
    has_dupes = True
    print(f"  [!] Found {len(dupes_global)} URLs that appear in multiple different lists:")
    for d in dupes_global:
        print(f"      - {d}")
else:
    print("  ✓ No global cross-list duplicates found.")

if not has_dupes:
    print("\n✅ Your proxy sources are perfectly clean! No duplicates anywhere.")
