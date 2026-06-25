import io

upo_path = r"f:\ZHCraking\JB\UPO\UPO.py"
with open(upo_path, "r", encoding="utf-8") as f:
    text = f.read()

# 1. Remove zloi-user https and http (Wait, user just mentioned https, but let's just remove https as requested)
text = text.replace('    "https://raw.githubusercontent.com/zloi-user/hideip.me/main/https.txt",\n', "")

# 2. Fix ErcinDedeoglu and add https
text = text.replace(
    '    "https://raw.githubusercontent.com/ErcinDedeworkarounds/proxies/main/proxies/http.txt",',
    '    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/http.txt",\n    "https://raw.githubusercontent.com/ErcinDedeoglu/proxies/main/proxies/https.txt",'
)
text = text.replace('ErcinDedeworkarounds', 'ErcinDedeoglu')

# 3. Remove KangProxy
text = text.replace('    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/http/http.txt",\n', "")
text = text.replace('    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/https/https.txt",\n', "")
text = text.replace('    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks4/socks4.txt",\n', "")
text = text.replace('    "https://raw.githubusercontent.com/officialputuid/KangProxy/KangProxy/socks5/socks5.txt",\n', "")

# 4. Remove ObcbO
text = text.replace('    "https://raw.githubusercontent.com/ObcbO/getproxy/master/http.txt",\n', "")
text = text.replace('    "https://raw.githubusercontent.com/ObcbO/getproxy/master/https.txt",\n', "")
text = text.replace('    "https://raw.githubusercontent.com/ObcbO/getproxy/master/socks4.txt",\n', "")
text = text.replace('    "https://raw.githubusercontent.com/ObcbO/getproxy/master/socks5.txt",\n', "")

# 5. Remove ALIILAPRO socks5
text = text.replace('    "https://raw.githubusercontent.com/ALIILAPRO/Proxy/main/socks5.txt",\n', "")

# 6. Remove Zaeem20 socks5
text = text.replace('    "https://raw.githubusercontent.com/Zaeem20/FREE_PROXIES_LIST/master/socks5.txt",\n', "")

with open(upo_path, "w", encoding="utf-8") as f:
    f.write(text)

print("UPO.py updated successfully.")
