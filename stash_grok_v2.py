import urllib.request
import urllib.parse
import uuid
import yaml
from typing import Dict, Optional, List
import sys
import os

os.makedirs("files", exist_ok=True)
OUTPUT_FILE = os.path.join("files", "stash_grok_v2.yaml")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8") # type: ignore

SOURCE_URL = "https://raw.githubusercontent.com/x45fh56/tgs/refs/heads/main/Servers/Protocols/Categorized_Servers/1_VLESS_REALITY_TCP.txt"

MIXED_PORT = 7890
ALLOW_LAN = True
LOG_LEVEL = "info"
MODE = "rule"
HEALTH_CHECK_URL = "http://www.gstatic.com/generate_204"

def parse_vless_url(line: str) -> Optional[Dict]:
    line = line.strip()
    if not line.startswith("vless://") or "#" not in line:
        return None
    try:
        url_part, remark_part = line.split("#", 1)
        remark = urllib.parse.unquote(remark_part.strip()) if remark_part.strip() else f"Reality-{uuid.uuid4().hex[:6]}"
        parsed = urllib.parse.urlparse(url_part)
        uuid_and_host = parsed.netloc
        if '@' not in uuid_and_host:
            return None
        uuid_val, host_port = uuid_and_host.split("@", 1)
        if len(uuid_val) != 36 or '-' not in uuid_val:
            print(f"Invalid UUID skipped (len={len(uuid_val)}): {uuid_val[:10]}...")
            return None
        clean_uuid = uuid_val.replace('-', '')
        if len(clean_uuid) != 32 or not all(c in '0123456789abcdefABCDEF' for c in clean_uuid):
            print(f"Invalid UUID chars skipped: {uuid_val[:10]}...")
            return None
        server, port_str = host_port.rsplit(":", 1)
        port = int(port_str)
        params = urllib.parse.parse_qs(parsed.query)
        security = params.get("security", [""])[0]
        if security != "reality":
            return None
        pbk = params.get("pbk", [None])[0]
        sid = params.get("sid", [""])[0]
        sni = params.get("sni", [""])[0]
        fp = params.get("fp", ["chrome"])[0]
        flow = params.get("flow", [None])[0]
        spx = params.get("spx", [None])[0]
        if not pbk or not sni:
            return None
        return {
            "name": remark,
            "server": server,
            "port": port,
            "uuid": uuid_val,
            "flow": flow,
            "tls": True,
            "network": "tcp",
            "servername": sni,
            "client-fingerprint": fp,
            "reality-opts": {
                "public-key": pbk,
                "short-id": sid
            },
            "spiderX": spx if spx else None
        }
    except Exception as e:
        print(f"Parse error: {line[:60]}... → {e}")
        return None

def build_dns() -> Dict:
    return {
        "enable": True,
        "listen": "0.0.0.0:53",
        "ipv6": False,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": [
            "*.lan", "*.local", "*.localdomain", "*.example", "*.invalid",
            "*.localhost", "*.test", "*.home.arpa", "router.asus.com",
            "localhost.ptlogin2.qq.com", "localhost.sec.qq.com",
            "+.msftconnecttest.com", "+.ir", "+.co.ir",
            "time.*.com", "ntp.*.com", "*.ntp.org.cn", "+.pool.ntp.org"
        ],
        "default-nameserver": ["223.5.5.5", "114.114.114.114", "8.8.8.8"],
        "nameserver": ["https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"],
        "fallback": ["tls://8.8.8.8:853", "tls://1.1.1.1:853"],
        "fallback-filter": {
            "geoip": True,
            "geoip-code": "IR",
            "ipcidr": ["240.0.0.0/4", "224.0.0.0/4"]
        }
    }

def main():
    print("Downloading server list...")
    try:
        with urllib.request.urlopen(SOURCE_URL) as response:
            text = response.read().decode("utf-8")
    except Exception as e:
        print(f"Download failed: {e}")
        return

    proxies: List[Dict] = []
    for line in text.splitlines():
        proxy = parse_vless_url(line)
        if proxy:
            proxies.append(proxy)

    if not proxies:
        print("No valid VLESS Reality servers found.")
        return

    print(f"Found {len(proxies)} valid servers.")

    proxy_names = []
    seen = set()
    name_counters = {}

    for p in proxies:
        base_name = p["name"]
        if base_name in name_counters:
            name_counters[base_name] += 1
            new_name = f"{base_name} - {name_counters[base_name]}"
        else:
            name_counters[base_name] = 1
            new_name = base_name
        while new_name in seen:
            new_name = f"{new_name} ~{uuid.uuid4().hex[:4]}"
        p["name"] = new_name
        seen.add(new_name)
        proxy_names.append(new_name)

    print(f"Unique proxy names: {len(proxy_names)}")

    config = {
        "mixed-port": MIXED_PORT,
        "allow-lan": ALLOW_LAN,
        "mode": MODE,
        "log-level": LOG_LEVEL,
        "ipv6": False,
        "dns": build_dns(),
        "proxies": [],
        "proxy-groups": [
            {"name": "Main Select", "type": "select", "proxies": proxy_names + ["Auto Best", "DIRECT"]},
            {
                "name": "Auto Best",
                "type": "url-test",
                "url": HEALTH_CHECK_URL,
                "interval": 300,
                "tolerance": 100,
                "timeout": 8,
                "lazy": True,
                "proxies": proxy_names
            },
            {"name": "Iran Direct", "type": "select", "proxies": ["DIRECT", "Main Select"]},
            {"name": "YouTube", "type": "select", "proxies": ["Main Select", "Auto Best", "Iran Direct"]},
            {"name": "Netflix", "type": "select", "proxies": ["Main Select", "Auto Best"]},
            {"name": "OpenAI", "type": "select", "proxies": ["Main Select", "Auto Best"]},
            {"name": "Telegram", "type": "select", "proxies": ["Main Select", "Auto Best"]},
            {"name": "Streaming", "type": "select", "proxies": ["Main Select", "Auto Best", "Iran Direct"]}
        ],
        "rule-providers": {
            "ir": {
                "type": "http",
                "behavior": "domain",
                "format": "text",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt",
                "interval": 86400
            },
            "ads": {
                "type": "http",
                "behavior": "domain",
                "format": "text",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ads.txt",
                "interval": 86400
            },
            "direct": {
                "type": "http",
                "behavior": "domain",
                "format": "text",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/direct.txt",
                "interval": 86400
            }
        },
        "rules": [
            "RULE-SET,ads,REJECT",
            "RULE-SET,ir,Iran Direct",
            "RULE-SET,direct,Iran Direct",
            "GEOIP,IR,Iran Direct,no-resolve",
            "MATCH,Main Select"
        ]
    }

    for p in proxies:
        entry = {
            "name": p["name"],
            "type": "vless",
            "server": p["server"],
            "port": p["port"],
            "uuid": p["uuid"],
            "network": "tcp",
            "tls": True,
            "servername": p["servername"],
            "client-fingerprint": p["client-fingerprint"],
            "reality-opts": p["reality-opts"],
            "skip-cert-verify": True,
            "udp": True,
            "health-check": {
                "enable": True,
                "url": HEALTH_CHECK_URL,
                "interval": 300,
                "timeout": 5
            }
        }
        if p.get("flow"):
            entry["flow"] = p["flow"]
        config["proxies"].append(entry)

    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f, allow_unicode=True, sort_keys=False, indent=2, default_flow_style=False)
        print(f"\nConfig saved: {OUTPUT_FILE}")
        print("Iran-optimized + zuluion-inspired groups & structure")
    except Exception as e:
        print(f"Error saving file: {e}")

if __name__ == "__main__":
    main()