import os
import requests
import yaml
from urllib.parse import urlparse, parse_qs, unquote

SOURCE_URL = "https://raw.githubusercontent.com/x45fh56/tgs/refs/heads/main/Servers/Protocols/Categorized_Servers/1_VLESS_REALITY_TCP.txt"

OUTPUT_FILE = os.path.join("files", "stash_gpt.yaml")


def parse_vless(link, existing_names):
    link = link.strip()
    if not link.startswith("vless://"):
        return None

    parsed = urlparse(link)

    uuid_value = parsed.username
    server = parsed.hostname
    port = parsed.port

    if not server or not port or not uuid_value:
        return None

    params = parse_qs(parsed.query)

    security = params.get("security", ["none"])[0]
    if security != "reality":
        return None

    public_key = params.get("pbk", [None])[0]
    short_id = params.get("sid", [None])[0]

    if not public_key or not short_id:
        return None

    sni = params.get("sni", [server])[0]
    fingerprint = params.get("fp", ["chrome"])[0]
    flow = params.get("flow", ["xtls-rprx-vision"])[0]

    remark = unquote(parsed.fragment) if parsed.fragment else f"{server}:{port}"

    if remark in existing_names:
        return None

    proxy = {
        "name": remark,
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": uuid_value,
        "network": "tcp",
        "udp": True,
        "tls": True,
        "servername": sni,
        "client-fingerprint": fingerprint,
        "flow": flow,
        "skip-cert-verify": True,
        "benchmark-url": "http://www.gstatic.com/generate_204",
        "benchmark-timeout": 6,
        "reality-opts": {
            "public-key": public_key,
            "short-id": short_id
        }
    }

    return proxy


def build_config(proxies):
    proxy_names = [p["name"] for p in proxies]

    config = {
        "mixed-port": 7890,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:1053",
            "ipv6": False,
            "enhanced-mode": "redir-host",
            "default-nameserver": [
                "1.1.1.1",
                "8.8.8.8"
            ],
            "nameserver": [
                "https://cloudflare-dns.com/dns-query",
                "https://dns.google/dns-query"
            ],
            "fallback": [
                "tls://8.8.4.4:853",
                "tls://1.0.0.1:853"
            ],
            "fallback-filter": {
                "geoip": True,
                "geoip-code": "IR"
            }
        },
        "tun": {
            "enable": True,
            "stack": "system",
            "auto-route": True,
            "auto-detect-interface": True
        },
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "AUTO-IRAN",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 120,
                "tolerance": 100,
                "proxies": proxy_names
            },
            {
                "name": "SELECT",
                "type": "select",
                "proxies": ["AUTO-IRAN"] + proxy_names + ["DIRECT"]
            }
        ],
        "rule-providers": {
            "ir": {
                "behavior": "domain",
                "format": "text",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/ir.txt",
                "interval": 86400
            },
            "direct": {
                "behavior": "domain",
                "format": "text",
                "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release/direct.txt",
                "interval": 86400
            }
        },
        "rules": [
            "RULE-SET,ir,DIRECT",
            "RULE-SET,direct,DIRECT",
            "GEOIP,IR,DIRECT,no-resolve",
            "MATCH,SELECT"
        ]
    }

    return config


def main():
    response = requests.get(SOURCE_URL, timeout=20)
    response.raise_for_status()

    lines = response.text.splitlines()

    proxies = []
    existing_names = set()

    for line in lines:
        proxy = parse_vless(line, existing_names)
        if proxy:
            existing_names.add(proxy["name"])
            proxies.append(proxy)

    config = build_config(proxies)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)


if __name__ == "__main__":
    main()