import requests
import yaml
from urllib.parse import urlparse, parse_qs, unquote
import os

os.makedirs("files", exist_ok=True)
OUTPUT_FILE = os.path.join("files", "stash_gemini.yaml")
SOURCE_URL = "https://raw.githubusercontent.com/x45fh56/tgs/refs/heads/main/Servers/Protocols/Categorized_Servers/1_VLESS_REALITY_TCP.txt"

BASE_CONFIG = {
    "mixed-port": 7890,
    "allow-lan": True,
    "mode": "rule",
    "log-level": "info",
    "ipv6": False,
    "global-client-fingerprint": "chrome",
    "dns": {
        "enable": True,
        "listen": "0.0.0.0:53",
        "ipv6": False,
        "default-nameserver": ["1.1.1.1", "8.8.8.8", "119.29.29.29"],
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "use-hosts": True,
        "nameserver": [
            "https://1.1.1.1/dns-query",
            "https://8.8.8.8/dns-query",
            "https://doh.pub/dns-query"
        ],
        "fallback": [
            "https://1.0.0.1/dns-query",
            "https://public.dns.iij.jp/dns-query",
            "tcp://8.8.8.8"
        ],
        "fallback-filter": {
            "geoip": True,
            "ipcidr": ["240.0.0.0/4"]
        },
        "fake-ip-filter": [
            "+.ir",
            "+.gov.ir",
            "*.ir",
            "*.snapp.ir",
            "*.tapsi.ir",
            "*.rubika.ir",
            "*.igap.net",
            "*.eitaa.com",
            "*.shad.ir",
            "*.shaparak.ir",
            "*.bank*",
            "*.bmi.ir",
            "*.sep.ir"
        ]
    },
    "rule-providers": {
        "Iran_Domains": {
            "type": "http",
            "behavior": "domain",
            "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/clash/iran.yaml",
            "path": "./rules/iran_domains.yaml",
            "interval": 86400
        },
        "Iran_IP": {
            "type": "http",
            "behavior": "ipcidr",
            "url": "https://cdn.jsdelivr.net/gh/Chocolate4U/Iran-sing-box-rules@rule-set/clash/iran_ip.yaml",
            "path": "./rules/iran_ip.yaml",
            "interval": 86400
        },
        "Ads": {
            "type": "http",
            "behavior": "domain",
            "url": "https://cdn.jsdelivr.net/gh/privacy-protection-tools/anti-AD@master/anti-ad-clash.yaml",
            "path": "./rules/ads.yaml",
            "interval": 86400
        }
    }
}

def is_valid_proxy(proxy):
    if not proxy:
        return False
    
    required_fields = ["name", "type", "server", "port", "uuid"]
    
    for field in required_fields:
        if field not in proxy or not proxy[field]:
            return False
            
    try:
        port = int(proxy["port"])
        if not (1 <= port <= 65535):
            return False
    except:
        return False

    if len(proxy["uuid"]) < 30:
        return False

    return True

def build_transport_stash(net_type, path, host, service_name, header_type):
    transport = {}
    
    if path and "?" in path:
        path = path.split("?")[0]
    if not path:
        path = "/"

    if net_type == 'tcp':
        if header_type == 'http':
            transport = {
                "network": "http",
                "http-opts": {
                    "method": "GET",
                    "path": [path],
                    "headers": {"Host": [host]} if host else {}
                }
            }
        else:
            transport = {"network": "tcp"}

    elif net_type == 'ws':
        transport = {
            "network": "ws",
            "ws-opts": {
                "path": path,
                "headers": {"Host": host} if host else {}
            }
        }

    elif net_type == 'grpc':
        transport = {
            "network": "grpc",
            "grpc-opts": {
                "grpc-service-name": service_name
            }
        }
    
    return transport

def build_tls_stash(security, sni, fp, pbk, sid, alpn):
    if security not in ["tls", "reality"]:
        return {}

    tls_config = {
        "tls": True,
        "servername": sni,
        "client-fingerprint": fp if fp else "chrome" 
    }

    if security == "tls":
        if alpn:
            tls_config["alpn"] = alpn.split(",")
        tls_config["skip-cert-verify"] = True

    elif security == "reality":
        if not pbk or not sid:
            return None

        tls_config["reality-opts"] = {
            "public-key": pbk,
            "short-id": sid
        }
        if alpn:
             tls_config["alpn"] = alpn.split(",") if "," in alpn else [alpn]
        
        tls_config["skip-cert-verify"] = True 

    return tls_config

def parse_vless_stash(link):
    if not link.startswith("vless://"):
        return None

    try:
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        
        uuid = parsed.username
        server = parsed.hostname
        port = parsed.port
        name = unquote(parsed.fragment) if parsed.fragment else "VLESS Node"
        
        security = params.get("security", [""])[0]
        net_type = params.get("type", ["tcp"])[0]
        sni = params.get("sni", [""])[0] or server
        pbk = params.get("pbk", [""])[0]
        sid = params.get("sid", [""])[0]
        fp = params.get("fp", ["chrome"])[0]
        path = params.get("path", ["/"])[0]
        host = params.get("host", [""])[0]
        service_name = params.get("serviceName", [""])[0]
        header_type = params.get("headerType", [""])[0]
        flow = params.get("flow", [""])[0]
        alpn = params.get("alpn", [""])[0]

        tls_settings = build_tls_stash(security, sni, fp, pbk, sid, alpn)
        
        if security == "reality" and tls_settings is None:
            return None

        transport_settings = build_transport_stash(net_type, path, host, service_name, header_type)

        proxy = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "tfo": False,
            "udp": True,
            "skip-cert-verify": True
        }

        if flow:
            if flow in ["xtls-rprx-vision", "xtls-rprx-vision-udp443"]:
                 proxy["flow"] = flow

        if tls_settings:
            proxy.update(tls_settings)
        
        if transport_settings:
            proxy.update(transport_settings)

        return proxy

    except Exception:
        return None

if __name__ == "__main__":
    print(f"Downloading links from: {SOURCE_URL}")
    try:
        response = requests.get(SOURCE_URL, timeout=15)
        response.raise_for_status()
        links = response.text.splitlines()
    except Exception as e:
        print(f"Failed to download: {e}")
        exit(1)

    proxies = []
    name_counter = {}

    print("Processing & Validating links for Stash...")
    
    for link in links:
        stripped_link = link.strip()
        if stripped_link and not stripped_link.startswith("#"):
            p = parse_vless_stash(stripped_link)
            
            if p is not None and is_valid_proxy(p):
                original_name = p["name"]
                
                if original_name in name_counter:
                    name_counter[original_name] += 1
                    new_name = f"{original_name} {name_counter[original_name]}"
                    p["name"] = new_name
                else:
                    name_counter[original_name] = 1
                
                proxies.append(p)

    print(f"Valid proxies extracted: {len(proxies)}")

    if proxies:
        proxy_names = [p["name"] for p in proxies]
        
        proxy_groups = [
            {
                "name": "Proxy",
                "type": "select",
                "proxies": ["Auto", "Fallback", "DIRECT"] + proxy_names
            },
            {
                "name": "Auto",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 600,
                "tolerance": 100,
                "proxies": proxy_names
            },
            {
                "name": "Fallback",
                "type": "fallback",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 600,
                "proxies": proxy_names
            },
            {
                "name": "Iran-Direct",
                "type": "select",
                "proxies": ["DIRECT", "Proxy"]
            }
        ]

        rules = [
            "RULE-SET,Ads,REJECT",
            "RULE-SET,Iran_Domains,Iran-Direct",
            "RULE-SET,Iran_IP,Iran-Direct",
            "DOMAIN-SUFFIX,ir,Iran-Direct",
            "GEOIP,IR,Iran-Direct",
            "GEOIP,PRIVATE,DIRECT",
            "MATCH,Proxy"
        ]

        final_config = BASE_CONFIG.copy()
        final_config["proxies"] = proxies
        final_config["proxy-groups"] = proxy_groups
        final_config["rules"] = rules

        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            yaml.dump(final_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        
        print(f"[SUCCESS] Stash configuration saved to: {OUTPUT_FILE}")
    else:
        print("[ERROR] No valid proxies found after validation.")