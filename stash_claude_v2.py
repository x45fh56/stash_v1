import urllib.request
import urllib.parse
import uuid
import yaml
from typing import Dict, Optional, List
import sys
import os
import ipaddress

os.makedirs("files", exist_ok=True)
OUTPUT_FILE = os.path.join("files", "stash_claude_v2.yaml")

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8") # type: ignore

SOURCE_URL = (
    "https://raw.githubusercontent.com/x45fh56/tgs/refs/heads/main"
    "/Servers/Protocols/Categorized_Servers/1_VLESS_REALITY_TCP.txt"
)

MODE      = "rule"
LOG_LEVEL = "info"

HEALTH_CHECK_URL = "http://www.apple.com/library/test/success.html"
RULE_INTERVAL    = 86400
IR_BASE          = "https://raw.githubusercontent.com/Chocolate4U/Iran-clash-rules/release"
ZULUION_BASE     = "https://cdn.jsdelivr.net/gh/zuluion/Clash-Template-Config@master/Filter"
QURE_BASE        = "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color"

VALID_FINGERPRINTS = {
    "chrome", "firefox", "safari", "ios", "android",
    "edge", "360", "qq", "random", "randomized",
}

VALID_FLOWS = {
    "xtls-rprx-origin", "xtls-rprx-direct",
    "xtls-rprx-splice", "xtls-rprx-vision",
    None, "",
}

ICONS = {
    "proxy":     f"{QURE_BASE}/Proxy.png",
    "auto":      f"{QURE_BASE}/Auto.png",
    "fallback":  f"{QURE_BASE}/Available.png",
    "iran":      f"{QURE_BASE}/Iran.png",
    "final":     f"{QURE_BASE}/Final.png",
    "ad":        f"{QURE_BASE}/Advertising.png",
    "telegram":  f"{QURE_BASE}/Telegram.png",
    "openai":    f"{QURE_BASE}/ChatGPT.png",
    "claude":    f"{QURE_BASE}/Claude.png",
    "gemini":    f"{QURE_BASE}/AI.png",
    "instagram": f"{QURE_BASE}/Instagram.png",
    "twitter":   f"{QURE_BASE}/Twitter.png",
    "discord":   f"{QURE_BASE}/Discord.png",
    "google":    f"{QURE_BASE}/Google.png",
    "youtube":   f"{QURE_BASE}/YouTube.png",
    "github":    f"{QURE_BASE}/GitHub.png",
    "netflix":   f"{QURE_BASE}/Netflix.png",
    "disney":    f"{QURE_BASE}/Disney+_1.png",
    "spotify":   f"{QURE_BASE}/Spotify.png",
    "apple":     f"{QURE_BASE}/Apple_1.png",
    "microsoft": f"{QURE_BASE}/Microsoft.png",
    "steam":     f"{QURE_BASE}/Steam.png",
    "speedtest": f"{QURE_BASE}/Speedtest.png",
}


def is_valid_server(server: str) -> bool:
    if not server or len(server) < 3:
        return False
    try:
        ipaddress.ip_address(server)
        return True
    except ValueError:
        pass
    if "." not in server or len(server) > 253:
        return False
    for label in server.split("."):
        if not label or len(label) > 63:
            return False
    return True


def parse_vless_url(line: str) -> Optional[Dict]:
    line = line.strip()
    if not line.startswith("vless://"):
        return None

    if "#" in line:
        url_part, remark_raw = line.split("#", 1)
        remark = urllib.parse.unquote(remark_raw.strip()) or f"Reality-{uuid.uuid4().hex[:6]}"
    else:
        url_part = line
        remark = f"Reality-{uuid.uuid4().hex[:6]}"

    try:
        parsed  = urllib.parse.urlparse(url_part)
        netloc  = parsed.netloc
        if "@" not in netloc:
            return None

        uuid_val, host_port = netloc.split("@", 1)
        uuid_val = uuid_val.strip()
        if len(uuid_val) < 32 or ":" not in host_port:
            return None

        server, port_str = host_port.rsplit(":", 1)
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None

        server = server.strip("[]")
        if not is_valid_server(server):
            return None

        params = urllib.parse.parse_qs(parsed.query)
        if params.get("security", [""])[0] != "reality":
            return None

        pbk  = params.get("pbk",  [None])[0]
        sid  = params.get("sid",  [""])[0]
        sni  = params.get("sni",  [""])[0]
        fp   = params.get("fp",   ["chrome"])[0]
        flow = params.get("flow", [None])[0]

        if not pbk or not sni:
            return None
        if fp not in VALID_FINGERPRINTS:
            fp = "chrome"
        if flow not in VALID_FLOWS:
            return None

        return {
            "name":               remark,
            "server":             server,
            "port":               port,
            "uuid":               uuid_val,
            "flow":               flow if flow else None,
            "sni":                sni,
            "client-fingerprint": fp,
            "reality-opts": {
                "public-key": pbk,
                "short-id":   sid,
            },
        }

    except Exception as e:
        print(f"  Parse error: {line[:60]}... -> {e}")
        return None


def build_dns() -> Dict:
    ir_domains = [
        "+.ir", "+.aparat.com", "+.digikala.com",
        "+.snapp.ir", "+.tapsi.ir", "+.divar.ir",
    ]
    secure_doh = "https://dns.google/dns-query"
    secure_domains = [
        "+.google.com", "+.googleapis.com", "+.youtube.com",
        "+.instagram.com", "+.telegram.org", "+.github.com",
        "+.twitter.com", "+.x.com", "+.openai.com",
    ]
    return {
        "default-nameserver": ["178.22.122.100", "8.8.8.8"],
        "nameserver": [
            "https://dns.shecan.ir/dns-query",
            "https://doh.403.online/dns-query",
            secure_doh,
        ],
        "nameserver-policy": {
            **{d: "178.22.122.100" for d in ir_domains},
            **{d: secure_doh for d in secure_domains},
        },
        "fake-ip-filter": [
            "+.stun.*.*", "+.stun.*.*.*", "+.stun.*.*.*.*",
            "lens.l.google.com", "stun.l.google.com",
            "*.n.n.srv.nintendo.net", "+.stun.playstation.net",
            "xbox.*.*.microsoft.com", "*.*.xboxlive.com",
            "*.msftncsi.com", "*.msftconnecttest.com", "msftconnecttest.com",
            "time.*.com", "time.*.apple.com", "+.pool.ntp.org",
            *ir_domains,
            "*.local", "*.localhost", "*.lan", "*.home.arpa", "localhost",
        ],
    }


def build_proxy_groups(proxy_names: List[str]) -> List[Dict]:
    foreign  = ["🚀 Main Proxy", "♻️ Auto Best", "🔄 Fallback"]
    fdirect  = ["DIRECT", "🚀 Main Proxy", "♻️ Auto Best"]
    ai_group = ["🚀 Main Proxy", "♻️ Auto Best"]

    return [
        {
            "name":    "🚀 Main Proxy",
            "type":    "select",
            "proxies": ["♻️ Auto Best", "🔄 Fallback", "DIRECT"] + proxy_names,
            "icon":    ICONS["proxy"],
        },
        {
            "name":      "♻️ Auto Best",
            "type":      "url-test",
            "url":       HEALTH_CHECK_URL,
            "interval":  180,
            "tolerance": 80,
            "lazy":      True,
            "proxies":   proxy_names,
            "icon":      ICONS["auto"],
        },
        {
            "name":     "🔄 Fallback",
            "type":     "fallback",
            "url":      HEALTH_CHECK_URL,
            "interval": 120,
            "proxies":  proxy_names,
            "icon":     ICONS["fallback"],
        },
        {
            "name":    "🇮🇷 Iran Direct",
            "type":    "select",
            "proxies": ["DIRECT", "🚀 Main Proxy"],
            "icon":    ICONS["iran"],
        },
        {
            "name":    "✈️ Telegram",
            "type":    "select",
            "proxies": foreign,
            "icon":    ICONS["telegram"],
        },
        {
            "name":    "🤖 OpenAI",
            "type":    "select",
            "proxies": ai_group,
            "icon":    ICONS["openai"],
        },
        {
            "name":    "🤖 Claude",
            "type":    "select",
            "proxies": ai_group,
            "icon":    ICONS["claude"],
        },
        {
            "name":    "🤖 Gemini",
            "type":    "select",
            "proxies": ai_group,
            "icon":    ICONS["gemini"],
        },
        {
            "name":    "📸 Instagram",
            "type":    "select",
            "proxies": foreign,
            "icon":    ICONS["instagram"],
        },
        {
            "name":    "🐦 Twitter",
            "type":    "select",
            "proxies": foreign,
            "icon":    ICONS["twitter"],
        },
        {
            "name":    "💬 Discord",
            "type":    "select",
            "proxies": foreign,
            "icon":    ICONS["discord"],
        },
        {
            "name":    "🔍 Google",
            "type":    "select",
            "proxies": foreign,
            "icon":    ICONS["google"],
        },
        {
            "name":    "📺 YouTube",
            "type":    "select",
            "proxies": foreign,
            "icon":    ICONS["youtube"],
        },
        {
            "name":    "🐙 GitHub",
            "type":    "select",
            "proxies": foreign,
            "icon":    ICONS["github"],
        },
        {
            "name":    "🎬 Netflix",
            "type":    "select",
            "proxies": foreign,
            "icon":    ICONS["netflix"],
        },
        {
            "name":    "🎬 Disney+",
            "type":    "select",
            "proxies": foreign,
            "icon":    ICONS["disney"],
        },
        {
            "name":    "🎵 Spotify",
            "type":    "select",
            "proxies": foreign,
            "icon":    ICONS["spotify"],
        },
        {
            "name":    "🍎 Apple",
            "type":    "select",
            "proxies": fdirect,
            "icon":    ICONS["apple"],
        },
        {
            "name":    "🪟 Microsoft",
            "type":    "select",
            "proxies": fdirect,
            "icon":    ICONS["microsoft"],
        },
        {
            "name":    "🎮 Steam",
            "type":    "select",
            "proxies": ["🚀 Main Proxy", "♻️ Auto Best", "DIRECT"] + proxy_names,
            "icon":    ICONS["steam"],
        },
        {
            "name":    "🚦 Speedtest",
            "type":    "select",
            "proxies": fdirect,
            "icon":    ICONS["speedtest"],
        },
        {
            "name":    "🚫 Ad Block",
            "type":    "select",
            "proxies": ["REJECT", "DIRECT"],
            "icon":    ICONS["ad"],
        },
        {
            "name":    "🌐 Final",
            "type":    "select",
            "proxies": ["🚀 Main Proxy", "♻️ Auto Best", "DIRECT"],
            "icon":    ICONS["final"],
        },
    ]


def build_rule_providers() -> Dict:
    def ir(behavior, filename):
        return {
            "type": "http", "behavior": behavior,
            "format": "text", "url": f"{IR_BASE}/{filename}",
            "interval": RULE_INTERVAL,
        }

    def zl(filename):
        return {
            "type": "http", "behavior": "classical",
            "url": f"{ZULUION_BASE}/{filename}",
            "interval": RULE_INTERVAL,
        }

    return {
        "iran-domains":  ir("domain",  "ir.txt"),
        "iran-direct":   ir("domain",  "direct.txt"),
        "iran-cidr":     ir("ipcidr",  "ircidr.txt"),
        "ads":           ir("domain",  "ads.txt"),
        "telegram-cidr": ir("ipcidr",  "telegram.txt"),
        "OpenAI":        zl("OpenAI.yaml"),
        "Claude":        zl("Claude.yaml"),
        "Gemini":        zl("Gemini.yaml"),
        "Instagram":     zl("Facebook.yaml"),
        "Twitter":       zl("Twitter.yaml"),
        "Discord":       zl("Discord.yaml"),
        "Google":        zl("Google.yaml"),
        "YouTube":       zl("YouTube.yaml"),
        "GitHub":        zl("GitHub.yaml"),
        "Netflix":       zl("Netflix.yaml"),
        "Disney":        zl("DisneyPlus.yaml"),
        "Spotify":       zl("Spotify.yaml"),
        "Apple":         zl("Apple.yaml"),
        "Microsoft":     zl("Microsoft.yaml"),
        "Steam":         zl("Steam.yaml"),
        "Speedtest":     zl("Speedtest.yaml"),
    }


def build_rules() -> List[str]:
    return [
        "SCRIPT,quic,REJECT,no-track",
        "RULE-SET,ads,🚫 Ad Block",
        "RULE-SET,telegram-cidr,✈️ Telegram,no-resolve",
        "DOMAIN-SUFFIX,t.me,✈️ Telegram",
        "DOMAIN-SUFFIX,telegram.me,✈️ Telegram",
        "DOMAIN-SUFFIX,telegram.org,✈️ Telegram",
        "RULE-SET,OpenAI,🤖 OpenAI",
        "RULE-SET,Claude,🤖 Claude",
        "RULE-SET,Gemini,🤖 Gemini",
        "RULE-SET,Instagram,📸 Instagram",
        "RULE-SET,Twitter,🐦 Twitter",
        "RULE-SET,Discord,💬 Discord",
        "RULE-SET,Google,🔍 Google",
        "RULE-SET,YouTube,📺 YouTube",
        "RULE-SET,GitHub,🐙 GitHub",
        "RULE-SET,Netflix,🎬 Netflix",
        "RULE-SET,Disney,🎬 Disney+",
        "RULE-SET,Spotify,🎵 Spotify",
        "RULE-SET,Apple,🍎 Apple",
        "RULE-SET,Microsoft,🪟 Microsoft",
        "RULE-SET,Steam,🎮 Steam",
        "RULE-SET,Speedtest,🚦 Speedtest",
        "RULE-SET,iran-domains,🇮🇷 Iran Direct",
        "RULE-SET,iran-direct,🇮🇷 Iran Direct",
        "RULE-SET,iran-cidr,🇮🇷 Iran Direct,no-resolve",
        "GEOIP,IR,🇮🇷 Iran Direct,no-resolve",
        "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
        "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
        "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
        "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
        "MATCH,🌐 Final",
    ]


def dedup_proxies(raw: List[Dict]) -> List[Dict]:
    seen: set = set()
    unique: List[Dict] = []
    dups = 0
    for p in raw:
        key = (p["server"].lower(), p["port"], p["uuid"].lower())
        if key in seen:
            dups += 1
        else:
            seen.add(key)
            unique.append(p)
    if dups:
        print(f"  Duplicates removed: {dups}")
    return unique


def fix_names(proxies: List[Dict]) -> List[str]:
    names: List[str] = []
    seen: set = set()
    counters: Dict[str, int] = {}
    for p in proxies:
        base = p["name"]
        if base in counters:
            counters[base] += 1
            new = f"{base} ({counters[base]})"
        else:
            counters[base] = 1
            new = base
        while new in seen:
            new = f"{new}-{uuid.uuid4().hex[:4]}"
        p["name"] = new
        seen.add(new)
        names.append(new)
    return names


def build_proxy_entry(p: Dict) -> Dict:
    entry: Dict = {
        "name":               p["name"],
        "type":               "vless",
        "server":             p["server"],
        "port":               p["port"],
        "uuid":               p["uuid"],
        "network":            "tcp",
        "tls":                True,
        "udp":                True,
        "sni":                p["sni"],
        "client-fingerprint": p["client-fingerprint"],
        "reality-opts":       p["reality-opts"],
        "benchmark-url":      HEALTH_CHECK_URL,
        "benchmark-timeout":  5,
    }
    if p.get("flow"):
        entry["flow"] = p["flow"]
    return entry


def main():
    print("=" * 52)
    print("  Stash Config Generator — Optimized for Iran")
    print("=" * 52)
    print("\nDownloading server list...")

    try:
        req = urllib.request.Request(
            SOURCE_URL,
            headers={"User-Agent": "Mozilla/5.0 (Stash/ConfigGen)"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            text = resp.read().decode("utf-8")
    except Exception as e:
        print(f"Download failed: {e}")
        return

    lines = text.splitlines()
    print(f"  Total lines: {len(lines)}")

    raw: List[Dict] = []
    skipped = 0
    for line in lines:
        line = line.strip()
        if not line:
            continue
        p = parse_vless_url(line)
        if p:
            raw.append(p)
        elif line.startswith("vless://"):
            skipped += 1

    print(f"  Valid servers: {len(raw)}")
    if skipped:
        print(f"  Skipped (invalid): {skipped}")

    if not raw:
        print("No valid servers found.")
        return

    unique = dedup_proxies(raw)
    names  = fix_names(unique)
    print(f"  Final unique proxies: {len(names)}")

    entries = [build_proxy_entry(p) for p in unique]

    config = {
        "mode":      MODE,
        "log-level": LOG_LEVEL,
        "dns": build_dns(),
        "script": {
            "shortcuts": {
                "quic": "network == 'udp' and dst_port == 443",
            }
        },
        "proxies":        entries,
        "proxy-groups":   build_proxy_groups(names),
        "rule-providers": build_rule_providers(),
        "rules":          build_rules(),
    }

    try:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            yaml.safe_dump(
                config, f,
                allow_unicode=True,
                sort_keys=False,
                indent=2,
                default_flow_style=False,
            )
        size_kb = os.path.getsize(OUTPUT_FILE) / 1024
        print(f"\nConfig saved: {OUTPUT_FILE}")
        print(f"Size: {size_kb:.1f} KB  |  Proxies: {len(entries)}")
        print("\nLoad in Stash: Profile -> + -> Import from file")
        print("\nProxy groups:")
        print("  🚀 Main Proxy    select manually")
        print("  ♻️ Auto Best     lowest latency (every 3 min)")
        print("  🔄 Fallback      ordered auto-switch")
        print("  🇮🇷 Iran Direct  no proxy")
        print("  ✈️ Telegram      dedicated")
        print("  🤖 AI services   OpenAI / Claude / Gemini")
        print("  📺 Media         YouTube / Netflix / Disney+")
        print("  🚫 Ad Block      REJECT")
        print("  🌐 Final         catch-all")
    except Exception as e:
        print(f"Error saving file: {e}")


if __name__ == "__main__":
    main()