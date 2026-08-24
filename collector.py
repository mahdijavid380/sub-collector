#!/usr/bin/env python3
"""
Subscription Manager for VLESS
- Fetches from SUB_URLS (base64 or plain)
- Outputs:
    1) javidsub        : raw VLESS links
    2) final_sub.txt   : Xray/V2Ray full config
    3) javidbox.json   : Sing‑Box full config (like the sample)
"""

import base64
import json
import logging
import os
import re
import urllib.request
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, unquote, urlparse

# ==================== Logging ====================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ==================== Validation ====================
def is_valid_vless(url: str) -> bool:
    """Validate VLESS URL format."""
    if not url or not url.startswith("vless://"):
        return False
    return bool(re.match(r"^vless://[a-f0-9\-]{36}@[a-zA-Z0-9\.\-]+:\d+.*$", url))


# ==================== Fetch & Decode ====================
def fetch_subscription(sub_url: str) -> List[str]:
    """Fetch and decode (if base64) a subscription URL."""
    try:
        req = urllib.request.Request(
            sub_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8").strip()
            try:
                decoded = base64.b64decode(content).decode("utf-8")
                logger.info(f"Base64 decoded: {sub_url[:50]}...")
                return decoded.splitlines()
            except Exception:
                logger.info(f"Plain text: {sub_url[:50]}...")
                return content.splitlines()
    except Exception as e:
        logger.error(f"Failed to fetch {sub_url}: {e}")
        return []


# ==================== Xray Parser ====================
def to_xray_outbound(link: str, tag: str) -> Optional[Dict[str, Any]]:
    """Convert VLESS link to Xray outbound object."""
    try:
        if not is_valid_vless(link):
            return None
        parsed = urlparse(link)
        uuid = parsed.username
        addr = parsed.hostname
        port = parsed.port or 443
        if not uuid or not addr:
            return None

        q = parse_qs(parsed.query)
        net = q.get("type", ["tcp"])[0]
        sec = q.get("security", ["none"])[0]
        path = unquote(q.get("path", ["/"])[0])
        host = q.get("host", [""])[0]
        sni = q.get("sni", [""])[0]
        fp = q.get("fp", ["chrome"])[0]
        alpn_raw = q.get("alpn", [""])[0]
        alpn = [x.strip() for x in alpn_raw.split(",") if x.strip()]

        port_num = int(port)
        if not 1 <= port_num <= 65535:
            raise ValueError("port out of range")

        out = {
            "mux": {"concurrency": -1, "enabled": False},
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": addr,
                    "port": port_num,
                    "users": [{"encryption": "none", "id": uuid, "level": 8}],
                }]
            },
            "streamSettings": {"network": net},
            "tag": tag,
        }

        if net == "ws":
            ws = {"headers": {}}
            if host:
                ws["headers"]["Host"] = host
            if path:
                ws["path"] = path
            out["streamSettings"]["wsSettings"] = ws
        elif net == "grpc":
            svc = q.get("serviceName", [""])[0]
            if svc:
                out["streamSettings"]["grpcSettings"] = {"serviceName": svc}

        if sec == "tls":
            out["streamSettings"]["security"] = "tls"
            tls = {"allowInsecure": False, "show": False, "serverName": sni or addr}
            if fp:
                tls["fingerprint"] = fp
            if alpn:
                tls["alpn"] = alpn
            out["streamSettings"]["tlsSettings"] = tls
        elif sec == "reality":
            out["streamSettings"]["security"] = "reality"
            reality = {
                "show": False,
                "publicKey": q.get("pbk", [""])[0],
                "shortId": q.get("sid", [""])[0],
                "serverName": sni or addr,
            }
            if fp:
                reality["fingerprint"] = fp
            out["streamSettings"]["realitySettings"] = reality

        return out
    except Exception as e:
        logger.error(f"Xray parse error for {link[:50]}...: {e}")
        return None


# ==================== Sing‑Box Parser (Advanced) ====================
def to_singbox_outbound(link: str, tag: str) -> Optional[Dict[str, Any]]:
    """Convert VLESS link to Sing‑Box outbound (matches sample structure)."""
    try:
        if not is_valid_vless(link):
            return None
        parsed = urlparse(link)
        uuid = parsed.username
        addr = parsed.hostname
        port = parsed.port or 443
        if not uuid or not addr:
            return None

        q = parse_qs(parsed.query)
        net = q.get("type", ["tcp"])[0]
        sec = q.get("security", ["none"])[0]
        path = unquote(q.get("path", ["/"])[0])
        host = q.get("host", [""])[0]
        sni = q.get("sni", [""])[0]
        fp = q.get("fp", ["chrome"])[0]
        alpn_raw = q.get("alpn", [""])[0]
        alpn = [x.strip() for x in alpn_raw.split(",") if x.strip()]

        port_num = int(port)
        if not 1 <= port_num <= 65535:
            raise ValueError("port out of range")

        out: Dict[str, Any] = {
            "type": "vless",
            "tag": tag,
            "server": addr,
            "server_port": port_num,
            "uuid": uuid,
            "flow": "xtls-rprx-vision" if sec in ("tls", "reality") else "",
        }

        # Transport
        if net in ("ws", "grpc"):
            tr: Dict[str, Any] = {"type": net}
            if net == "ws":
                if path:
                    tr["path"] = path
                if host:
                    tr["headers"] = {"Host": host}
            elif net == "grpc":
                svc = q.get("serviceName", [""])[0]
                if svc:
                    tr["service_name"] = svc
            out["transport"] = tr
        else:
            out["transport"] = {}

        # TLS / Reality
        if sec in ("tls", "reality"):
            tls: Dict[str, Any] = {"enabled": True, "server_name": sni or addr}
            if fp:
                tls["utls"] = {"enabled": True, "fingerprint": fp}
            if alpn:
                tls["alpn"] = alpn
            if sec == "reality":
                tls["reality"] = {
                    "enabled": True,
                    "public_key": q.get("pbk", [""])[0],
                    "short_id": q.get("sid", [""])[0],
                }
            out["tls"] = tls
        else:
            out["tls"] = {"enabled": False}

        return out
    except Exception as e:
        logger.error(f"Sing‑Box parse error for {link[:50]}...: {e}")
        return None


# ==================== Build Xray Full Config ====================
def build_xray_config(outbounds: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate complete Xray/V2Ray JSON."""
    config: Dict[str, Any] = {
        "dns": {
            "hosts": {
                "domain:googleapis.cn": "googleapis.com",
                "dns.alidns.com": ["223.5.5.5", "223.6.6.6", "2400:3200::1", "2400:3200:baba::1"],
                "one.one.one.one": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
                "dns.cloudflare.com": ["104.16.132.229", "104.16.133.229", "2606:4700::6810:84e5", "2606:4700::6810:85e5"],
                "dns.google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
            },
            "servers": [
                "1.1.1.1",
                {"address": "1.1.1.1", "domains": ["geosite:google"]},
                {
                    "address": "223.5.5.5",
                    "domains": ["domain:alidns.com", "domain:doh.pub", "domain:dot.pub", "geosite:cn"],
                    "expectIPs": ["geoip:cn"],
                    "skipFallback": True,
                    "tag": "domestic-dns",
                },
            ],
            "tag": "dns-module",
        },
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": 10808,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
            "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": False},
            "tag": "socks",
        }],
        "log": {"loglevel": "warning"},
        "observatory": {
            "enableConcurrency": True,
            "probeInterval": "3m",
            "probeUrl": "https://www.gstatic.com/generate_204",
            "subjectSelector": ["proxy-"],
        },
        "outbounds": outbounds + [
            {"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"},
            {"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"},
        ],
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
            "system": {"statsOutboundDownlink": True, "statsOutboundUplink": True},
        },
        "remarks": "javidsub Intelligent Selection",
        "routing": {
            "balancers": [{"selector": ["proxy-"], "strategy": {"type": "leastPing"}, "tag": "proxy-round"}],
            "domainStrategy": "AsIs",
            "rules": [
                {"network": "udp", "outboundTag": "block", "port": "443", "type": "field"},
                {"balancerTag": "proxy-round", "domain": ["geosite:google"], "type": "field"},
                {"ip": ["geoip:private"], "outboundTag": "direct", "type": "field"},
                {"domain": ["geosite:private"], "outboundTag": "direct", "type": "field"},
                {"ip": ["geoip:cn"], "outboundTag": "direct", "type": "field"},
                {"domain": ["geosite:cn"], "outboundTag": "direct", "type": "field"},
                {"inboundTag": ["domestic-dns"], "outboundTag": "direct", "type": "field"},
                {"balancerTag": "proxy-round", "inboundTag": ["dns-module"], "type": "field"},
                {"balancerTag": "proxy-round", "network": "tcp,udp", "type": "field"},
            ],
        },
        "stats": {},
    }
    return config


# ==================== Build Sing‑Box Full Config (like sample) ====================
def build_singbox_config(outbounds: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate Sing‑Box JSON exactly matching the provided sample structure.
    Includes TUN, FakeIP DNS, Rule Sets, Clash API, NTP, etc.
    """
    proxy_tags = [ob["tag"] for ob in outbounds]

    config: Dict[str, Any] = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [
                {
                    "type": "https",
                    "server": "8.8.8.8",
                    "detour": "زن زندگی آزادی",
                    "tag": "dns-remote",
                },
                {"type": "udp", "server": "8.8.8.8", "server_port": 53, "tag": "dns-direct"},
                {
                    "type": "fakeip",
                    "tag": "dns-fake",
                    "inet4_range": "198.18.0.0/15",
                    "inet6_range": "fc00::/18",
                },
            ],
            "rules": [
                {"domain": ["raw.githubusercontent.com"], "server": "dns-direct"},
                {"clash_mode": "Direct", "server": "dns-direct"},
                {"clash_mode": "Global", "server": "dns-remote"},
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [{"rule_set": "geosite-ir"}, {"rule_set": "geoip-ir"}],
                    "action": "route",
                    "server": "dns-direct",
                },
                {
                    "rule_set": [
                        "geosite-malware",
                        "geosite-phishing",
                        "geosite-cryptominers",
                        "geosite-category-ads-all",
                    ],
                    "action": "reject",
                },
                {
                    "disable_cache": True,
                    "inbound": "tun-in",
                    "query_type": ["A", "AAAA"],
                    "server": "dns-fake",
                },
            ],
            "strategy": "ipv4_only",
            "independent_cache": True,
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"],
                "mtu": 9000,
                "auto_route": True,
                "strict_route": True,
                "endpoint_independent_nat": True,
                "stack": "mixed",
            },
            {"type": "mixed", "tag": "mixed-in", "listen": "0.0.0.0", "listen_port": 2080},
        ],
        "outbounds": [],  # will be filled below
        "route": {
            "rules": [
                {"ip_cidr": "172.18.0.2", "action": "hijack-dns"},
                {"clash_mode": "Direct", "outbound": "direct"},
                {"clash_mode": "Global", "outbound": "زن زندگی آزادی"},
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"network": "udp", "action": "reject"},
                {
                    "rule_set": [
                        "geosite-malware",
                        "geosite-phishing",
                        "geosite-cryptominers",
                        "geosite-category-ads-all",
                    ],
                    "action": "reject",
                },
                {"rule_set": ["geoip-malware", "geoip-phishing"], "action": "reject"},
                {"rule_set": ["geosite-ir"], "action": "route", "outbound": "direct"},
                {"rule_set": ["geoip-ir"], "action": "route", "outbound": "direct"},
            ],
            "rule_set": [
                {
                    "type": "remote",
                    "tag": "geosite-malware",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-malware.srs",
                    "download_detour": "direct",
                },
                {
                    "type": "remote",
                    "tag": "geoip-malware",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-malware.srs",
                    "download_detour": "direct",
                },
                {
                    "type": "remote",
                    "tag": "geosite-phishing",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-phishing.srs",
                    "download_detour": "direct",
                },
                {
                    "type": "remote",
                    "tag": "geoip-phishing",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-phishing.srs",
                    "download_detour": "direct",
                },
                {
                    "type": "remote",
                    "tag": "geosite-cryptominers",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-cryptominers.srs",
                    "download_detour": "direct",
                },
                {
                    "type": "remote",
                    "tag": "geosite-category-ads-all",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-category-ads-all.srs",
                    "download_detour": "direct",
                },
                {
                    "type": "remote",
                    "tag": "geosite-ir",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geosite-ir.srs",
                    "download_detour": "direct",
                },
                {
                    "type": "remote",
                    "tag": "geoip-ir",
                    "format": "binary",
                    "url": "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/geoip-ir.srs",
                    "download_detour": "direct",
                },
            ],
            "auto_detect_interface": True,
            "default_domain_resolver": {
                "server": "dns-direct",
                "strategy": "prefer_ipv4",
                "rewrite_ttl": 60,
            },
            "final": "زن زندگی آزادی",
        },
        "ntp": {
            "enabled": True,
            "server": "time.cloudflare.com",
            "server_port": 123,
            "domain_resolver": "dns-direct",
            "interval": "30m",
            "write_to_system": False,
        },
        "experimental": {
            "cache_file": {"enabled": True, "store_fakeip": True},
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "external_ui": "ui",
                "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip",
                "external_ui_download_detour": "direct",
                "default_mode": "Rule",
            },
        },
    }

    # 1. Add all proxy outbounds with Persian numbering and a fixed flag (🇺🇸)
    #    You can change the flag logic if you have country info.
    for idx, ob in enumerate(outbounds, start=1):
        # Use Persian numerals
        persian_num = {
            1: "۱", 2: "۲", 3: "۳", 4: "۴", 5: "۵",
            6: "۶", 7: "۷", 8: "۸", 9: "۹", 10: "۱۰",
            11: "۱۱", 12: "۱۲", 13: "۱۳", 14: "۱۴", 15: "۱۵",
            16: "۱۶", 17: "۱۷", 18: "۱۸", 19: "۱۹", 20: "۲۰",
        }.get(idx, str(idx))
        # Use a generic name; you can change to "زن زندگی آزادی" if you prefer.
        ob["tag"] = f"{persian_num} - پروکسی 🇺🇸"
        config["outbounds"].append(ob)

    # 2. Selector (manual) – named "زن زندگی آزادی" as in sample
    config["outbounds"].append({
        "type": "selector",
        "tag": "زن زندگی آزادی",
        "outbounds": proxy_tags + ["direct"],
    })

    # 3. Direct
    config["outbounds"].append({"type": "direct", "tag": "direct"})

    # 4. urltest (auto-ping) – named "بهترین پینگ"
    config["outbounds"].append({
        "type": "urltest",
        "tag": "بهترین پینگ",
        "outbounds": proxy_tags,
        "url": "https://www.gstatic.com/generate_204",
        "interrupt_exist_connections": False,
        "interval": "30s",
    })

    # Note: The sample has both a selector and urltest, but the final route uses selector.
    # We keep both, and set final to selector as in sample.
    return config


# ==================== Main ====================
def main() -> None:
    sub_env = os.environ.get("SUB_URLS", "")
    sub_urls = [u.strip() for u in sub_env.splitlines() if u.strip()]

    if not sub_urls:
        logger.error("SUB_URLS environment variable is empty or not set.")
        return

    all_links: List[str] = []
    seen: Set[str] = set()

    for url in sub_urls:
        logger.info(f"Fetching: {url[:50]}...")
        lines = fetch_subscription(url)
        for line in lines:
            line = line.strip()
            if is_valid_vless(line) and line not in seen:
                seen.add(line)
                all_links.append(line)

    logger.info(f"Total unique VLESS links: {len(all_links)}")
    if not all_links:
        logger.warning("No valid VLESS links found.")
        return

    # 1. Raw links
    with open("javidsub", "w", encoding="utf-8") as f:
        f.write("\n".join(all_links))
    logger.info("Saved raw links to javidsub")

    # 2. Xray outbounds
    xray_outs: List[Dict[str, Any]] = []
    for idx, link in enumerate(all_links, start=1):
        tag = f"proxy-{idx}"
        ob = to_xray_outbound(link, tag)
        if ob:
            xray_outs.append(ob)
        else:
            logger.warning(f"Xray parse failed for #{idx}")

    xray_config = build_xray_config(xray_outs)
    with open("final_sub.txt", "w", encoding="utf-8") as f:
        json.dump(xray_config, f, ensure_ascii=False, indent=2)
    logger.info("Saved Xray config to final_sub.txt")

    # 3. Sing‑Box outbounds (with advanced structure)
    sb_outs: List[Dict[str, Any]] = []
    for idx, link in enumerate(all_links, start=1):
        # temporary tag; will be renamed in build_singbox_config
        tag = f"proxy-{idx}"
        ob = to_singbox_outbound(link, tag)
        if ob:
            sb_outs.append(ob)
        else:
            logger.warning(f"Sing‑Box parse failed for #{idx}")

    sb_config = build_singbox_config(sb_outs)
    with open("javidbox.json", "w", encoding="utf-8") as f:
        json.dump(sb_config, f, ensure_ascii=False, indent=2)
    logger.info("✅ Saved Sing‑Box config to javidbox.json (full sample structure)")


if __name__ == "__main__":
    main()
