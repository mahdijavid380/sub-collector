import base64
import json
import logging
import os
import re
import urllib.request
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, unquote, urlparse

# ==================== Logging Setup ====================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


# ==================== Validation ====================
def is_valid_vless_url(url: str) -> bool:
    """Check if the URL is a valid VLESS link."""
    if not url or not url.startswith("vless://"):
        return False
    pattern = r"^vless://[a-f0-9\-]{36}@[a-zA-Z0-9\.\-]+:\d+.*$"
    return bool(re.match(pattern, url))


# ==================== Fetching & Decoding ====================
def fetch_and_decode(sub_url: str) -> List[str]:
    """
    Fetch a subscription URL, decode if Base64, return list of lines.
    """
    try:
        req = urllib.request.Request(
            sub_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        with urllib.request.urlopen(req, timeout=15) as response:
            content = response.read().decode("utf-8").strip()
            # Try Base64 decode
            try:
                decoded = base64.b64decode(content).decode("utf-8")
                logger.info(f"Base64 decoded content from {sub_url[:50]}...")
                return decoded.splitlines()
            except Exception:
                logger.info(f"Plain text content from {sub_url[:50]}...")
                return content.splitlines()
    except urllib.error.URLError as e:
        logger.error(f"Network error fetching {sub_url}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error fetching {sub_url}: {e}")
    return []


# ==================== Xray/V2Ray Parser ====================
def parse_vless_to_xray(vless_url: str, tag: str) -> Optional[Dict[str, Any]]:
    """Convert VLESS URL to Xray outbound object."""
    try:
        if not is_valid_vless_url(vless_url):
            return None

        parsed = urlparse(vless_url)
        uuid = parsed.username
        address = parsed.hostname
        port = parsed.port or 443

        if not uuid or not address:
            logger.warning(f"Missing UUID/address in {vless_url[:50]}...")
            return None

        params = parse_qs(parsed.query)
        network = params.get("type", ["tcp"])[0]
        security = params.get("security", ["none"])[0]
        path = unquote(params.get("path", ["/"])[0])
        host = params.get("host", [""])[0]
        sni = params.get("sni", [""])[0]
        fp = params.get("fp", ["chrome"])[0]
        alpn_raw = params.get("alpn", [""])[0]
        alpn = [x.strip() for x in alpn_raw.split(",") if x.strip()]

        try:
            port_num = int(port)
            if not 1 <= port_num <= 65535:
                raise ValueError("Port out of range")
        except ValueError:
            logger.warning(f"Invalid port: {port}")
            return None

        outbound: Dict[str, Any] = {
            "mux": {"concurrency": -1, "enabled": False},
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": address,
                        "port": port_num,
                        "users": [{"encryption": "none", "id": uuid, "level": 8}],
                    }
                ]
            },
            "streamSettings": {"network": network},
            "tag": tag,
        }

        # Stream settings
        if network == "ws":
            ws: Dict[str, Any] = {"headers": {}}
            if host:
                ws["headers"]["Host"] = host
            if path:
                ws["path"] = path
            outbound["streamSettings"]["wsSettings"] = ws

        elif network == "grpc":
            service_name = params.get("serviceName", [""])[0]
            if service_name:
                outbound["streamSettings"]["grpcSettings"] = {
                    "serviceName": service_name
                }

        # TLS / Reality
        if security == "tls":
            outbound["streamSettings"]["security"] = "tls"
            tls: Dict[str, Any] = {"allowInsecure": False, "show": False}
            tls["serverName"] = sni or address
            if fp:
                tls["fingerprint"] = fp
            if alpn:
                tls["alpn"] = alpn
            outbound["streamSettings"]["tlsSettings"] = tls

        elif security == "reality":
            outbound["streamSettings"]["security"] = "reality"
            reality: Dict[str, Any] = {
                "show": False,
                "publicKey": params.get("pbk", [""])[0],
                "shortId": params.get("sid", [""])[0],
            }
            reality["serverName"] = sni or address
            if fp:
                reality["fingerprint"] = fp
            outbound["streamSettings"]["realitySettings"] = reality

        return outbound

    except Exception as e:
        logger.error(f"Error parsing Xray outbound: {e}")
        return None


# ==================== Sing-Box Parser ====================
def parse_vless_to_singbox(vless_url: str, tag: str) -> Optional[Dict[str, Any]]:
    """Convert VLESS URL to Sing-Box outbound object."""
    try:
        if not is_valid_vless_url(vless_url):
            return None

        parsed = urlparse(vless_url)
        uuid = parsed.username
        address = parsed.hostname
        port = parsed.port or 443

        if not uuid or not address:
            logger.warning(f"Missing UUID/address in {vless_url[:50]}...")
            return None

        params = parse_qs(parsed.query)
        network = params.get("type", ["tcp"])[0]
        security = params.get("security", ["none"])[0]
        path = unquote(params.get("path", ["/"])[0])
        host = params.get("host", [""])[0]
        sni = params.get("sni", [""])[0]
        fp = params.get("fp", ["chrome"])[0]
        alpn_raw = params.get("alpn", [""])[0]
        alpn = [x.strip() for x in alpn_raw.split(",") if x.strip()]

        try:
            port_num = int(port)
            if not 1 <= port_num <= 65535:
                raise ValueError("Port out of range")
        except ValueError:
            logger.warning(f"Invalid port: {port}")
            return None

        outbound: Dict[str, Any] = {
            "type": "vless",
            "tag": tag,
            "server": address,
            "server_port": port_num,
            "uuid": uuid,
            "flow": "none",  # default
        }

        # Transport
        transport: Dict[str, Any] = {"type": network}
        if network == "ws":
            if path:
                transport["path"] = path
            if host:
                transport["headers"] = {"Host": host}
        elif network == "grpc":
            service_name = params.get("serviceName", [""])[0]
            if service_name:
                transport["service_name"] = service_name

        if network in ("ws", "grpc"):
            outbound["transport"] = transport

        # TLS / Reality
        if security in ("tls", "reality"):
            tls_obj: Dict[str, Any] = {"enabled": True}
            tls_obj["server_name"] = sni or address
            if fp:
                tls_obj["utls"] = {"enabled": True, "fingerprint": fp}
            if alpn:
                tls_obj["alpn"] = alpn

            if security == "reality":
                tls_obj["reality"] = {
                    "enabled": True,
                    "public_key": params.get("pbk", [""])[0],
                    "short_id": params.get("sid", [""])[0],
                }
            outbound["tls"] = tls_obj

        return outbound

    except Exception as e:
        logger.error(f"Error parsing Sing-Box outbound: {e}")
        return None


# ==================== Generate Xray Full JSON ====================
def generate_xray_full(outbounds: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate the full Xray/V2Ray JSON configuration."""
    base: Dict[str, Any] = {
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
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 10808,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "userLevel": 8},
                "sniffing": {"destOverride": ["http", "tls"], "enabled": True, "routeOnly": False},
                "tag": "socks",
            }
        ],
        "log": {"loglevel": "warning"},
        "observatory": {
            "enableConcurrency": True,
            "probeInterval": "3m",
            "probeUrl": "https://www.gstatic.com/generate_204",
            "subjectSelector": ["proxy-"],
        },
        "outbounds": [],
        "policy": {
            "levels": {"8": {"connIdle": 300, "downlinkOnly": 1, "handshake": 4, "uplinkOnly": 1}},
            "system": {"statsOutboundDownlink": True, "statsOutboundUplink": True},
        },
        "remarks": "javidsub Intelligent Selection",
        "routing": {
            "balancers": [
                {
                    "selector": ["proxy-"],
                    "strategy": {"type": "leastPing"},
                    "tag": "proxy-round",
                }
            ],
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

    base["outbounds"].extend(outbounds)
    base["outbounds"].append({"protocol": "freedom", "settings": {"domainStrategy": "UseIP"}, "tag": "direct"})
    base["outbounds"].append({"protocol": "blackhole", "settings": {"response": {"type": "http"}}, "tag": "block"})
    return base


# ==================== Generate Sing-Box JSON ====================
def generate_singbox_full(outbounds: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generate full Sing-Box JSON with urltest, selector, and routing."""
    proxy_tags = [ob["tag"] for ob in outbounds]

    # Base structure
    config: Dict[str, Any] = {
        "log": {"level": "warning"},
        "dns": {
            "servers": [
                {"tag": "cloudflare", "address": "1.1.1.1"},
                {"tag": "google", "address": "8.8.8.8"},
                {"tag": "local", "address": "223.5.5.5", "detour": "direct"},
            ],
            "rules": [
                {"outbound": "any", "server": "local", "domain_suffix": ["ir"]},
                {"outbound": "any", "server": "local", "geosite": ["cn"]},
                {"outbound": "any", "server": "cloudflare", "geosite": ["google"]},
            ],
            "final": "cloudflare",
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": 10808,
            },
            {
                "type": "http",
                "tag": "http-in",
                "listen": "127.0.0.1",
                "listen_port": 10809,
            },
        ],
        "outbounds": [],
        "route": {
            "rules": [
                {"outbound": "direct", "ip_is_private": True},
                {"outbound": "direct", "geoip": ["cn"]},
                {"outbound": "direct", "geosite": ["cn"]},
                {"outbound": "proxy", "geosite": ["google"]},
                {"outbound": "proxy", "network": ["tcp", "udp"]},  # catch-all
            ],
            "final": "proxy",
            "auto_detect_interface": True,
        },
    }

    # Add proxy outbounds
    config["outbounds"].extend(outbounds)

    # urltest outbound
    config["outbounds"].append(
        {
            "type": "urltest",
            "tag": "proxy",
            "outbounds": proxy_tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "3m",
            "tolerance": 50,
        }
    )

    # selector outbound (manual selection)
    config["outbounds"].append(
        {
            "type": "selector",
            "tag": "select",
            "outbounds": ["proxy", "direct"],
            "default": "proxy",
        }
    )

    # direct and block
    config["outbounds"].append({"type": "direct", "tag": "direct"})
    config["outbounds"].append({"type": "block", "tag": "block"})

    # Update route final to use selector or proxy? Usually we want auto-select via urltest,
    # but we can set final to "proxy" (urltest) and also have selector for manual override.
    # The route's final is "proxy", which is urltest.
    # Users can switch to "select" in their client if they want manual.
    config["route"]["final"] = "proxy"

    return config


# ==================== Main ====================
def main() -> None:
    """Main entry point."""
    raw_urls = os.environ.get("SUB_URLS", "")
    urls = [u.strip() for u in raw_urls.splitlines() if u.strip()]

    if not urls:
        logger.error("No URLs found in SUB_URLS environment variable!")
        return

    all_links: List[str] = []
    seen: Set[str] = set()

    # Fetch and deduplicate
    for sub_url in urls:
        logger.info(f"Fetching subscription: {sub_url[:50]}...")
        lines = fetch_and_decode(sub_url)
        for line in lines:
            line = line.strip()
            if is_valid_vless_url(line) and line not in seen:
                seen.add(line)
                all_links.append(line)

    logger.info(f"Total unique VLESS links: {len(all_links)}")

    if not all_links:
        logger.warning("No valid VLESS configurations found.")
        return

    # 1. Save raw links to javidsub
    with open("javidsub", "w", encoding="utf-8") as f:
        f.write("\n".join(all_links))
    logger.info("Saved raw links to javidsub")

    # 2. Parse for Xray
    xray_outbounds: List[Dict[str, Any]] = []
    for idx, link in enumerate(all_links, start=1):
        tag = f"proxy-{idx}"
        ob = parse_vless_to_xray(link, tag)
        if ob:
            xray_outbounds.append(ob)
        else:
            logger.warning(f"Failed to parse Xray config #{idx}")

    logger.info(f"Xray outbounds parsed: {len(xray_outbounds)} / {len(all_links)}")

    # Generate final_sub.txt (Xray full config)
    xray_full = generate_xray_full(xray_outbounds)
    with open("final_sub.txt", "w", encoding="utf-8") as f:
        json.dump(xray_full, f, ensure_ascii=False, indent=2)
    logger.info("Saved Xray configuration to final_sub.txt")

    # 3. Parse for Sing-Box
    singbox_outbounds: List[Dict[str, Any]] = []
    for idx, link in enumerate(all_links, start=1):
        tag = f"proxy-{idx}"
        ob = parse_vless_to_singbox(link, tag)
        if ob:
            singbox_outbounds.append(ob)
        else:
            logger.warning(f"Failed to parse Sing-Box config #{idx}")

    logger.info(f"Sing-Box outbounds parsed: {len(singbox_outbounds)} / {len(all_links)}")

    # Generate javidbox.json
    singbox_full = generate_singbox_full(singbox_outbounds)
    with open("javidbox.json", "w", encoding="utf-8") as f:
        json.dump(singbox_full, f, ensure_ascii=False, indent=2)
    logger.info("Saved Sing-Box configuration to javidbox.json")


if __name__ == "__main__":
    main()
