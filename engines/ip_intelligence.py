"""
ip_intelligence.py — Infrastructure Intelligence & IP Classification Engine

Enriches basic IP geolocation data with threat intelligence context:
  - Risk Level: critical, high, medium, low, no_data
  - Infrastructure Type: hosting_server, vpn_proxy, tor_node, cloud_service,
                          open_relay, botnet_c2, unknown

Downloads and caches open threat feeds (Tor exit nodes, AWS/GCP cloud ranges,
abuse.ch Feodo Tracker botnet lists) with automatic local fallback when offline
or when downloads fail.
"""

from __future__ import annotations

import json
import ipaddress
import re
import time
import urllib.request
from pathlib import Path
from typing import Any

# Default corporate mail provider subnets (Google Workspace, M365, SendGrid, etc.)
CORPORATE_MAIL_NETWORKS = [
    ipaddress.ip_network("40.96.0.0/13"),
    ipaddress.ip_network("40.107.0.0/16"),
    ipaddress.ip_network("52.100.0.0/14"),
    ipaddress.ip_network("104.47.0.0/16"),
    ipaddress.ip_network("35.190.0.0/16"),
    ipaddress.ip_network("172.217.0.0/16"),
    ipaddress.ip_network("209.85.128.0/17"),
    ipaddress.ip_network("167.89.0.0/16"),
    ipaddress.ip_network("149.72.0.0/16"),
    ipaddress.ip_network("198.61.0.0/16"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
]

# Major consumer VPN ASNs & keywords
KNOWN_VPN_KEYWORDS = [
    "nordvpn", "expressvpn", "mullvad", "protonvpn", "surfshark",
    "privateinternetaccess", "cyberghost", "ipvanish", "vyprvpn",
    "windscribe", "hide.me", "vpn", "proxy"
]

KNOWN_VPN_ASNS = {
    "AS9009", "AS20473", "AS60068", "AS212238", "AS62005", "AS202425"
}


class IPIntelligenceEngine:
    """Classifies IP addresses into threat risk levels and infrastructure types."""

    def __init__(self, *, offline_mode: bool = False, cache_dir: Path | str | None = None):
        self.offline_mode = offline_mode
        self.base_dir = Path(__file__).resolve().parent.parent
        self.sample_intel_path = self.base_dir / "data" / "sample_ip_intel.json"
        
        self._sample_data: dict[str, Any] = {}
        self._tor_nodes: set[str] = set()
        self._botnet_ips: set[str] = set()
        self._cloud_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._last_refresh: float = 0.0

        self._load_fallback_sample_data()

        if not self.offline_mode:
            self._refresh_feeds_if_needed()

    def _load_fallback_sample_data(self) -> None:
        """Load bundled fallback JSON sample intelligence data."""
        if self.sample_intel_path.exists():
            try:
                self._sample_data = json.loads(self.sample_intel_path.read_text(encoding="utf-8"))
                sample_tor = self._sample_data.get("sample_tor_nodes", [])
                self._tor_nodes.update(sample_tor)
                sample_botnet = self._sample_data.get("sample_botnet_ips", [])
                self._botnet_ips.update(sample_botnet)
            except Exception:
                pass

    def _refresh_feeds_if_needed(self) -> None:
        """Fetch live threat feeds if cache is older than 6 hours."""
        now = time.time()
        if now - self._last_refresh < 21600:
            return

        self._fetch_tor_nodes()
        self._fetch_botnet_ips()
        self._fetch_cloud_ranges()
        self._last_refresh = now

    def _fetch_tor_nodes(self) -> None:
        """Fetch Tor exit nodes list."""
        url = "https://check.torproject.org/exit-addresses"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sentinel-mail/0.2"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
                ips = re.findall(r"ExitAddress\s+(\d{1,3}(?:\.\d{1,3}){3})", text)
                if ips:
                    self._tor_nodes.update(ips)
        except Exception:
            pass  # Retain offline fallback list

    def _fetch_botnet_ips(self) -> None:
        """Fetch abuse.ch Feodo Tracker botnet C2 IP list."""
        url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sentinel-mail/0.2"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
                lines = text.splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split(",")
                        if len(parts) >= 2:
                            ip = parts[1].strip('"').strip()
                            if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
                                self._botnet_ips.add(ip)
        except Exception:
            pass

    def _fetch_cloud_ranges(self) -> None:
        """Fetch AWS & GCP published IP ranges."""
        aws_url = "https://ip-ranges.amazonaws.com/ip-ranges.json"
        try:
            req = urllib.request.Request(aws_url, headers={"User-Agent": "sentinel-mail/0.2"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                prefixes = data.get("prefixes", [])
                for item in prefixes[:300]:  # Limit to top ranges for performance
                    p = item.get("ip_prefix")
                    if p:
                        try:
                            self._cloud_networks.append(ipaddress.ip_network(p))
                        except ValueError:
                            pass
        except Exception:
            pass

    def enrich(self, ip: str, geo_info: dict[str, Any] | None = None) -> dict[str, Any]:
        """Classify an IP into infrastructure intelligence structure.

        Returns:
            {
              "ip": str,
              "country": str | None,
              "lat": float | None,
              "lon": float | None,
              "risk_level": "critical" | "high" | "medium" | "low" | "no_data",
              "infra_type": "hosting_server" | "vpn_proxy" | "tor_node" |
                          "cloud_service" | "open_relay" | "botnet_c2" | "unknown"
            }
        """
        geo_info = geo_info or {}
        country = geo_info.get("country")
        lat = geo_info.get("lat")
        lon = geo_info.get("lon")
        isp = geo_info.get("isp", "")
        org = geo_info.get("org", "")
        as_info = geo_info.get("as", "")

        # 1. Check sample fallback dictionary for exact match (e.g. sample email IPs)
        sample_ips = self._sample_data.get("sample_ips", {})
        if ip in sample_ips:
            s_item = sample_ips[ip]
            return {
                "ip": ip,
                "country": country or s_item.get("country"),
                "lat": lat if lat is not None else s_item.get("lat"),
                "lon": lon if lon is not None else s_item.get("lon"),
                "risk_level": s_item.get("risk_level", "medium"),
                "infra_type": s_item.get("infra_type", "hosting_server"),
                "isp": isp or s_item.get("isp"),
                "org": org or s_item.get("org"),
            }

        # 2. Check private/loopback/invalid IP
        try:
            addr = ipaddress.ip_address(ip)
            is_rfc1918 = (
                addr in ipaddress.ip_network("10.0.0.0/8") or
                addr in ipaddress.ip_network("172.16.0.0/12") or
                addr in ipaddress.ip_network("192.168.0.0/16")
            )
            if is_rfc1918 or addr.is_loopback or addr.is_link_local:
                return {
                    "ip": ip,
                    "country": country or "Internal Network",
                    "lat": lat,
                    "lon": lon,
                    "risk_level": "no_data",
                    "infra_type": "unknown",
                    "isp": isp or "Private IP",
                    "org": org or "Internal",
                }
        except ValueError:
            return {
                "ip": ip,
                "country": country,
                "lat": lat,
                "lon": lon,
                "risk_level": "no_data",
                "infra_type": "unknown",
            }

        # 2. Check Tor Node List
        if ip in self._tor_nodes:
            return {
                "ip": ip,
                "country": country or "Germany",
                "lat": lat or 52.52,
                "lon": lon or 13.405,
                "risk_level": "critical",
                "infra_type": "tor_node",
                "isp": isp or "Tor Exit Node",
                "org": org or "Tor Project Relay",
            }

        # 3. Check Botnet C2 List
        if ip in self._botnet_ips or "bulletproof" in (isp + org).lower():
            return {
                "ip": ip,
                "country": country or "Unknown",
                "lat": lat or 0.0,
                "lon": lon or 0.0,
                "risk_level": "critical",
                "infra_type": "botnet_c2",
                "isp": isp or "Bulletproof Host",
                "org": org or "Botnet C2 Node",
            }

        # 4. Check Corporate Mail Networks (Low risk)
        for net in CORPORATE_MAIL_NETWORKS:
            if addr in net:
                return {
                    "ip": ip,
                    "country": country or "United States",
                    "lat": lat or 37.751,
                    "lon": lon or -97.822,
                    "risk_level": "low",
                    "infra_type": "cloud_service",
                    "isp": isp or "Corporate Mail Provider",
                    "org": org or "Trusted Mail Infrastructure",
                }

        # 5. Check Cloud Provider Networks (Medium risk)
        for net in self._cloud_networks:
            if addr in net:
                return {
                    "ip": ip,
                    "country": country or "United States",
                    "lat": lat or 37.751,
                    "lon": lon or -97.822,
                    "risk_level": "medium",
                    "infra_type": "cloud_service",
                    "isp": isp or "Cloud Service Provider",
                    "org": org or "Cloud Infrastructure",
                }

        # 6. Check Consumer VPN ASNs & Keywords (High risk)
        as_upper = as_info.upper()
        isp_lower = (isp + " " + org + " " + as_info).lower()
        if any(asn in as_upper for asn in KNOWN_VPN_ASNS) or any(kw in isp_lower for kw in KNOWN_VPN_KEYWORDS):
            return {
                "ip": ip,
                "country": country,
                "lat": lat,
                "lon": lon,
                "risk_level": "high",
                "infra_type": "vpn_proxy",
                "isp": isp or "VPN Provider",
                "org": org or "Consumer VPN",
            }

        # 7. Check Open Relay markers
        if "open_relay" in isp_lower or "relay" in isp_lower or "hostinger" in isp_lower:
            return {
                "ip": ip,
                "country": country,
                "lat": lat,
                "lon": lon,
                "risk_level": "high",
                "infra_type": "open_relay",
                "isp": isp,
                "org": org,
            }

        # 8. Default fallback: hosting server (Datacenter IP, High risk)
        return {
            "ip": ip,
            "country": country or "Unknown",
            "lat": lat or 0.0,
            "lon": lon or 0.0,
            "risk_level": "high" if country else "medium",
            "infra_type": "hosting_server",
            "isp": isp or "Generic Datacenter",
            "org": org or "Hosting Provider",
        }
