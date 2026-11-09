"""
header_parser.py — Email Header Analysis Engine

Parses raw .eml files and produces a structured threat-assessment dict
covering four dimensions:

  relay_path      Ordered list of SMTP hops extracted from Received headers.
  auth_results    SPF / DKIM / DMARC verdicts (parsed from the email's own
                  Authentication-Results header, supplemented with live DNS
                  record lookups when available).
  spoofing_flags  Domain-mismatch and lookalike detections across the
                  From / Reply-To / Return-Path triple.
  geo_trace       IP-geolocation data for every public relay hop
                  (free-tier ip-api.com, with caching and rate limiting).
"""

from __future__ import annotations

import email
import email.policy
import email.utils
import ipaddress
import json
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path
from typing import Any

from engines.ip_intelligence import IPIntelligenceEngine

# Optional: dnspython for live DNS validation
try:
    import dns.resolver
    import dns.rdatatype
    import dns.exception

    _HAS_DNS = True
except ImportError:  # pragma: no cover
    _HAS_DNS = False

# ── Well-known domains for lookalike detection ─────────────────────────

WELL_KNOWN_DOMAINS: list[str] = [
    "microsoft.com",
    "outlook.com",
    "office365.com",
    "google.com",
    "gmail.com",
    "apple.com",
    "icloud.com",
    "amazon.com",
    "aws.amazon.com",
    "paypal.com",
    "netflix.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "twitter.com",
    "dropbox.com",
    "adobe.com",
    "chase.com",
    "wellsfargo.com",
    "bankofamerica.com",
    "citibank.com",
    "dhl.com",
    "fedex.com",
    "ups.com",
    "usps.com",
    "yahoo.com",
    "hotmail.com",
    "live.com",
]

# ── Compiled regex patterns ────────────────────────────────────────────

_RE_FROM_HOST = re.compile(r"\bfrom\s+(\S+)", re.I)
_RE_BY_HOST = re.compile(r"\bby\s+(\S+)", re.I)
_RE_IPV4_BRACKET = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
_RE_IPV6_BRACKET = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:]+)\]", re.I)
_RE_WITH_PROTO = re.compile(r"\bwith\s+(E?SMTP\S*|LMTP\S*)", re.I)
_RE_TIMESTAMP_SEP = re.compile(r";\s*(.+)$", re.S)

# Authentication-Results sub-patterns
_RE_AR_SPF = re.compile(
    r"spf\s*=\s*(\w+)\s*(?:\(([^)]*)\))?\s*(?:smtp\.mailfrom\s*=\s*(\S+))?",
    re.I,
)
_RE_AR_DKIM = re.compile(
    r"dkim\s*=\s*(\w+)\s*(?:\(([^)]*)\))?"
    r"(?:\s*header\.d\s*=\s*(\S+))?"
    r"(?:\s*header\.s\s*=\s*(\S+))?",
    re.I,
)
_RE_AR_DMARC = re.compile(
    r"dmarc\s*=\s*(\w+)\s*(?:\(([^)]*)\))?" r"(?:\s*header\.from\s*=\s*(\S+))?",
    re.I,
)

# DKIM-Signature field extraction
_RE_DKIM_TAG = re.compile(r"(\w+)\s*=\s*([^;]+)")


# ═══════════════════════════════════════════════════════════════════════
# HeaderParser
# ═══════════════════════════════════════════════════════════════════════


class HeaderParser:
    """Parses and analyses email headers for threat indicators.

    Parameters
    ----------
    offline_mode : bool
        When *True*, skip all network calls (DNS lookups, geo-IP API).
        Auth results are derived entirely from the email's own
        ``Authentication-Results`` header.
    geo_enabled : bool
        Set *False* to skip IP geolocation even when online.
    geo_rate_limit : float
        Minimum seconds between consecutive ip-api.com requests
        (free tier allows ~45 req/min → 1.4 s is safe).
    """

    def __init__(
        self,
        *,
        offline_mode: bool = False,
        geo_enabled: bool = True,
        geo_rate_limit: float = 1.5,
    ):
        self.offline_mode = offline_mode
        self.geo_enabled = geo_enabled and not offline_mode
        self._geo_rate_limit = geo_rate_limit
        self._geo_cache: dict[str, dict[str, Any]] = {}
        self._geo_last_ts: float = 0.0
        self.intel_engine = IPIntelligenceEngine(offline_mode=offline_mode)

    # ── Public API ─────────────────────────────────────────────────────

    def analyse(self, eml_path: str) -> dict[str, Any]:
        """Run full header analysis on an ``.eml`` file.

        Parameters
        ----------
        eml_path : str
            Filesystem path to a raw ``.eml`` file.

        Returns
        -------
        dict
            ``{file, relay_path, auth_results, spoofing_flags, geo_trace}``
        """
        path = Path(eml_path)
        raw = path.read_bytes()
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)

        relay_path = self._parse_received_chain(msg)
        auth_results = self._build_auth_results(msg, relay_path)
        spoofing_flags = self._detect_spoofing(msg)
        geo_trace = self._build_geo_trace(relay_path)

        return {
            "file": path.name,
            "subject": self._decode_header(msg.get("Subject", "")),
            "from": self._decode_header(msg.get("From", "")),
            "relay_path": relay_path,
            "auth_results": auth_results,
            "spoofing_flags": spoofing_flags,
            "geo_trace": geo_trace,
        }

    # ── 1. Received-chain parsing ──────────────────────────────────────

    def _parse_received_chain(self, msg: Message) -> list[dict[str, Any]]:
        """Return chronologically-ordered list of relay hops."""
        raw_headers: list[str] = msg.get_all("Received", [])
        # Received headers are prepended (newest first) → reverse for chrono order.
        hops = [self._parse_one_hop(h) for h in reversed(raw_headers)]

        for idx, hop in enumerate(hops):
            hop["hop"] = idx + 1
            if idx > 0:
                hop["delay_seconds"] = self._compute_delay(hops[idx - 1], hop)
            else:
                hop["delay_seconds"] = None

        return hops

    def _parse_one_hop(self, header: str) -> dict[str, Any]:
        """Extract structured fields from a single Received header value."""
        # Normalise folded whitespace
        h = " ".join(header.split())

        from_host = self._first_group(_RE_FROM_HOST, h)
        by_host = self._first_group(_RE_BY_HOST, h)

        # IP — prefer IPv4, fall back to IPv6
        from_ip = self._first_group(_RE_IPV4_BRACKET, h)
        if from_ip is None:
            from_ip = self._first_group(_RE_IPV6_BRACKET, h)

        protocol = self._first_group(_RE_WITH_PROTO, h)

        # Timestamp lives after the last semicolon
        timestamp_raw = None
        timestamp_utc = None
        m = _RE_TIMESTAMP_SEP.search(h)
        if m:
            timestamp_raw = m.group(1).strip()
            try:
                dt = email.utils.parsedate_to_datetime(timestamp_raw)
                timestamp_utc = dt.astimezone(timezone.utc).isoformat()
            except Exception:
                pass

        return {
            "from_host": from_host,
            "from_ip": from_ip,
            "by_host": by_host,
            "protocol": protocol,
            "timestamp": timestamp_raw,
            "timestamp_utc": timestamp_utc,
        }

    @staticmethod
    def _compute_delay(prev: dict, curr: dict) -> float | None:
        t1 = prev.get("timestamp_utc")
        t2 = curr.get("timestamp_utc")
        if not t1 or not t2:
            return None
        try:
            d1 = datetime.fromisoformat(t1)
            d2 = datetime.fromisoformat(t2)
            return round((d2 - d1).total_seconds(), 2)
        except Exception:
            return None

    # ── 2. Authentication validation ───────────────────────────────────

    def _build_auth_results(
        self, msg: Message, relay_path: list[dict]
    ) -> dict[str, Any]:
        """Combine header-parsed auth verdicts with optional live DNS data."""
        result: dict[str, Any] = {}

        # 2a. Parse the Authentication-Results header (always available)
        result["header"] = self._parse_auth_results_header(msg)

        # 2b. Extract key identity domains
        envelope_from = self._extract_domain(msg.get("Return-Path", ""))
        header_from = self._extract_domain(msg.get("From", ""))
        result["envelope_domain"] = envelope_from
        result["header_from_domain"] = header_from

        # 2c. Live DNS lookups (best-effort, skipped in offline mode)
        if not self.offline_mode and _HAS_DNS:
            result["live_dns"] = self._live_dns_checks(msg, envelope_from or header_from)
        else:
            result["live_dns"] = None

        return result

    # ── 2a. Parse Authentication-Results header ────────────────────────

    def _parse_auth_results_header(self, msg: Message) -> dict[str, Any]:
        raw = msg.get("Authentication-Results", "")
        if not raw:
            return {"spf": None, "dkim": None, "dmarc": None}

        # Normalise folded header
        raw = " ".join(raw.split())

        spf = self._parse_ar_spf(raw)
        dkim = self._parse_ar_dkim(raw)
        dmarc = self._parse_ar_dmarc(raw)

        return {"spf": spf, "dkim": dkim, "dmarc": dmarc}

    def _parse_ar_spf(self, text: str) -> dict[str, str | None] | None:
        m = _RE_AR_SPF.search(text)
        if not m:
            return None
        return {
            "verdict": m.group(1).lower(),
            "detail": (m.group(2) or "").strip() or None,
            "smtp_mailfrom": (m.group(3) or "").strip("; ") or None,
        }

    def _parse_ar_dkim(self, text: str) -> dict[str, str | None] | None:
        m = _RE_AR_DKIM.search(text)
        if not m:
            return None
        return {
            "verdict": m.group(1).lower(),
            "detail": (m.group(2) or "").strip() or None,
            "domain": (m.group(3) or "").strip("; ") or None,
            "selector": (m.group(4) or "").strip("; ") or None,
        }

    def _parse_ar_dmarc(self, text: str) -> dict[str, str | None] | None:
        m = _RE_AR_DMARC.search(text)
        if not m:
            return None
        return {
            "verdict": m.group(1).lower(),
            "detail": (m.group(2) or "").strip() or None,
            "header_from": (m.group(3) or "").strip("; ") or None,
        }

    # ── 2b. Live DNS checks ───────────────────────────────────────────

    def _live_dns_checks(self, msg: Message, domain: str | None) -> dict[str, Any]:
        result: dict[str, Any] = {"spf_record": None, "dmarc_record": None, "dkim": None}

        if not domain:
            return result

        # SPF — look up TXT record for the domain
        result["spf_record"] = self._dns_lookup_spf(domain)

        # DMARC — look up TXT at _dmarc.<domain>
        result["dmarc_record"] = self._dns_lookup_dmarc(domain)

        # DKIM — need selector + domain from the DKIM-Signature header
        dkim_sig = msg.get("DKIM-Signature", "")
        if dkim_sig:
            tags = self._parse_dkim_signature(dkim_sig)
            selector = tags.get("s")
            dkim_domain = tags.get("d")
            if selector and dkim_domain:
                key_record = self._dns_lookup_dkim(selector.strip(), dkim_domain.strip())
                result["dkim"] = {
                    "selector": selector.strip(),
                    "domain": dkim_domain.strip(),
                    "public_key_found": key_record is not None,
                    "record_preview": (key_record[:120] + "…") if key_record and len(key_record) > 120 else key_record,
                }

        return result

    def _dns_lookup_spf(self, domain: str) -> str | None:
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=4)
            for rdata in answers:
                txt = b"".join(rdata.strings).decode(errors="replace")
                if txt.lower().startswith("v=spf1"):
                    return txt
        except Exception:
            pass
        return None

    def _dns_lookup_dmarc(self, domain: str) -> str | None:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=4)
            for rdata in answers:
                txt = b"".join(rdata.strings).decode(errors="replace")
                if txt.lower().startswith("v=dmarc1"):
                    return txt
        except Exception:
            pass
        return None

    def _dns_lookup_dkim(self, selector: str, domain: str) -> str | None:
        try:
            qname = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(qname, "TXT", lifetime=4)
            for rdata in answers:
                txt = b"".join(rdata.strings).decode(errors="replace")
                if "p=" in txt:
                    return txt
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_dkim_signature(raw: str) -> dict[str, str]:
        """Extract tag=value pairs from a DKIM-Signature header."""
        # Normalise folded header
        raw = " ".join(raw.split())
        tags: dict[str, str] = {}
        for m in _RE_DKIM_TAG.finditer(raw):
            tags[m.group(1).strip()] = m.group(2).strip().rstrip(";")
        return tags

    # ── 3. Spoofing / lookalike detection ──────────────────────────────

    def _detect_spoofing(self, msg: Message) -> list[dict[str, Any]]:
        flags: list[dict[str, Any]] = []

        from_domain = self._extract_domain(msg.get("From", ""))
        reply_to_domain = self._extract_domain(msg.get("Reply-To", ""))
        return_path_domain = self._extract_domain(msg.get("Return-Path", ""))

        domains_map: dict[str, str | None] = {
            "From": from_domain,
            "Reply-To": reply_to_domain,
            "Return-Path": return_path_domain,
        }

        # 3a. Cross-field domain mismatches
        pairs = [
            ("From", "Reply-To"),
            ("From", "Return-Path"),
            ("Reply-To", "Return-Path"),
        ]
        for field_a, field_b in pairs:
            da = domains_map[field_a]
            db = domains_map[field_b]
            if da and db and da.lower() != db.lower():
                flags.append(
                    {
                        "type": "domain_mismatch",
                        "fields": [field_a, field_b],
                        "values": [da, db],
                        "severity": "high" if field_a == "From" and field_b == "Reply-To" else "medium",
                        "description": (
                            f"{field_a} domain ({da}) differs from "
                            f"{field_b} domain ({db})"
                        ),
                    }
                )

        # 3b. Lookalike detection against well-known brands
        active_domains = {d.lower() for d in domains_map.values() if d}
        for email_domain in active_domains:
            # Strip subdomains for comparison (e.g. mail.google.com → google.com)
            base = self._base_domain(email_domain)
            for known in WELL_KNOWN_DOMAINS:
                if base == known:
                    continue  # exact match → legitimate
                dist = self._levenshtein(base, known)
                if 0 < dist <= 3:
                    flags.append(
                        {
                            "type": "brand_lookalike",
                            "suspect_domain": email_domain,
                            "resembles": known,
                            "levenshtein_distance": dist,
                            "severity": "critical" if dist == 1 else "high",
                            "description": (
                                f"Domain '{email_domain}' is {dist} edit(s) away "
                                f"from well-known brand '{known}'"
                            ),
                        }
                    )

        # 3c. Display-name impersonation
        display_name, addr = email.utils.parseaddr(
            self._decode_header(msg.get("From", ""))
        )
        if display_name and from_domain:
            dn_lower = display_name.lower()
            for known in WELL_KNOWN_DOMAINS:
                brand = known.split(".")[0]  # "microsoft", "google", …
                if brand in dn_lower and from_domain.lower() != known:
                    flags.append(
                        {
                            "type": "display_name_impersonation",
                            "display_name": display_name,
                            "actual_domain": from_domain,
                            "impersonated_brand": known,
                            "severity": "critical",
                            "description": (
                                f"Display name '{display_name}' mentions "
                                f"'{brand}' but actual domain is '{from_domain}'"
                            ),
                        }
                    )
                    break  # one flag per From address is enough

        # 3d. Spam score (if present)
        spam_score_raw = msg.get("X-Spam-Score", "")
        if spam_score_raw:
            try:
                score = float(spam_score_raw.strip())
                if score >= 5.0:
                    flags.append(
                        {
                            "type": "high_spam_score",
                            "score": score,
                            "severity": "high" if score >= 7.0 else "medium",
                            "description": f"X-Spam-Score is {score} (threshold 5.0)",
                        }
                    )
            except ValueError:
                pass

        return flags

    # ── 4. IP geolocation ──────────────────────────────────────────────

    def _build_geo_trace(self, relay_path: list[dict]) -> list[dict[str, Any]]:
        """Geolocate every public IP in the relay path and enrich with IP intelligence."""
        seen: set[str] = set()
        results: list[dict[str, Any]] = []

        for hop in relay_path:
            ip = hop.get("from_ip")
            if not ip or ip in seen:
                continue
            seen.add(ip)

            if self._is_private_ip(ip):
                enriched = self.intel_engine.enrich(ip, {"country": "Internal Network"})
                enriched["private"] = True
                results.append(enriched)
                continue

            geo_data = {}
            if self.geo_enabled:
                geo_data = self._geolocate_ip(ip)

            enriched = self.intel_engine.enrich(ip, geo_data)
            results.append(enriched)

        return results

    def _geolocate_ip(self, ip: str) -> dict[str, Any]:
        """Query ip-api.com (free tier, JSON) with caching + rate-limit."""
        if ip in self._geo_cache:
            return self._geo_cache[ip]

        # Rate-limit: wait if needed
        now = time.monotonic()
        wait = self._geo_rate_limit - (now - self._geo_last_ts)
        if wait > 0:
            time.sleep(wait)

        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,lat,lon"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sentinel-mail/0.1"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                self._geo_last_ts = time.monotonic()
                data = json.loads(resp.read())
        except Exception as exc:
            data = {"status": "error", "message": str(exc)}

        result: dict[str, Any] = {"ip": ip}
        if data.get("status") == "success":
            result.update(
                {
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "as": data.get("as"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                }
            )
        else:
            result["geo_error"] = data.get("message", "unknown error")

        self._geo_cache[ip] = result
        return result

    # ── Utility helpers ────────────────────────────────────────────────

    @staticmethod
    def _first_group(pattern: re.Pattern, text: str) -> str | None:
        m = pattern.search(text)
        return m.group(1) if m else None

    @staticmethod
    def _extract_domain(addr_string: str) -> str | None:
        """Extract the domain part from an email address / header value."""
        if not addr_string:
            return None
        # Strip angle brackets and quotes
        addr_string = addr_string.strip().strip("<>").strip()
        _, addr = email.utils.parseaddr(addr_string)
        if "@" in addr:
            return addr.split("@", 1)[1].lower().rstrip(">")
        # Maybe it's already just a domain?
        if "." in addr_string and "@" not in addr_string:
            return addr_string.lower()
        return None

    @staticmethod
    def _base_domain(domain: str) -> str:
        """Reduce ``mail.sub.example.com`` → ``example.com``."""
        parts = domain.lower().rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain.lower()

    @staticmethod
    def _decode_header(value: str) -> str:
        """Decode RFC 2047 encoded header values."""
        if not value:
            return ""
        decoded_parts = email.header.decode_header(value)
        fragments: list[str] = []
        for part, charset in decoded_parts:
            if isinstance(part, bytes):
                fragments.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                fragments.append(part)
        return " ".join(fragments)

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Return True for RFC-1918, loopback, and link-local addresses."""
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.is_loopback or addr.is_link_local:
                return True
            # Explicit RFC 1918 private ranges
            return (
                addr in ipaddress.ip_network("10.0.0.0/8") or
                addr in ipaddress.ip_network("172.16.0.0/12") or
                addr in ipaddress.ip_network("192.168.0.0/16")
            )
        except ValueError:
            return False

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Classic dynamic-programming Levenshtein distance."""
        if len(s1) < len(s2):
            return HeaderParser._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)

        prev = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(
                    min(
                        prev[j + 1] + 1,  # deletion
                        curr[j] + 1,  # insertion
                        prev[j] + (c1 != c2),  # substitution
                    )
                )
            prev = curr
        return prev[-1]


# Convenience import fix: add email.header for _decode_header
import email.header  # noqa: E402 — late import for readability above
