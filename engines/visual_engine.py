"""
visual_engine.py — Visual / Attachment Analysis Engine

Extracts images from ``.eml`` files (both inline and attached), scans
them for QR codes using OpenCV + pyzbar, and performs structural risk
assessment on any decoded URLs.

Output dict keys
-----------------
attachments       Inventory of all MIME parts with content-type & size.
images_scanned    Number of image parts processed.
qr_codes_found   Total QR codes decoded across all images.
decoded_urls      List of URLs extracted from QR codes.
url_risk_flags    Per-URL structural risk assessment.
"""

from __future__ import annotations

import email
import email.header
import email.policy
import io
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ── Optional heavy deps (fail gracefully) ──────────────────────────────

_HAS_CV2 = False
_HAS_PYZBAR = False
_HAS_PIL = False

try:
    import cv2
    import numpy as np

    _HAS_CV2 = True
except Exception:
    pass

try:
    from pyzbar.pyzbar import decode as pyzbar_decode, ZBarSymbol

    _HAS_PYZBAR = True
except Exception:
    pass

try:
    from PIL import Image

    _HAS_PIL = True
except Exception:
    pass

# ── Constants ──────────────────────────────────────────────────────────

_IMAGE_CONTENT_TYPES = frozenset(
    {
        "image/png",
        "image/jpeg",
        "image/jpg",
        "image/gif",
        "image/bmp",
        "image/tiff",
        "image/webp",
        "image/svg+xml",
    }
)

_URL_SHORTENERS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "shorturl.at",
        "tiny.cc",
        "rb.gy",
        "qr.io",
        "qrco.de",
        "lnkd.in",
        "surl.li",
    }
)

_SUSPICIOUS_TLDS = frozenset(
    {
        ".xyz",
        ".top",
        ".click",
        ".club",
        ".icu",
        ".buzz",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
        ".gq",
        ".work",
        ".link",
        ".support",
        ".stream",
        ".racing",
    }
)

_PHISHY_PATH_KEYWORDS = frozenset(
    {
        "login",
        "signin",
        "sign-in",
        "verify",
        "auth",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "credential",
        "enroll",
        "mfa",
        "2fa",
        "token",
    }
)


# ═══════════════════════════════════════════════════════════════════════
# VisualEngine
# ═══════════════════════════════════════════════════════════════════════


class VisualEngine:
    """Analyses email attachments and embedded images for visual threats.

    Parameters
    ----------
    sender_domain : str or None
        The sender's claimed domain (from the ``From`` header).  When
        supplied, QR-decoded URLs whose domain differs from this are
        flagged as domain-mismatch.
    """

    def __init__(self, *, sender_domain: str | None = None):
        self.sender_domain = sender_domain

    # ── Public API ─────────────────────────────────────────────────────

    def analyse(self, attachments: list[dict[str, Any]]) -> dict[str, Any]:
        """Run visual analysis on a list of pre-extracted attachments.

        Parameters
        ----------
        attachments
            Each dict must contain ``filename`` (str), ``content_type``
            (str), and ``payload`` (bytes).

        Returns
        -------
        dict  with keys ``attachments``, ``images_scanned``,
              ``qr_codes_found``, ``decoded_urls``, ``url_risk_flags``.
        """
        inventory: list[dict[str, Any]] = []
        all_qr: list[dict[str, Any]] = []
        images_scanned = 0

        for att in attachments:
            ct = att.get("content_type", "").lower()
            filename = att.get("filename") or "(unnamed)"
            payload: bytes = att.get("payload", b"")

            entry: dict[str, Any] = {
                "filename": filename,
                "content_type": ct,
                "size_bytes": len(payload),
            }

            if ct in _IMAGE_CONTENT_TYPES and payload:
                images_scanned += 1
                qr_results = self._scan_qr_codes(payload, filename)
                entry["qr_codes"] = qr_results
                all_qr.extend(qr_results)
            else:
                entry["qr_codes"] = []

            inventory.append(entry)

        decoded_urls = [qr["data"] for qr in all_qr if qr.get("is_url")]
        url_flags = [self._assess_url_risk(u) for u in decoded_urls]

        return {
            "attachments": inventory,
            "images_scanned": images_scanned,
            "qr_codes_found": len(all_qr),
            "decoded_urls": decoded_urls,
            "url_risk_flags": url_flags,
        }

    # ── Convenience: analyse straight from an .eml path ────────────────

    def analyse_eml(self, eml_path: str) -> dict[str, Any]:
        """Extract attachments from a ``.eml`` file, then analyse.

        Also auto-detects the sender domain from the ``From`` header
        unless one was explicitly set on the engine.
        """
        attachments, sender_domain = self.extract_attachments(eml_path)

        if self.sender_domain is None and sender_domain:
            self.sender_domain = sender_domain

        result = self.analyse(attachments)
        result["source_file"] = Path(eml_path).name
        return result

    # ── Attachment extraction ──────────────────────────────────────────

    @staticmethod
    def extract_attachments(eml_path: str) -> tuple[list[dict[str, Any]], str | None]:
        """Parse a ``.eml`` file and return ``(attachments, sender_domain)``.

        Every image part (inline or attached) is included.
        """
        raw = Path(eml_path).read_bytes()
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)

        # Sender domain
        from_hdr = msg.get("From", "")
        sender_domain = None
        m = re.search(r"@([\w.\-]+)", from_hdr)
        if m:
            sender_domain = m.group(1).lower()

        attachments: list[dict[str, Any]] = []
        for part in msg.walk():
            ct = part.get_content_type()
            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            filename = part.get_filename() or ""
            # Also capture inline images identified by Content-ID
            content_id = part.get("Content-ID", "").strip("<>")
            disposition = str(part.get("Content-Disposition", ""))

            if ct.startswith("image/") or "attachment" in disposition:
                attachments.append(
                    {
                        "filename": filename or content_id or "(inline)",
                        "content_type": ct,
                        "payload": payload,
                        "content_id": content_id or None,
                        "disposition": disposition or None,
                    }
                )

        return attachments, sender_domain

    # ── QR code scanning ──────────────────────────────────────────────

    def _scan_qr_codes(
        self, image_bytes: bytes, filename: str
    ) -> list[dict[str, Any]]:
        """Attempt to decode QR codes from raw image bytes.

        Tries pyzbar first (best accuracy), then falls back to OpenCV's
        built-in QR detector, then PIL-only as a last resort for
        format verification.
        """
        results: list[dict[str, Any]] = []

        # Strategy 1: pyzbar (wraps zbar — very reliable)
        if _HAS_PYZBAR:
            results = self._decode_pyzbar(image_bytes, filename)
            if results:
                return results

        # Strategy 2: OpenCV QRCodeDetector
        if _HAS_CV2:
            results = self._decode_opencv(image_bytes, filename)
            if results:
                return results

        # Strategy 3: PIL-only (can confirm image is valid but can't decode QR)
        if _HAS_PIL and not results:
            try:
                img = Image.open(io.BytesIO(image_bytes))
                img.verify()
                # Image is valid but we can't decode QR without pyzbar/opencv
            except Exception:
                pass

        return results

    def _decode_pyzbar(
        self, image_bytes: bytes, filename: str
    ) -> list[dict[str, Any]]:
        """Decode QR codes via pyzbar."""
        results: list[dict[str, Any]] = []

        try:
            # pyzbar works best with PIL Image objects
            if _HAS_PIL:
                img = Image.open(io.BytesIO(image_bytes))
                # Convert to RGB if needed (RGBA, palette, etc.)
                if img.mode not in ("RGB", "L"):
                    img = img.convert("RGB")
                decoded = pyzbar_decode(img, symbols=[ZBarSymbol.QRCODE])
            elif _HAS_CV2:
                arr = np.frombuffer(image_bytes, dtype=np.uint8)
                img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
                if img is None:
                    return []
                decoded = pyzbar_decode(img, symbols=[ZBarSymbol.QRCODE])
            else:
                return []

            for obj in decoded:
                data = obj.data.decode("utf-8", errors="replace")
                is_url = bool(re.match(r"https?://", data, re.I))
                results.append(
                    {
                        "data": data,
                        "type": obj.type,
                        "is_url": is_url,
                        "source_file": filename,
                        "decoder": "pyzbar",
                        "rect": {
                            "left": obj.rect.left,
                            "top": obj.rect.top,
                            "width": obj.rect.width,
                            "height": obj.rect.height,
                        },
                    }
                )
        except Exception:
            pass

        return results

    def _decode_opencv(
        self, image_bytes: bytes, filename: str
    ) -> list[dict[str, Any]]:
        """Decode QR codes via OpenCV's QRCodeDetector."""
        results: list[dict[str, Any]] = []

        try:
            arr = np.frombuffer(image_bytes, dtype=np.uint8)
            img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
            if img is None:
                return []

            detector = cv2.QRCodeDetector()

            # detectAndDecodeMulti handles multiple QR codes
            retval, decoded_info, points, _ = detector.detectAndDecodeMulti(img)
            if retval and decoded_info:
                for i, data in enumerate(decoded_info):
                    if not data:
                        continue
                    is_url = bool(re.match(r"https?://", data, re.I))
                    result_entry: dict[str, Any] = {
                        "data": data,
                        "type": "QRCODE",
                        "is_url": is_url,
                        "source_file": filename,
                        "decoder": "opencv",
                    }
                    if points is not None and i < len(points):
                        pts = points[i].tolist()
                        result_entry["polygon"] = pts
                    results.append(result_entry)
        except Exception:
            # Older OpenCV may lack detectAndDecodeMulti — try single
            try:
                data, points, _ = detector.detectAndDecode(img)
                if data:
                    is_url = bool(re.match(r"https?://", data, re.I))
                    results.append(
                        {
                            "data": data,
                            "type": "QRCODE",
                            "is_url": is_url,
                            "source_file": filename,
                            "decoder": "opencv",
                        }
                    )
            except Exception:
                pass

        return results

    # ── URL risk assessment ───────────────────────────────────────────

    def _assess_url_risk(self, url: str) -> dict[str, Any]:
        """Structural risk checks on a QR-decoded URL (no live lookups)."""
        flags: list[dict[str, str]] = []
        risk_score = 0.0

        try:
            parsed = urlparse(url)
        except Exception:
            return {"url": url, "risk_score": 1.0, "flags": [{"flag": "unparseable_url", "severity": "critical"}]}

        hostname = (parsed.hostname or "").lower()
        path_lower = (parsed.path or "").lower()
        query_lower = (parsed.query or "").lower()

        # 1. URL shortener
        for shortener in _URL_SHORTENERS:
            if hostname == shortener or hostname.endswith("." + shortener):
                flags.append({"flag": "url_shortener", "detail": f"Domain '{hostname}' is a known URL shortener", "severity": "high"})
                risk_score += 0.3
                break

        # 2. Suspicious TLD
        for tld in _SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                flags.append({"flag": "suspicious_tld", "detail": f"TLD '{tld}' is frequently used in phishing", "severity": "high"})
                risk_score += 0.25
                break

        # 3. Domain mismatch vs sender
        if self.sender_domain and hostname:
            sender_base = self._base_domain(self.sender_domain)
            url_base = self._base_domain(hostname)
            if sender_base != url_base:
                flags.append(
                    {
                        "flag": "domain_mismatch",
                        "detail": f"QR URL domain '{hostname}' does not match sender domain '{self.sender_domain}'",
                        "severity": "high",
                    }
                )
                risk_score += 0.25

        # 4. IP-based URL
        if re.match(r"\d{1,3}(?:\.\d{1,3}){3}$", hostname):
            flags.append({"flag": "ip_address_url", "detail": f"URL uses raw IP address '{hostname}'", "severity": "critical"})
            risk_score += 0.35

        # 5. Phishy path keywords
        matched_kw: list[str] = []
        for kw in _PHISHY_PATH_KEYWORDS:
            if kw in path_lower or kw in query_lower:
                matched_kw.append(kw)
        if matched_kw:
            flags.append(
                {
                    "flag": "phishy_path_keywords",
                    "detail": f"Path/query contains suspicious keywords: {', '.join(matched_kw)}",
                    "severity": "medium",
                }
            )
            risk_score += min(0.15 * len(matched_kw), 0.3)

        # 6. Non-HTTPS
        if parsed.scheme == "http":
            flags.append({"flag": "no_https", "detail": "URL uses plain HTTP (no TLS)", "severity": "medium"})
            risk_score += 0.1

        # 7. Excessively long URL (obfuscation)
        if len(url) > 150:
            flags.append({"flag": "long_url", "detail": f"URL is {len(url)} chars (potential obfuscation)", "severity": "low"})
            risk_score += 0.1

        # 8. Multiple subdomains
        dot_count = hostname.count(".")
        if dot_count >= 4:
            flags.append({"flag": "excessive_subdomains", "detail": f"Hostname has {dot_count} dot-separated labels", "severity": "medium"})
            risk_score += 0.15

        # 9. Embedded credentials
        if parsed.username or parsed.password:
            flags.append({"flag": "embedded_credentials", "detail": "URL contains embedded username/password", "severity": "critical"})
            risk_score += 0.4

        return {
            "url": url,
            "hostname": hostname,
            "risk_score": round(min(risk_score, 1.0), 3),
            "risk_level": self._risk_label(risk_score),
            "flags": flags,
        }

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _base_domain(domain: str) -> str:
        """``mail.sub.example.com`` → ``example.com``."""
        parts = domain.lower().rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()

    @staticmethod
    def _risk_label(score: float) -> str:
        if score >= 0.7:
            return "high"
        if score >= 0.4:
            return "medium"
        if score >= 0.15:
            return "low"
        return "safe"
