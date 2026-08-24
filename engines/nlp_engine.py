"""
nlp_engine.py — Natural-Language Threat Analysis Engine

Two-tier architecture:
  **Primary**   – HuggingFace transformer classifier
                  (``cybersectony/phishing-email-detection`` or compatible)
                  + GPT-2 perplexity / burstiness for AI-generated text detection.
  **Fallback**  – Heuristic keyword scorer (always available, no downloads).

Both tiers share the same regex-based entity extractor and phrase flagger.

Output dict keys:
  phishing_score       Classification result + contributing signals.
  ai_generated_score   Perplexity & burstiness metrics.
  extracted_entities   Financial refs, contacts, URLs, named entities.
  flagged_phrases      Categorised suspicious phrases with severity.
"""

from __future__ import annotations

import email
import email.header
import email.policy
import html as html_module
import math
import re
import statistics
import sys
from pathlib import Path
from typing import Any

# ── Optional heavy dependencies (fail gracefully) ─────────────────────

_HAS_TORCH = False
_HAS_TRANSFORMERS = False
_HAS_NLTK = False
_HAS_SPACY = False

try:
    import torch  # noqa: F401

    _HAS_TORCH = True
except ImportError:
    pass

try:
    from transformers import (  # noqa: F401
        pipeline as hf_pipeline,
        GPT2LMHeadModel,
        GPT2TokenizerFast,
    )

    _HAS_TRANSFORMERS = _HAS_TORCH  # transformers needs torch
except ImportError:
    pass

try:
    import nltk  # noqa: F401

    _HAS_NLTK = True
except ImportError:
    pass

try:
    import spacy  # noqa: F401

    _HAS_SPACY = True
except ImportError:
    pass

# ═══════════════════════════════════════════════════════════════════════
# Phrase patterns for flagging   {category: [(regex, severity), …]}
# ═══════════════════════════════════════════════════════════════════════

PHRASE_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "urgency": [
        (r"\burgent(?:ly)?\b", "high"),
        (r"\bimmediate(?:ly)?\b", "high"),
        (r"\b(?:act|respond|verify|confirm)\s+(?:now|immediately|today)\b", "high"),
        (r"\bwithin\s+\d+\s+hours?\b", "high"),
        (r"\btime[- ]sensitive\b", "high"),
        (r"\bdeadline\b", "medium"),
        (r"\bexpir(?:e|es|ed|ing)\b", "medium"),
        (r"\bfailure\s+to\s+(?:verify|comply|respond|act)\b", "critical"),
        (r"\bmust\s+be\s+completed?\b", "medium"),
        (r"\bbefore\s+\d+\s*(?:am|pm)\b", "medium"),
        (r"\brequired\s+(?:by|before|today)\b", "medium"),
    ],
    "financial": [
        (r"\bwire\s+transfer\b", "high"),
        (r"\bbank\s+(?:account|details?)\b", "medium"),
        (r"\bIBAN\b", "medium"),
        (r"\bSWIFT(?:\s*/\s*BIC)?\b", "medium"),
        (r"\bbeneficiary\b", "medium"),
        (r"\bpayment(?:\s+(?:required|overdue|pending))?\b", "medium"),
        (r"\binvoice\b", "low"),
        (r"\bfunds?\b", "low"),
    ],
    "secrecy": [
        (r"\b(?:do\s+not|don'?t)\s+(?:discuss|share|tell|mention|forward)\b", "critical"),
        (r"\bconfidential\b", "medium"),
        (r"\b(?:between|stay\s+between)\s+(?:us|you\s+and\s+(?:me|I))\b", "high"),
        (r"\bkeep\s+(?:this\s+)?(?:private|quiet|secret)\b", "high"),
        (r"\bnot\s+(?:been\s+)?announced\b", "medium"),
    ],
    "threat": [
        (r"\baccount\s+(?:will\s+be\s+)?(?:suspend|lock|disabl|terminat|restrict)", "critical"),
        (r"\bpermanent(?:ly)?\s+(?:lock|suspend|disabl|delet|clos)", "critical"),
        (r"\bunauthori[sz]ed\s+access\b", "high"),
        (r"\blegal\s+action\b", "high"),
        (r"\blose\s+access\b", "high"),
        (r"\bcompromised\b", "high"),
    ],
    "impersonation": [
        (r"\bsecurity\s+(?:team|department|division|alert|notification)\b", "medium"),
        (r"\b(?:IT|I\.T\.)\s+(?:help\s*desk|department|support|security)\b", "medium"),
        (r"\bverify\s+your\s+(?:identity|account)\b", "high"),
        (r"\bupdate\s+your\s+(?:account|password|information|credentials)\b", "high"),
        (r"\bscan\s+(?:the\s+)?QR\s+code\b", "high"),
        (r"\b(?:click|tap)\s+(?:here|below|the\s+(?:link|button))\b", "medium"),
    ],
}

# Flatten for quick scoring  → [(compiled_re, category, severity, weight)]
_COMPILED_PHRASES: list[tuple[re.Pattern, str, str, float]] = []
_SEVERITY_WEIGHT = {"critical": 3.0, "high": 2.0, "medium": 1.0, "low": 0.5}
for _cat, _patterns in PHRASE_PATTERNS.items():
    for _pat, _sev in _patterns:
        _COMPILED_PHRASES.append(
            (re.compile(_pat, re.I), _cat, _sev, _SEVERITY_WEIGHT[_sev])
        )

# ═══════════════════════════════════════════════════════════════════════
# Regex patterns for entity extraction
# ═══════════════════════════════════════════════════════════════════════

_RE_IBAN = re.compile(
    r"\b([A-Z]{2}\d{2}\s?[\dA-Z]{4}(?:\s?[\dA-Z]{4}){1,7}(?:\s?[\dA-Z]{1,4})?)\b"
)
_RE_SWIFT = re.compile(r"\b([A-Z]{4}[A-Z]{2}[A-Z\d]{2}(?:[A-Z\d]{3})?)\b")
_RE_AMOUNT = re.compile(
    r"([\$€£¥]\s?\d{1,3}(?:[,\s]\d{3})*(?:\.\d{2})?)"
    r"|(\d{1,3}(?:[,\s]\d{3})*(?:\.\d{2})?\s?(?:USD|EUR|GBP|INR|AUD|CAD))"
)
_RE_INVOICE = re.compile(
    r"\b((?:INV|PO|REF|ORDER|TXN|CASE)[-#: ]*\d[\w\-/]*)\b", re.I
)
_RE_PHONE = re.compile(
    r"(?:\+\d{1,3}[\s.-]?)?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}\b"
)
_RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
_RE_URL = re.compile(r"https?://[^\s<>\"'\])+]+", re.I)
_RE_CRYPTO = re.compile(r"\b((?:0x[0-9a-fA-F]{40})|(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}))\b")

# Suspicious URL TLDs
_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".club", ".icu", ".buzz",
    ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".link",
    ".support", ".stream", ".racing",
}


# ═══════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════


def _strip_html(html: str) -> str:
    """Remove HTML tags / scripts / styles and decode entities."""
    text = re.sub(r"<style[^>]*>.*?</style>", " ", html, flags=re.S | re.I)
    text = re.sub(r"<script[^>]*>.*?</script>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html_module.unescape(text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def _sent_tokenize(text: str) -> list[str]:
    """Split *text* into sentences. Uses nltk when available."""
    if _HAS_NLTK:
        try:
            return nltk.sent_tokenize(text)
        except LookupError:
            # punkt_tab data missing – download once then retry
            try:
                nltk.download("punkt_tab", quiet=True)
                return nltk.sent_tokenize(text)
            except Exception:
                pass
    # Fallback: simple regex splitter
    parts = re.split(r"(?<=[.!?])\s+", text)
    return [p.strip() for p in parts if p.strip()]


def _decode_header(value: str) -> str:
    """Decode RFC-2047 encoded header values."""
    if not value:
        return ""
    parts = email.header.decode_header(value)
    frags: list[str] = []
    for part, charset in parts:
        if isinstance(part, bytes):
            frags.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            frags.append(part)
    return " ".join(frags)


# ═══════════════════════════════════════════════════════════════════════
# NLPEngine
# ═══════════════════════════════════════════════════════════════════════


class NLPEngine:
    """Analyses email body text for phishing and social-engineering signals.

    Parameters
    ----------
    lightweight : bool
        When *True*, skip transformer model loading entirely and use only
        heuristic scoring.  Much faster and needs no GPU / large downloads.
    phishing_model : str
        HuggingFace model ID for phishing classification.
    gpt2_model : str
        HuggingFace model ID for perplexity scoring.
    """

    PHISHING_MODEL_ID = "cybersectony/phishing-email-detection"
    GPT2_MODEL_ID = "gpt2"

    def __init__(
        self,
        *,
        lightweight: bool = False,
        phishing_model: str | None = None,
        gpt2_model: str | None = None,
    ):
        self.lightweight = lightweight
        self._phishing_model_id = phishing_model or self.PHISHING_MODEL_ID
        self._gpt2_model_id = gpt2_model or self.GPT2_MODEL_ID

        # Lazy-loaded model handles
        self._phishing_pipe: Any = None
        self._gpt2_model: Any = None
        self._gpt2_tok: Any = None
        self._spacy_nlp: Any = None

        self._phishing_loaded = False
        self._gpt2_loaded = False
        self._spacy_loaded = False

    # ── Public API ─────────────────────────────────────────────────────

    def analyse(
        self,
        subject: str,
        body: str,
        urls: list[str] | None = None,
    ) -> dict[str, Any]:
        """Run full NLP analysis on email content.

        Returns
        -------
        dict  with keys ``phishing_score``, ``ai_generated_score``,
              ``extracted_entities``, ``flagged_phrases``.
        """
        combined_text = f"{subject}\n\n{body}"
        if urls is None:
            urls = _RE_URL.findall(body)

        return {
            "phishing_score": self._classify_phishing(combined_text, urls),
            "ai_generated_score": self._detect_ai_generated(body),
            "extracted_entities": self._extract_entities(body, urls),
            "flagged_phrases": self._flag_phrases(subject, body),
        }

    # ── Email text extraction utility ──────────────────────────────────

    @staticmethod
    def extract_email_text(eml_path: str) -> tuple[str, str, list[str]]:
        """Parse a ``.eml`` file and return ``(subject, body, urls)``.

        Prefers ``text/plain`` parts; falls back to HTML with tags stripped.
        URLs are collected from both plain and HTML parts.
        """
        raw = Path(eml_path).read_bytes()
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)

        subject = _decode_header(msg.get("Subject", ""))

        plain_body = ""
        html_body = ""

        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                payload = part.get_payload(decode=True)
                if payload is None:
                    continue
                text = payload.decode(errors="replace")
                if ct == "text/plain" and not plain_body:
                    plain_body = text
                elif ct == "text/html" and not html_body:
                    html_body = text
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                text = payload.decode(errors="replace")
                if msg.get_content_type() == "text/html":
                    html_body = text
                else:
                    plain_body = text

        body = plain_body or _strip_html(html_body)

        # Collect URLs from both representations
        all_text = plain_body + " " + html_body
        urls = list(dict.fromkeys(_RE_URL.findall(all_text)))  # unique, ordered

        return subject, body, urls

    # ══════════════════════════════════════════════════════════════════
    # 1.  PHISHING CLASSIFICATION
    # ══════════════════════════════════════════════════════════════════

    def _classify_phishing(
        self, text: str, urls: list[str]
    ) -> dict[str, Any]:
        """Dispatch to transformer or heuristic classifier."""
        # Always compute heuristic (fast, used as signals either way)
        heuristic = self._classify_heuristic(text, urls)

        if not self.lightweight and _HAS_TRANSFORMERS:
            transformer = self._classify_transformer(text)
            if transformer is not None:
                transformer["heuristic_signals"] = heuristic["signals"]
                return transformer

        return heuristic

    # ── 1a. Transformer-based ──────────────────────────────────────────

    def _classify_transformer(self, text: str) -> dict[str, Any] | None:
        """Run HuggingFace phishing classifier."""
        if not self._phishing_loaded:
            self._phishing_loaded = True
            try:
                print(
                    f"  [nlp] Loading phishing model: {self._phishing_model_id}…",
                    file=sys.stderr,
                )
                self._phishing_pipe = hf_pipeline(
                    "text-classification",
                    model=self._phishing_model_id,
                    truncation=True,
                    max_length=512,
                )
            except Exception as exc:
                print(f"  [nlp] Transformer load failed: {exc}", file=sys.stderr)
                return None

        if self._phishing_pipe is None:
            return None

        try:
            # Truncate input to avoid excessive memory use
            snippet = text[:2048]
            results = self._phishing_pipe(snippet)
            top = results[0] if results else {}
            label = top.get("label", "").lower()
            score = top.get("score", 0.0)

            # Normalise to 0 = safe, 1 = phishing
            is_phish = "phish" in label or "malicious" in label or "spam" in label
            phishing_score = score if is_phish else 1.0 - score

            return {
                "score": round(phishing_score, 4),
                "label": "phishing" if phishing_score >= 0.5 else "safe",
                "confidence": round(score, 4),
                "raw_label": top.get("label", ""),
                "method": "transformer",
                "model": self._phishing_model_id,
            }
        except Exception as exc:
            print(f"  [nlp] Transformer inference failed: {exc}", file=sys.stderr)
            return None

    # ── 1b. Heuristic keyword scorer ───────────────────────────────────

    def _classify_heuristic(
        self, text: str, urls: list[str]
    ) -> dict[str, Any]:
        """Weighted keyword / pattern scoring (always available)."""
        text_lower = text.lower()
        word_count = max(len(text.split()), 1)

        # Accumulate per-category weighted hits
        cat_scores: dict[str, float] = {}
        cat_hits: dict[str, int] = {}
        signals: list[dict[str, Any]] = []

        for pat, category, severity, weight in _COMPILED_PHRASES:
            matches = pat.findall(text)
            if matches:
                cat_scores[category] = cat_scores.get(category, 0.0) + weight * len(matches)
                cat_hits[category] = cat_hits.get(category, 0) + len(matches)

        # URL risk
        url_risk = 0.0
        for url in urls:
            risk = self._score_url_risk(url)
            url_risk = max(url_risk, risk)

        # Compute a composite phishing score via sigmoid
        raw = (
            cat_scores.get("urgency", 0) * 0.8
            + cat_scores.get("financial", 0) * 0.7
            + cat_scores.get("secrecy", 0) * 1.2
            + cat_scores.get("threat", 0) * 0.9
            + cat_scores.get("impersonation", 0) * 0.6
            + url_risk * 4.0
            - 3.0  # bias so neutral text ≈ 0.05
        )
        phishing_score = 1.0 / (1.0 + math.exp(-raw))  # sigmoid

        # Per-category normalised sub-scores (0–1 via tanh)
        category_scores = {}
        for cat in PHRASE_PATTERNS:
            cs = cat_scores.get(cat, 0.0)
            category_scores[cat] = {
                "score": round(math.tanh(cs / 4.0), 3),
                "matches": cat_hits.get(cat, 0),
            }
        category_scores["url_risk"] = {
            "score": round(url_risk, 3),
            "suspicious_urls": sum(1 for u in urls if self._score_url_risk(u) > 0.4),
        }

        return {
            "score": round(phishing_score, 4),
            "label": "phishing" if phishing_score >= 0.5 else "safe",
            "confidence": round(phishing_score, 4),
            "method": "heuristic",
            "signals": category_scores,
        }

    @staticmethod
    def _score_url_risk(url: str) -> float:
        """Return 0–1 risk score for a single URL."""
        risk = 0.0
        lower = url.lower()

        # Suspicious TLD
        for tld in _SUSPICIOUS_TLDS:
            if tld in lower:
                risk += 0.4
                break

        # IP-address URL
        if re.search(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", lower):
            risk += 0.5

        # Very long URL (obfuscation)
        if len(url) > 120:
            risk += 0.15

        # Multiple subdomains
        try:
            host = url.split("//", 1)[1].split("/", 1)[0].split("?", 1)[0]
            if host.count(".") >= 4:
                risk += 0.25
        except IndexError:
            pass

        # Known phishy keywords in path
        phishy_kw = ["verify", "login", "secure", "update", "confirm", "auth", "signin", "account"]
        path = url.split("//", 1)[-1]
        for kw in phishy_kw:
            if kw in path.lower():
                risk += 0.1
                break

        return min(risk, 1.0)

    # ══════════════════════════════════════════════════════════════════
    # 2.  AI-GENERATED TEXT DETECTION  (GPT-2 perplexity + burstiness)
    # ══════════════════════════════════════════════════════════════════

    def _detect_ai_generated(self, body: str) -> dict[str, Any]:
        """Estimate whether the body is AI-generated."""
        if not self.lightweight and _HAS_TRANSFORMERS:
            result = self._perplexity_gpt2(body)
            if result is not None:
                return result

        return self._ai_heuristic(body)

    # ── 2a. GPT-2 perplexity ──────────────────────────────────────────

    def _perplexity_gpt2(self, text: str) -> dict[str, Any] | None:
        """Compute per-token perplexity and per-sentence burstiness."""
        if not self._gpt2_loaded:
            self._gpt2_loaded = True
            try:
                print(
                    f"  [nlp] Loading GPT-2 model: {self._gpt2_model_id}…",
                    file=sys.stderr,
                )
                self._gpt2_tok = GPT2TokenizerFast.from_pretrained(self._gpt2_model_id)
                self._gpt2_model = GPT2LMHeadModel.from_pretrained(self._gpt2_model_id)
                self._gpt2_model.eval()
            except Exception as exc:
                print(f"  [nlp] GPT-2 load failed: {exc}", file=sys.stderr)
                return None

        if self._gpt2_model is None:
            return None

        try:
            ppl = self._compute_ppl(text)
            if ppl < 0:
                return self._ai_heuristic(text)

            # Per-sentence burstiness
            sentences = _sent_tokenize(text)
            sent_ppls = []
            for s in sentences:
                sp = self._compute_ppl(s)
                if sp > 0:
                    sent_ppls.append(sp)

            burstiness = statistics.stdev(sent_ppls) if len(sent_ppls) >= 3 else -1.0

            # Map to AI score
            #   Low perplexity  +  low burstiness  →  likely AI
            #   High perplexity +  high burstiness →  likely human
            ppl_score = max(0.0, min(1.0, 1.0 - (ppl - 15) / 120))
            burst_score = (
                max(0.0, min(1.0, 1.0 - (burstiness - 5) / 50))
                if burstiness >= 0
                else 0.5
            )
            ai_score = 0.55 * ppl_score + 0.45 * burst_score

            return {
                "score": round(ai_score, 4),
                "label": self._ai_label(ai_score),
                "perplexity": round(ppl, 2),
                "burstiness": round(burstiness, 2) if burstiness >= 0 else None,
                "sentences_analysed": len(sent_ppls),
                "method": "gpt2",
            }
        except Exception as exc:
            print(f"  [nlp] GPT-2 inference failed: {exc}", file=sys.stderr)
            return None

    def _compute_ppl(self, text: str) -> float:
        """Return perplexity of *text* under GPT-2.  Returns -1 if too short."""
        enc = self._gpt2_tok(text, return_tensors="pt", truncation=True, max_length=1024)
        ids = enc.input_ids
        if ids.shape[1] < 5:
            return -1.0
        with torch.no_grad():
            out = self._gpt2_model(ids, labels=ids)
        return math.exp(out.loss.item())

    # ── 2b. Heuristic AI-detection fallback ────────────────────────────

    def _ai_heuristic(self, text: str) -> dict[str, Any]:
        """Lightweight heuristic based on lexical statistics."""
        words = text.split()
        n = max(len(words), 1)

        # Type-token ratio (lower → more repetitive → possibly AI)
        ttr = len(set(w.lower() for w in words)) / n

        # Average word length
        avg_wl = sum(len(w) for w in words) / n

        # Sentence-length variance
        sents = _sent_tokenize(text)
        sent_lens = [len(s.split()) for s in sents]
        sent_var = statistics.stdev(sent_lens) if len(sent_lens) >= 3 else 10.0

        # Simple heuristic score
        #   AI text: TTR ~0.4-0.6, uniform sentence length
        #   Human text: TTR higher or lower (depends), variable sentence length
        ttr_signal = max(0, min(1, 1.0 - abs(ttr - 0.50) * 4))
        var_signal = max(0, min(1, 1.0 - sent_var / 15.0))
        ai_score = 0.5 * ttr_signal + 0.5 * var_signal

        return {
            "score": round(ai_score, 4),
            "label": self._ai_label(ai_score),
            "type_token_ratio": round(ttr, 3),
            "avg_word_length": round(avg_wl, 2),
            "sentence_length_stdev": round(sent_var, 2),
            "method": "heuristic",
        }

    @staticmethod
    def _ai_label(score: float) -> str:
        if score >= 0.75:
            return "likely AI-generated"
        if score >= 0.5:
            return "possibly AI-generated"
        if score >= 0.3:
            return "uncertain"
        return "likely human-written"

    # ══════════════════════════════════════════════════════════════════
    # 3.  ENTITY EXTRACTION
    # ══════════════════════════════════════════════════════════════════

    def _extract_entities(
        self, body: str, urls: list[str]
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "financial": self._extract_financial(body),
            "references": self._extract_references(body),
            "contact": self._extract_contact(body),
            "urls": self._analyse_urls(urls),
            "crypto": [m for m in _RE_CRYPTO.findall(body)],
        }

        # Optional spaCy NER
        if not self.lightweight and _HAS_SPACY:
            result["named_entities"] = self._spacy_ner(body)
        else:
            result["named_entities"] = None

        return result

    @staticmethod
    def _extract_financial(text: str) -> list[dict[str, str]]:
        items: list[dict[str, str]] = []
        for m in _RE_IBAN.finditer(text):
            items.append({"type": "IBAN", "value": m.group(1).strip()})
        for m in _RE_SWIFT.finditer(text):
            val = m.group(1)
            # Exclude common English words that match the 8-char pattern
            if len(val) >= 8 and not val.isalpha():
                items.append({"type": "SWIFT/BIC", "value": val})
        for m in _RE_AMOUNT.finditer(text):
            val = (m.group(1) or m.group(2) or "").strip()
            if val:
                items.append({"type": "monetary_amount", "value": val})
        return items

    @staticmethod
    def _extract_references(text: str) -> list[dict[str, str]]:
        items: list[dict[str, str]] = []
        for m in _RE_INVOICE.finditer(text):
            items.append({"type": "reference_number", "value": m.group(1).strip()})
        return items

    @staticmethod
    def _extract_contact(text: str) -> list[dict[str, str]]:
        items: list[dict[str, str]] = []
        for m in _RE_PHONE.finditer(text):
            val = m.group(0).strip()
            # Ignore very short matches (likely just part numbers)
            if len(re.sub(r"\D", "", val)) >= 7:
                items.append({"type": "phone", "value": val})
        seen_emails: set[str] = set()
        for m in _RE_EMAIL.finditer(text):
            addr = m.group(0).lower()
            if addr not in seen_emails:
                seen_emails.add(addr)
                items.append({"type": "email", "value": addr})
        return items

    def _analyse_urls(self, urls: list[str]) -> list[dict[str, Any]]:
        return [
            {
                "url": u,
                "risk_score": round(self._score_url_risk(u), 3),
                "suspicious": self._score_url_risk(u) > 0.4,
            }
            for u in urls
        ]

    def _spacy_ner(self, text: str) -> list[dict[str, str]]:
        """Extract named entities via spaCy (lazy-loaded)."""
        if not self._spacy_loaded:
            self._spacy_loaded = True
            try:
                self._spacy_nlp = spacy.load("en_core_web_sm")
            except OSError:
                try:
                    print("  [nlp] Downloading spaCy model…", file=sys.stderr)
                    from spacy.cli import download

                    download("en_core_web_sm")
                    self._spacy_nlp = spacy.load("en_core_web_sm")
                except Exception:
                    pass

        if self._spacy_nlp is None:
            return []

        doc = self._spacy_nlp(text[:10000])
        entities: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for ent in doc.ents:
            if ent.label_ in ("PERSON", "ORG", "GPE", "MONEY", "DATE", "NORP"):
                key = (ent.text.strip(), ent.label_)
                if key not in seen:
                    seen.add(key)
                    entities.append({"text": ent.text.strip(), "label": ent.label_})
        return entities

    # ══════════════════════════════════════════════════════════════════
    # 4.  PHRASE FLAGGING
    # ══════════════════════════════════════════════════════════════════

    @staticmethod
    def _flag_phrases(subject: str, body: str) -> list[dict[str, Any]]:
        """Return every suspicious phrase match with context."""
        full_text = f"{subject}\n{body}"
        flags: list[dict[str, Any]] = []
        seen_phrases: set[str] = set()

        for pat, category, severity, _w in _COMPILED_PHRASES:
            for m in pat.finditer(full_text):
                phrase = m.group(0)
                if phrase.lower() in seen_phrases:
                    continue
                seen_phrases.add(phrase.lower())

                # Extract surrounding context (±40 chars)
                start = max(0, m.start() - 40)
                end = min(len(full_text), m.end() + 40)
                context = full_text[start:end].replace("\n", " ").strip()
                if start > 0:
                    context = "…" + context
                if end < len(full_text):
                    context += "…"

                flags.append(
                    {
                        "phrase": phrase,
                        "category": category,
                        "severity": severity,
                        "context": context,
                    }
                )

        # Sort: critical → high → medium → low
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        flags.sort(key=lambda f: sev_order.get(f["severity"], 9))

        return flags
