"""
fusion_engine.py — Multi-Engine Score Fusion

Fuses outputs from the four analysis engines (HeaderParser, NLPEngine,
VisualEngine, AttributionGraph) using Dempster–Shafer evidence theory.
Categorises the results into standard threat tiers and returns a unified verdict
with a detailed reasoning trace.
"""

from __future__ import annotations

from typing import Any, Dict, List


class FusionEngine:
    """Fuses outputs from the four analysis engines into a single verdict."""

    def fuse(
        self,
        header_result: dict,
        nlp_result: dict,
        visual_result: dict,
        attribution_result: dict,
    ) -> dict[str, Any]:
        """Combine engine results into a unified threat verdict.

        Args:
            header_result:      Output of HeaderParser.analyse().
            nlp_result:         Output of NLPEngine.analyse().
            visual_result:      Output of VisualEngine.analyse().
            attribution_result: Output of AttributionGraph.build().

        Returns:
            A dict with keys ``threat_score`` (0-100), ``tier`` (str),
            ``signal_contributions`` (list), and ``reasoning`` (str).
        """
        contributions: list[dict[str, Any]] = []
        reasoning_steps: list[str] = []

        # ── 1. Define Engine Masses ────────────────────────────────────

        # Initialize mass distributions as:
        #   'T' (Threat belief), 'S' (Safe belief), 'U' (Uncertainty / don't know)
        # where T + S + U = 1.0

        # --- A. Header Parser Evidence ---
        m_header = self._get_header_mass(header_result, contributions, reasoning_steps)

        # --- B. NLP Engine Evidence ---
        m_nlp = self._get_nlp_mass(nlp_result, contributions, reasoning_steps)

        # --- C. Visual Engine Evidence ---
        m_visual = self._get_visual_mass(visual_result, contributions, reasoning_steps)

        # --- D. Attribution Graph Evidence ---
        m_attribution = self._get_attribution_mass(attribution_result, contributions, reasoning_steps)

        # ── 2. Combine Evidence Sequential using Dempster's Rule ───────

        m_combined = {"T": 0.0, "S": 0.0, "U": 1.0}  # Start with total uncertainty
        m_combined = self._dempster_combine(m_combined, m_header)
        m_combined = self._dempster_combine(m_combined, m_nlp)
        m_combined = self._dempster_combine(m_combined, m_visual)
        m_combined = self._dempster_combine(m_combined, m_attribution)

        # ── 3. Calculate Final Threat Score and Tier ───────────────────

        # Score is primarily based on Threat belief (T), scaled 0-100
        threat_score = int(round(m_combined["T"] * 100))

        if threat_score >= 80:
            tier = "CONFIRMED_THREAT"
        elif threat_score >= 50:
            tier = "LIKELY_PHISH"
        elif threat_score >= 20:
            tier = "SUSPICIOUS"
        else:
            tier = "SAFE"

        # Combine all reasoning steps into a cohesive text block
        reasoning = " | ".join(reasoning_steps) if reasoning_steps else "No significant threat indicators found."

        return {
            "threat_score": threat_score,
            "tier": tier,
            "signal_contributions": contributions,
            "reasoning": reasoning,
            "raw_belief": {
                "threat": round(m_combined["T"], 4),
                "safe": round(m_combined["S"], 4),
                "uncertainty": round(m_combined["U"], 4),
            },
        }

    # ── Mass Calculation Helpers ───────────────────────────────────────

    def _get_header_mass(
        self, header: dict, contributions: list, reasoning: list
# pytype: disable=bad-return-type
    ) -> dict[str, float]:
        t_belief = 0.0
        s_belief = 0.0

        # Check SPF / DKIM / DMARC
        hdr_auth = header.get("auth_results", {}).get("header", {})
        spf_v = (hdr_auth.get("spf") or {}).get("verdict", "none")
        dkim_v = (hdr_auth.get("dkim") or {}).get("verdict", "none")
        dmarc_v = (hdr_auth.get("dmarc") or {}).get("verdict", "none")

        auth_issues = []
        if spf_v in ("fail", "softfail"):
            auth_issues.append(f"SPF {spf_v.upper()}")
            t_belief += 0.15
        if dkim_v in ("fail", "none"):
            auth_issues.append(f"DKIM {dkim_v.upper()}")
            t_belief += 0.10
        if dmarc_v in ("fail", "none"):
            auth_issues.append(f"DMARC {dmarc_v.upper()}")
            t_belief += 0.20

        if auth_issues:
            reasoning.append(f"Email authentication issues: {', '.join(auth_issues)}")

        # Check Spoofing Flags
        flags = header.get("spoofing_flags", [])
        for f in flags:
            ftype = f.get("type")
            sev = f.get("severity", "medium")
            
            # Map severity to belief increments
            weight = {"critical": 0.50, "high": 0.35, "medium": 0.20, "low": 0.05}.get(sev, 0.10)
            t_belief += weight
            reasoning.append(f"Spoofing flagged: {f.get('description', ftype)}")

        # Cap Threat belief from header
        t_belief = min(t_belief, 0.90)

        # If everything passes and no flags, assert safe belief
        if not auth_issues and not flags and spf_v == "pass" and dkim_v == "pass" and dmarc_v == "pass":
            s_belief = 0.60
            reasoning.append("Header validation: All SPF/DKIM/DMARC authentications passed, zero anomalies.")

        # Compute uncertainty
        u_belief = 1.0 - t_belief - s_belief
        contributions.append({
            "engine": "HeaderParser",
            "threat_belief": round(t_belief, 3),
            "safe_belief": round(s_belief, 3),
            "uncertainty": round(u_belief, 3),
        })

        return {"T": t_belief, "S": s_belief, "U": u_belief}

    def _get_nlp_mass(
        self, nlp: dict, contributions: list, reasoning: list
# pytype: disable=bad-return-type
    ) -> dict[str, float]:
        t_belief = 0.0
        s_belief = 0.0

        phish_info = nlp.get("phishing_score", {})
        score = phish_info.get("score", 0.0)

        if score >= 0.5:
            # Map score directly to threat evidence
            t_belief = score * 0.85
            signals = phish_info.get("signals", {})
            phish_reasons = []
            for sig_name, sig_data in signals.items():
                if isinstance(sig_data, dict) and sig_data.get("score", 0.0) > 0.4:
                    phish_reasons.append(sig_name)
            
            reasoning.append(
                f"NLP engine detected high phishing risk ({score:.2f}) "
                f"with signals: {', '.join(phish_reasons) or 'general keywords'}"
            )
        else:
            s_belief = (1.0 - score) * 0.50
            reasoning.append(f"NLP engine text analysis: standard/legitimate tone ({score:.2f})")

        # Capture flagged phrases count
        n_flags = len(nlp.get("flagged_phrases", []))
        if n_flags > 0:
            t_belief = min(t_belief + min(n_flags * 0.05, 0.15), 0.95)

        u_belief = 1.0 - t_belief - s_belief
        contributions.append({
            "engine": "NLPEngine",
            "threat_belief": round(t_belief, 3),
            "safe_belief": round(s_belief, 3),
            "uncertainty": round(u_belief, 3),
        })

        return {"T": t_belief, "S": s_belief, "U": u_belief}

    def _get_visual_mass(
        self, visual: dict, contributions: list, reasoning: list
# pytype: disable=bad-return-type
    ) -> dict[str, float]:
        t_belief = 0.0
        s_belief = 0.0

        images = visual.get("images_scanned", 0)
        qr_count = visual.get("qr_codes_found", 0)
        decoded = visual.get("decoded_urls", [])

        if qr_count > 0:
            # Check risks associated with QR URLs
            url_flags = visual.get("url_risk_flags", [])
            max_risk = 0.0
            critical_flags = []

            for entry in url_flags:
                max_risk = max(max_risk, entry.get("risk_score", 0.0))
                for f in entry.get("flags", []):
                    if f.get("severity") in ("high", "critical"):
                        critical_flags.append(f.get("flag"))

            if max_risk >= 0.4:
                t_belief = 0.50 + (max_risk * 0.40)  # scale 0.50 to 0.90
                reasoning.append(
                    f"Visual engine flagged embedded QR code linking to risky URL: "
                    f"{', '.join(decoded)} ({', '.join(critical_flags)})"
                )
            else:
                t_belief = 0.35  # Suspicious but URL looks normal
                reasoning.append(f"Visual engine found embedded QR code linking to: {', '.join(decoded)}")
        else:
            # No QR codes found
            if images == 0 and not visual.get("attachments", []):
                s_belief = 0.20
            else:
                # Images exist but no QRs
                s_belief = 0.10

        u_belief = 1.0 - t_belief - s_belief
        contributions.append({
            "engine": "VisualEngine",
            "threat_belief": round(t_belief, 3),
            "safe_belief": round(s_belief, 3),
            "uncertainty": round(u_belief, 3),
        })

        return {"T": t_belief, "S": s_belief, "U": u_belief}

    def _get_attribution_mass(
        self, attr: dict, contributions: list, reasoning: list
# pytype: disable=bad-return-type
    ) -> dict[str, float]:
        t_belief = 0.0
        s_belief = 0.0

        attributions = attr.get("attributions", [])
        indicators = attr.get("indicators", {})

        if attributions:
            top = attributions[0]
            confidence = top.get("confidence", 0)
            
            # Map threat actor confidence to belief
            t_belief = (confidence / 100.0) * 0.95
            t_belief = max(t_belief, 0.40)  # Floor of 40% if any known actor profile hits
            
            reasoning.append(f"Threat attribution match: {top['actor_name']} ({confidence}% confidence)")
        elif indicators.get("total_malicious_nodes", 0) > 0:
            t_belief = 0.70  # Hit blocklist but not attributed
            reasoning.append("Infrastructure correlation: Indicators found on threat-intel blocklist")
        else:
            s_belief = 0.30  # clean correlation

        u_belief = 1.0 - t_belief - s_belief
        contributions.append({
            "engine": "AttributionGraph",
            "threat_belief": round(t_belief, 3),
            "safe_belief": round(s_belief, 3),
            "uncertainty": round(u_belief, 3),
        })

        return {"T": t_belief, "S": s_belief, "U": u_belief}

    # ── Dempster Combination Implementation ────────────────────────────

    @staticmethod
    def _dempster_combine(m1: dict[str, float], m2: dict[str, float]) -> dict[str, float]:
        """Combine two mass distributions using Dempster's rule of combination."""
        # Conflict metric K
        k = m1["T"] * m2["S"] + m1["S"] * m2["T"]
        
        # In case of near-total conflict, handle gracefully
        if k >= 0.9999:
            # Fallback: simple average
            t_avg = (m1["T"] + m2["T"]) / 2.0
            s_avg = (m1["S"] + m2["S"]) / 2.0
            return {"T": t_avg, "S": s_avg, "U": 1.0 - t_avg - s_avg}

        # Dempster combination formula
        denom = 1.0 - k
        t_comb = (m1["T"] * m2["T"] + m1["T"] * m2["U"] + m1["U"] * m2["T"]) / denom
        s_comb = (m1["S"] * m2["S"] + m1["S"] * m2["U"] + m1["U"] * m2["S"]) / denom
        u_comb = (m1["U"] * m2["U"]) / denom

        return {"T": t_comb, "S": s_comb, "U": u_comb}
