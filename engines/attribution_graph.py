"""
attribution_graph.py — Threat Attribution & Relationship Graph Engine

Builds a NetworkX relationship graph linking email metadata, relay hops,
domains, URLs, attachments, and financial entities.
Correlates these entities against a local threat intelligence database
and computes threat-actor attribution confidence scores.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse
import networkx as nx

# ── Local Threat Intelligence Database ────────────────────────────────

THREAT_INTEL = {
    "actors": [
        {
            "id": "APT-Storm-0982",
            "name": "Storm-0982 (Scattered Spider subgroup)",
            "type": "Cybercrime / Access Broker",
            "known_domains": {"company-1t-support.net", "m1cr0soft-secure.xyz"},
            "known_ips": {"153.92.0.44", "185.234.72.19"},
            "known_emails": {"helpdesk@company-1t-support.net", "security-alert@m1cr0soft-secure.xyz"},
            "tactics": "QR-phishing (quishing), MFA fatigue/bypass, Microsoft 365 credential harvesting.",
            "severity": "critical",
        },
        {
            "id": "TA505-BEC",
            "name": "TA505 BEC Campaign",
            "type": "Business Email Compromise (BEC) Group",
            "known_domains": {"deltahold1ngs.com"},
            "known_ips": {"194.163.128.77"},
            "known_emails": {"r.walsh@deltahold1ngs.com"},
            "tactics": "Executive impersonation, financial invoice fraud, ProtonMail/anonymous reply-to routing.",
            "severity": "high",
        },
    ],
    "malicious_domains": {
        "m1cr0soft-secure.xyz",
        "deltahold1ngs.com",
        "company-1t-support.net",
    },
    "malicious_ips": {
        "185.234.72.19",
        "194.163.128.77",
        "153.92.0.44",
    },
}


class AttributionGraph:
    """Builds a threat-attribution knowledge graph linking observed entities."""

    def build(
        self, header_result: dict, nlp_result: dict, visual_result: dict
    ) -> dict[str, Any]:
        """Construct an attribution graph from all analysis engine outputs.

        Args:
            header_result: Output of HeaderParser.analyse().
            nlp_result:    Output of NLPEngine.analyse().
            visual_result: Output of VisualEngine.analyse().

        Returns:
            A dict containing the NetworkX DiGraph, serialised nodes/edges,
            and threat-actor attribution details.
        """
        g = nx.DiGraph()

        # 1. Add the central Email node
        email_id = header_result.get("file", "subject_email")
        g.add_node(
            email_id,
            type="email",
            label="Email",
            subject=header_result.get("subject", ""),
        )

        # 2. Add Sender and Reply-To entities
        from_hdr = header_result.get("from", "")
        sender_email = self._extract_email_address(from_hdr)
        sender_domain = header_result.get("auth_results", {}).get("header_from_domain")

        if sender_email:
            g.add_node(sender_email, type="sender", label=f"Sender: {sender_email}")
            g.add_edge(email_id, sender_email, relation="has_sender")

            if sender_domain:
                g.add_node(sender_domain, type="domain", label=f"Domain: {sender_domain}")
                g.add_edge(sender_email, sender_domain, relation="belongs_to_domain")

        # Extract Reply-To from NLP entities or spoofing flags
        reply_to_email = None
        for flag in header_result.get("spoofing_flags", []):
            if flag.get("type") == "domain_mismatch" and "Reply-To" in flag.get("fields", []):
                # Reply-to mismatch was flagged, let's find the Reply-To email from NLP or flags
                pass

        # Parse NLP contact emails to find reply-to or other entities
        contacts = nlp_result.get("extracted_entities", {}).get("contact", [])
        for c in contacts:
            if c.get("type") == "email":
                c_email = c.get("value")
                if c_email and c_email != sender_email:
                    g.add_node(c_email, type="contact_email", label=f"Contact: {c_email}")
                    g.add_edge(email_id, c_email, relation="mentions_email")
                    c_dom = c_email.split("@")[-1] if "@" in c_email else None
                    if c_dom:
                        g.add_node(c_dom, type="domain", label=f"Domain: {c_dom}")
                        g.add_edge(c_email, c_dom, relation="belongs_to_domain")

        # 3. Add IP and Geolocation nodes from relay path
        relay_path = header_result.get("relay_path", [])
        for hop in relay_path:
            ip = hop.get("from_ip")
            if ip:
                ip_label = f"IP: {ip}"
                # Get geo location if available
                geo_info = next((item for item in header_result.get("geo_trace", []) if item.get("ip") == ip), {})
                country = geo_info.get("country")
                isp = geo_info.get("isp")
                
                attrs = {"type": "ip", "label": ip_label}
                if country:
                    attrs["country"] = country
                if isp:
                    attrs["isp"] = isp
                
                g.add_node(ip, **attrs)
                g.add_edge(email_id, ip, relation="routed_through", hop=hop.get("hop"))

                # Link IP to its country if country exists
                if country:
                    g.add_node(country, type="location", label=f"Country: {country}")
                    g.add_edge(ip, country, relation="located_in")

        # 4. Add URL nodes (body URLs and visual QR URLs)
        body_urls = nlp_result.get("extracted_entities", {}).get("urls", [])
        qr_urls = visual_result.get("decoded_urls", [])

        all_urls = []
        for bu in body_urls:
            all_urls.append((bu.get("url"), "body"))
        for qu in qr_urls:
            all_urls.append((qu, "qr_code"))

        for url_str, source in all_urls:
            if not url_str:
                continue
            url_node_id = f"url:{url_str}"
            g.add_node(url_node_id, type="url", label=f"URL ({source})", url=url_str)
            g.add_edge(email_id, url_node_id, relation="contains_url", source=source)

            # Link URL to its domain
            try:
                parsed = urlparse(url_str)
                domain = parsed.netloc.lower()
                if ":" in domain:
                    domain = domain.split(":")[0]
                if domain:
                    g.add_node(domain, type="domain", label=f"Domain: {domain}")
                    g.add_edge(url_node_id, domain, relation="resolves_to_domain")
            except Exception:
                pass

        # 5. Add Attachments
        attachments = visual_result.get("attachments", [])
        for att in attachments:
            fname = att.get("filename", "unnamed_attachment")
            g.add_node(fname, type="attachment", label=f"Attachment: {fname}", content_type=att.get("content_type", ""))
            g.add_edge(email_id, fname, relation="has_attachment")

        # 6. Add Financial details (IBAN, SWIFT, etc.)
        financials = nlp_result.get("extracted_entities", {}).get("financial", [])
        for fin in financials:
            fin_type = fin.get("type", "financial")
            fin_val = fin.get("value", "")
            if fin_val:
                g.add_node(fin_val, type="financial", label=f"{fin_type}: {fin_val}", subtype=fin_type)
                g.add_edge(email_id, fin_val, relation="mentions_financial")

        # 7. Perform Threat Intelligence Correlation and Actor Attribution
        attributions, indicators = self._correlate_threat_intel(g)

        # 8. Add Actor node to the graph if high confidence attribution
        for attr in attributions:
            if attr["confidence"] >= 30: # Only draw actor nodes for plausible matches
                actor_id = attr["actor_id"]
                actor_name = attr["actor_name"]
                g.add_node(actor_id, type="actor", label=f"Threat Actor: {actor_name}", details=attr)
                
                # Draw edges from all matching nodes in the graph to the Actor node
                for match_val in attr["matched_indicators"]:
                    if g.has_node(match_val):
                        g.add_edge(match_val, actor_id, relation="associated_with_actor")

        # 9. Format output dictionary
        # Convert NetworkX graph to serialisable node/link format
        nodes_list = []
        for node_id, data in g.nodes(data=True):
            node_data = {"id": node_id}
            node_data.update(data)
            nodes_list.append(node_data)

        edges_list = []
        for source, target, data in g.edges(data=True):
            edge_data = {"source": source, "target": target}
            edge_data.update(data)
            edges_list.append(edge_data)

        return {
            "graph": g,
            "nodes": nodes_list,
            "edges": edges_list,
            "attributions": attributions,
            "indicators": indicators,
            "summary": self._generate_summary(attributions, indicators),
        }

    # ── Correlation Logic ──────────────────────────────────────────────

    def _correlate_threat_intel(self, g: nx.DiGraph) -> tuple[list[dict], dict]:
        """Correlate all nodes in the graph with known threat intelligence."""
        matched_indicators = []
        actor_scores: dict[str, set] = {} # actor_id -> set of matching nodes
        
        blocklisted_domains_hit = []
        blocklisted_ips_hit = []

        # Scan nodes for threat intel hits
        for node_id, data in g.nodes(data=True):
            ntype = data.get("type")
            
            # Check domain blocklist
            if ntype == "domain":
                domain_val = node_id.lower()
                if domain_val in THREAT_INTEL["malicious_domains"]:
                    blocklisted_domains_hit.append(domain_val)
                    matched_indicators.append({"type": "domain", "value": domain_val, "status": "malicious"})
                
                # Corelate with actors
                for actor in THREAT_INTEL["actors"]:
                    if domain_val in actor["known_domains"]:
                        actor_scores.setdefault(actor["id"], set()).add(domain_val)

            # Check IP blocklist
            elif ntype == "ip":
                ip_val = node_id
                if ip_val in THREAT_INTEL["malicious_ips"]:
                    blocklisted_ips_hit.append(ip_val)
                    matched_indicators.append({"type": "ip", "value": ip_val, "status": "malicious"})

                # Corelate with actors
                for actor in THREAT_INTEL["actors"]:
                    if ip_val in actor["known_ips"]:
                        actor_scores.setdefault(actor["id"], set()).add(ip_val)

            # Check Email blocklist
            elif ntype in ("sender", "contact_email"):
                email_val = node_id.lower()
                for actor in THREAT_INTEL["actors"]:
                    if email_val in actor["known_emails"]:
                        actor_scores.setdefault(actor["id"], set()).add(email_val)
                        matched_indicators.append({"type": "email", "value": email_val, "status": "malicious"})

        # Compute attribution scores
        attributions = []
        for actor in THREAT_INTEL["actors"]:
            aid = actor["id"]
            matches = actor_scores.get(aid, set())
            
            if not matches:
                continue

            # Calculate confidence score (0 to 100) based on matches
            # E.g., matching a domain and an IP gives 100, one match gives 50
            total_indicators = len(actor["known_domains"]) + len(actor["known_ips"]) + len(actor["known_emails"])
            confidence = int((len(matches) / max(total_indicators, 1)) * 100)
            # Give a minimum floor confidence of 30 if we have any match
            confidence = max(confidence, 40 if len(matches) > 1 else 30)
            confidence = min(confidence, 100)

            attributions.append({
                "actor_id": aid,
                "actor_name": actor["name"],
                "actor_type": actor["type"],
                "tactics": actor["tactics"],
                "severity": actor["severity"],
                "confidence": confidence,
                "matched_indicators": list(matches),
            })

        # Sort attributions by confidence
        attributions.sort(key=lambda x: x["confidence"], reverse=True)

        indicators = {
            "blocklisted_domains": blocklisted_domains_hit,
            "blocklisted_ips": blocklisted_ips_hit,
            "total_malicious_nodes": len(matched_indicators),
        }

        return attributions, indicators

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _extract_email_address(hdr: str) -> str | None:
        """Extract 'alice@example.com' from 'Alice <alice@example.com>'."""
        if not hdr:
            return None
        m = re.search(r"[\w.\-]+@[\w.\-]+", hdr)
        return m.group(0).lower() if m else None

    @staticmethod
    def _generate_summary(attributions: list[dict], indicators: dict) -> str:
        """Generate a natural language attribution summary."""
        if not attributions:
            if indicators["total_malicious_nodes"] > 0:
                return (
                    f"Threat intelligence correlation flagged {indicators['total_malicious_nodes']} "
                    f"infrastructure IOC(s) as malicious (Domains: {', '.join(indicators['blocklisted_domains']) or 'None'}; "
                    f"IPs: {', '.join(indicators['blocklisted_ips']) or 'None'}), but no specific threat-actor group "
                    f"could be attributed with high confidence."
                )
            return "No known threat indicators or threat-actor profiles matched the artifacts in this email."

        top = attributions[0]
        summary = (
            f"Attributed to {c(top['actor_name'], 'bold', 'red')} ({top['actor_type']}) with "
            f"{c(str(top['confidence']) + '%', 'bold')} confidence. Matching indicators: "
            f"{', '.join(top['matched_indicators'])}. "
            f"Observed Tactics: {top['tactics']}"
        )
        return summary


# Late binding of utility coloring function just for internal summary formatting
def c(text: str, *styles: str) -> str:
    # Minimal console-style format helper for summary output
    _C = {"bold": "\033[1m", "red": "\033[91m", "reset": "\033[0m"}
    prefix = "".join(_C.get(s, "") for s in styles)
    return f"{prefix}{text}{_C['reset']}" if prefix else text
