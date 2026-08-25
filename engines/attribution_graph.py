"""
attribution_graph.py — Threat Attribution & Relationship Graph Engine

Builds a NetworkX relationship graph linking email metadata, relay hops,
domains, URLs, attachments, and financial entities across individual or batches of emails.

Features:
1. Builds a NetworkX graph connecting emails, sender IPs, relay hosts, and decoded URLs.
2. Adds direct cross-email edges when two emails share an IP, relay host, or URL/Reply-To domain.
3. Detects connected components (clusters) as candidate threat "campaigns".
4. Exports graph as NetworkX object, custom node-link dicts, and standard JSON node-link format.
5. Provides render_graph_png() using matplotlib to export static graph visualizations.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple, Union
from urllib.parse import urlparse

import networkx as nx

# ── Optional: Matplotlib for static graph PNG rendering ────────────────
try:
    import matplotlib
    matplotlib.use("Agg")  # Non-interactive background backend
    import matplotlib.pyplot as plt
    _HAS_MATPLOTLIB = True
except ImportError:  # pragma: no cover
    _HAS_MATPLOTLIB = False

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
    """Builds a threat-attribution knowledge graph linking observed entities across emails."""

    def build(
        self, header_result: dict, nlp_result: dict, visual_result: dict
    ) -> dict[str, Any]:
        """Construct an attribution graph for a single email.

        Maintains full backward-compatibility with single-email analysis callers.
        """
        return self.build_batch([(header_result, nlp_result, visual_result)])

    def build_batch(
        self,
        email_results: list[Union[dict, tuple[dict, dict, dict]]],
    ) -> dict[str, Any]:
        """Construct an attribution graph from a batch of email engine outputs.

        Parameters
        ----------
        email_results : list
            A list where each item is either:
            - A 3-tuple: (header_result, nlp_result, visual_result)
            - A dict with keys "header", "nlp", "visual" (or "header_result", "nlp_result", "visual_result")

        Returns
        -------
        dict
            Contains graph (NetworkX object), nodes, edges, json_data (node-link JSON format),
            campaigns (connected components), attributions, indicators, and summary.
        """
        g = nx.DiGraph()
        parsed_batch = self._normalise_input_batch(email_results)

        email_nodes: list[str] = []

        # ── 1. Ingest Each Email into the Graph ────────────────────────
        for header_res, nlp_res, visual_res in parsed_batch:
            email_id = header_res.get("file", f"email_{len(email_nodes) + 1}")
            email_nodes.append(email_id)

            subject = header_res.get("subject", "")
            from_hdr = header_res.get("from", "")

            # 1a. Central Email Node
            g.add_node(
                email_id,
                type="email",
                label=f"Email: {email_id}",
                subject=subject,
                sender=from_hdr,
            )

            # 1b. Sender & Sender Domain
            sender_email = self._extract_email_address(from_hdr)
            sender_domain = header_res.get("auth_results", {}).get("header_from_domain")
            if not sender_domain and sender_email and "@" in sender_email:
                sender_domain = sender_email.split("@")[-1]

            if sender_email:
                g.add_node(sender_email, type="sender", label=f"Sender: {sender_email}")
                g.add_edge(email_id, sender_email, relation="has_sender")

                if sender_domain:
                    g.add_node(sender_domain, type="domain", label=f"Domain: {sender_domain}")
                    g.add_edge(sender_email, sender_domain, relation="belongs_to_domain")

            # 1c. Reply-To Address & Domain
            for flag in header_res.get("spoofing_flags", []):
                if flag.get("type") == "domain_mismatch" and "Reply-To" in flag.get("fields", []):
                    # Flag mentions reply-to mismatch
                    pass

            # Extract Reply-To from nlp / header
            contacts = nlp_res.get("extracted_entities", {}).get("contact", [])
            for c_item in contacts:
                if c_item.get("type") == "email":
                    c_email = c_item.get("value", "").lower()
                    if c_email and c_email != sender_email:
                        g.add_node(c_email, type="contact_email", label=f"Contact: {c_email}")
                        g.add_edge(email_id, c_email, relation="mentions_email")
                        if "@" in c_email:
                            c_dom = c_email.split("@")[-1]
                            g.add_node(c_dom, type="domain", label=f"Domain: {c_dom}")
                            g.add_edge(c_email, c_dom, relation="belongs_to_domain")
                            g.add_edge(email_id, c_dom, relation="has_reply_to_domain")

            # 1d. IPs and Geolocation from Relay Path
            relay_path = header_res.get("relay_path", [])
            geo_trace = header_res.get("geo_trace", [])
            for hop in relay_path:
                ip = hop.get("from_ip")
                if ip:
                    ip_label = f"IP: {ip}"
                    geo_info = next((item for item in geo_trace if item.get("ip") == ip), {})
                    country = geo_info.get("country")
                    isp = geo_info.get("isp")

                    attrs = {"type": "ip", "label": ip_label}
                    if country:
                        attrs["country"] = country
                    if isp:
                        attrs["isp"] = isp

                    g.add_node(ip, **attrs)
                    g.add_edge(email_id, ip, relation="routed_through", hop=hop.get("hop"))

                    if country:
                        g.add_node(country, type="location", label=f"Country: {country}")
                        g.add_edge(ip, country, relation="located_in")

                # 1e. Relay Hosts
                for host_field in ("from_host", "by_host"):
                    host_val = hop.get(host_field)
                    if host_val and host_val not in ("localhost", "unknown") and not self._is_ip_str(host_val):
                        host_node_id = f"host:{host_val.lower()}"
                        g.add_node(host_node_id, type="relay_host", label=f"Relay: {host_val}", host=host_val)
                        g.add_edge(email_id, host_node_id, relation="relayed_by")
                        
                        base_dom = self._base_domain(host_val)
                        if base_dom and "." in base_dom:
                            g.add_node(base_dom, type="domain", label=f"Domain: {base_dom}")
                            g.add_edge(host_node_id, base_dom, relation="belongs_to_domain")

            # 1f. URLs and Decoded QR URLs
            body_urls = nlp_res.get("extracted_entities", {}).get("urls", [])
            qr_urls = visual_res.get("decoded_urls", [])

            all_urls: list[tuple[str, str]] = []
            for bu in body_urls:
                all_urls.append((bu.get("url", ""), "body"))
            for qu in qr_urls:
                all_urls.append((qu, "qr_code"))

            for url_str, source in all_urls:
                if not url_str:
                    continue
                url_node_id = f"url:{url_str}"
                g.add_node(url_node_id, type="url", label=f"URL ({source})", url=url_str)
                g.add_edge(email_id, url_node_id, relation="contains_url", source=source)

                # Link URL to Domain
                try:
                    parsed_u = urlparse(url_str)
                    domain = parsed_u.netloc.lower()
                    if ":" in domain:
                        domain = domain.split(":")[0]
                    if domain:
                        g.add_node(domain, type="domain", label=f"Domain: {domain}")
                        g.add_edge(url_node_id, domain, relation="resolves_to_domain")
                        g.add_edge(email_id, domain, relation="uses_domain")
                except Exception:
                    pass

            # 1g. Attachments
            attachments = visual_res.get("attachments", [])
            for att in attachments:
                fname = att.get("filename", "unnamed_attachment")
                g.add_node(fname, type="attachment", label=f"Attachment: {fname}", content_type=att.get("content_type", ""))
                g.add_edge(email_id, fname, relation="has_attachment")

            # 1h. Financial details
            financials = nlp_res.get("extracted_entities", {}).get("financial", [])
            for fin in financials:
                fin_type = fin.get("type", "financial")
                fin_val = fin.get("value", "")
                if fin_val:
                    g.add_node(fin_val, type="financial", label=f"{fin_type}: {fin_val}", subtype=fin_type)
                    g.add_edge(email_id, fin_val, relation="mentions_financial")

        # ── 2. Add Direct Cross-Email Edges for Shared Infrastructure ───
        self._add_cross_email_edges(g, email_nodes)

        # ── 3. Detect Campaigns (Connected Components) ─────────────────
        campaigns = self._detect_campaigns(g, email_nodes)

        # ── 4. Threat Intel Correlation & Actor Attribution ─────────────
        attributions, indicators = self._correlate_threat_intel(g)

        # Add Actor nodes to graph if high confidence match
        for attr in attributions:
            if attr["confidence"] >= 30:
                actor_id = attr["actor_id"]
                actor_name = attr["actor_name"]
                g.add_node(actor_id, type="actor", label=f"Threat Actor: {actor_name}", details=attr)
                for match_val in attr["matched_indicators"]:
                    if g.has_node(match_val):
                        g.add_edge(match_val, actor_id, relation="associated_with_actor")

        # ── 5. Format Export Formats ───────────────────────────────────
        # Custom nodes list
        nodes_list = []
        for node_id, data in g.nodes(data=True):
            ndict = {"id": node_id}
            ndict.update(data)
            nodes_list.append(ndict)

        # Custom edges list
        edges_list = []
        for source, target, data in g.edges(data=True):
            edict = {"source": source, "target": target}
            edict.update(data)
            edges_list.append(edict)

        # Standard NetworkX JSON node-link format for frontend
        json_data = nx.node_link_data(g)

        return {
            "graph": g,
            "nodes": nodes_list,
            "edges": edges_list,
            "json_data": json_data,
            "campaigns": campaigns,
            "attributions": attributions,
            "indicators": indicators,
            "summary": self._generate_summary(attributions, indicators, campaigns),
        }

    # ── Cross-Email Edges ──────────────────────────────────────────────

    def _add_cross_email_edges(self, g: nx.DiGraph, email_nodes: list[str]) -> None:
        """Add direct edges between emails that share an IP, relay host, or URL/Reply-To domain."""
        num_emails = len(email_nodes)
        for i in range(num_emails):
            for j in range(i + 1, num_emails):
                e1, e2 = email_nodes[i], email_nodes[j]
                
                # Neighbors of E1 and E2
                n1 = set(g.successors(e1)) | set(g.predecessors(e1))
                n2 = set(g.successors(e2)) | set(g.predecessors(e2))
                common_nodes = n1 & n2

                for node_id in common_nodes:
                    ntype = g.nodes[node_id].get("type")
                    if ntype == "ip":
                        g.add_edge(e1, e2, relation="shares_ip", shared_val=node_id)
                    elif ntype == "relay_host":
                        host_val = g.nodes[node_id].get("host", node_id)
                        g.add_edge(e1, e2, relation="shares_relay_host", shared_val=host_val)
                    elif ntype == "domain":
                        # Skip generic targetcorp/internal domain matches from creating campaign links
                        if node_id.lower() not in ("targetcorp.com", "gmail.com", "outlook.com"):
                            g.add_edge(e1, e2, relation="shares_url_domain", shared_val=node_id)

    # ── Campaign / Connected Components Detection ──────────────────────

    def _detect_campaigns(self, g: nx.DiGraph, email_nodes: list[str]) -> list[dict[str, Any]]:
        """Detect connected components (clusters) of emails as candidate campaigns."""
        ug = g.to_undirected()
        components = list(nx.connected_components(ug))

        campaigns: list[dict[str, Any]] = []

        for idx, comp in enumerate(components):
            emails_in_comp = [n for n in comp if g.nodes[n].get("type") == "email"]
            if not emails_in_comp:
                continue

            # Shared indicators in component
            shared_ips = [n for n in comp if g.nodes[n].get("type") == "ip"]
            shared_hosts = [g.nodes[n].get("host", n) for n in comp if g.nodes[n].get("type") == "relay_host"]
            shared_domains = [
                n for n in comp
                if g.nodes[n].get("type") == "domain"
                and n.lower() not in ("targetcorp.com", "gmail.com", "outlook.com")
            ]
            urls = [g.nodes[n].get("url", n) for n in comp if g.nodes[n].get("type") == "url"]

            is_phishing = any(
                "phish" in e.lower() or "malicious" in e.lower() or "security" in e.lower() or "fraud" in e.lower()
                for e in emails_in_comp
            ) or bool(shared_domains or shared_ips)

            campaigns.append(
                {
                    "campaign_id": f"campaign_{idx + 1}",
                    "name": f"Campaign Cluster {idx + 1}",
                    "emails": emails_in_comp,
                    "email_count": len(emails_in_comp),
                    "total_nodes": len(comp),
                    "shared_ips": shared_ips,
                    "shared_hosts": shared_hosts,
                    "shared_domains": shared_domains,
                    "urls": urls,
                    "is_phishing": is_phishing,
                }
            )

        # Sort campaigns: multi-email campaigns first
        campaigns.sort(key=lambda c: (c["email_count"], len(c["shared_domains"])), reverse=True)
        return campaigns

    # ── Threat Intelligence Correlation ───────────────────────────────

    def _correlate_threat_intel(self, g: nx.DiGraph) -> tuple[list[dict], dict]:
        """Correlate all nodes in graph with known threat intelligence indicators."""
        matched_indicators = []
        actor_scores: dict[str, set] = {}

        blocklisted_domains_hit = []
        blocklisted_ips_hit = []

        for node_id, data in g.nodes(data=True):
            ntype = data.get("type")

            if ntype == "domain":
                domain_val = node_id.lower()
                if domain_val in THREAT_INTEL["malicious_domains"]:
                    blocklisted_domains_hit.append(domain_val)
                    matched_indicators.append({"type": "domain", "value": domain_val, "status": "malicious"})

                for actor in THREAT_INTEL["actors"]:
                    if domain_val in actor["known_domains"]:
                        actor_scores.setdefault(actor["id"], set()).add(domain_val)

            elif ntype == "ip":
                ip_val = node_id
                if ip_val in THREAT_INTEL["malicious_ips"]:
                    blocklisted_ips_hit.append(ip_val)
                    matched_indicators.append({"type": "ip", "value": ip_val, "status": "malicious"})

                for actor in THREAT_INTEL["actors"]:
                    if ip_val in actor["known_ips"]:
                        actor_scores.setdefault(actor["id"], set()).add(ip_val)

            elif ntype in ("sender", "contact_email"):
                email_val = node_id.lower()
                for actor in THREAT_INTEL["actors"]:
                    if email_val in actor["known_emails"]:
                        actor_scores.setdefault(actor["id"], set()).add(email_val)
                        matched_indicators.append({"type": "email", "value": email_val, "status": "malicious"})

        attributions = []
        for actor in THREAT_INTEL["actors"]:
            aid = actor["id"]
            matches = actor_scores.get(aid, set())
            if not matches:
                continue

            total_indicators = len(actor["known_domains"]) + len(actor["known_ips"]) + len(actor["known_emails"])
            confidence = int((len(matches) / max(total_indicators, 1)) * 100)
            confidence = max(confidence, 40 if len(matches) > 1 else 30)
            confidence = min(confidence, 100)

            attributions.append(
                {
                    "actor_id": aid,
                    "actor_name": actor["name"],
                    "actor_type": actor["type"],
                    "tactics": actor["tactics"],
                    "severity": actor["severity"],
                    "confidence": confidence,
                    "matched_indicators": list(matches),
                }
            )

        attributions.sort(key=lambda x: x["confidence"], reverse=True)

        indicators = {
            "blocklisted_domains": blocklisted_domains_hit,
            "blocklisted_ips": blocklisted_ips_hit,
            "total_malicious_nodes": len(matched_indicators),
        }

        return attributions, indicators

    # ── Helpers & Static PNG Renderer ──────────────────────────────────

    def render_graph_png(self, g: nx.Graph | nx.DiGraph, output_path: str = "attribution_graph.png") -> str:
        """Render a static PNG of the NetworkX graph using Matplotlib."""
        return render_graph_png(g, output_path)

    @staticmethod
    def _normalise_input_batch(
        email_results: list[Union[dict, tuple[dict, dict, dict]]],
    ) -> list[tuple[dict, dict, dict]]:
        """Normalize batch input into uniform (header_res, nlp_res, visual_res) tuples."""
        parsed: list[tuple[dict, dict, dict]] = []
        for item in email_results:
            if isinstance(item, tuple) and len(item) == 3:
                parsed.append(item)
            elif isinstance(item, dict):
                h = item.get("header") or item.get("header_result") or item
                n = item.get("nlp") or item.get("nlp_result") or item
                v = item.get("visual") or item.get("visual_result") or item
                parsed.append((h, n, v))
        return parsed

    @staticmethod
    def _extract_email_address(hdr: str) -> str | None:
        """Extract email address from From header string."""
        if not hdr:
            return None
        m = re.search(r"[\w.\-]+@[\w.\-]+", hdr)
        return m.group(0).lower() if m else None

    @staticmethod
    def _base_domain(domain: str) -> str:
        """Reduce host.sub.example.com -> example.com."""
        parts = domain.lower().rstrip(".").split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()

    @staticmethod
    def _is_ip_str(val: str) -> bool:
        """Check if string is IPv4 address."""
        return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", val))

    @staticmethod
    def _generate_summary(attributions: list[dict], indicators: dict, campaigns: list[dict]) -> str:
        """Generate summary text for graph and campaigns."""
        lines = []
        if campaigns:
            multi_camps = [c for c in campaigns if c["email_count"] > 1]
            if multi_camps:
                lines.append(f"Detected {len(multi_camps)} campaign cluster(s) spanning {sum(c['email_count'] for c in multi_camps)} emails.")
            else:
                lines.append(f"Analyzed {len(campaigns)} email(s) across individual components.")

        if attributions:
            top = attributions[0]
            lines.append(f"Attributed to {top['actor_name']} ({top['confidence']}% confidence).")
        elif indicators.get("total_malicious_nodes", 0) > 0:
            lines.append(f"Flagged {indicators['total_malicious_nodes']} threat intelligence IOC(s).")
        else:
            lines.append("No known threat-actor profiles matched.")

        return " ".join(lines)


def render_graph_png(g: nx.Graph | nx.DiGraph, output_path: str = "attribution_graph.png") -> str:
    """Standalone helper function to render a static PNG visualization of a NetworkX graph using matplotlib.

    Parameters
    ----------
    g : nx.Graph or nx.DiGraph
        The graph object to render.
    output_path : str
        Target file path to save the PNG image.

    Returns
    -------
    str
        Absolute path to the generated PNG file.
    """
    if not _HAS_MATPLOTLIB:
        raise RuntimeError("matplotlib is required to render graph PNGs. Install matplotlib first.")

    fig, ax = plt.subplots(figsize=(14, 10), dpi=150)
    ax.set_title("Sentinel-Mail Threat Attribution & Campaign Graph", fontsize=16, fontweight="bold", pad=20)

    # Node color mapping by type
    color_map = {
        "email": "#1f77b4",        # Blue
        "ip": "#ff7f0e",           # Orange
        "relay_host": "#2ca02c",    # Green
        "domain": "#d62728",       # Red
        "url": "#9467bd",          # Purple
        "actor": "#e377c2",        # Magenta/Pink
        "sender": "#8c564b",       # Brown
        "contact_email": "#bcbd22", # Olive
        "attachment": "#17becf",   # Cyan
        "financial": "#7f7f7f",    # Gray
        "location": "#393b79",     # Dark Navy
    }

    node_colors = []
    node_sizes = []
    labels = {}

    for node_id, data in g.nodes(data=True):
        ntype = data.get("type", "unknown")
        node_colors.append(color_map.get(ntype, "#7f7f7f"))

        if ntype == "actor":
            node_sizes.append(900)
        elif ntype == "email":
            node_sizes.append(700)
        elif ntype in ("domain", "ip"):
            node_sizes.append(500)
        else:
            node_sizes.append(350)

        # Label formatting
        lbl = data.get("label", str(node_id))
        if len(lbl) > 24:
            lbl = lbl[:21] + "..."
        labels[node_id] = lbl

    # Layout selection
    try:
        pos = nx.spring_layout(g, k=0.45, iterations=50, seed=42)
    except Exception:
        pos = nx.circular_layout(g)

    # Draw Edges
    nx.draw_networkx_edges(
        g,
        pos,
        ax=ax,
        edge_color="#cccccc",
        width=1.5,
        alpha=0.7,
        arrows=isinstance(g, nx.DiGraph),
        arrowsize=12,
    )

    # Draw Nodes
    nx.draw_networkx_nodes(
        g,
        pos,
        ax=ax,
        node_color=node_colors,
        node_size=node_sizes,
        alpha=0.9,
        edgecolors="#ffffff",
        linewidths=1.5,
    )

    # Draw Labels
    nx.draw_networkx_labels(
        g,
        pos,
        labels=labels,
        ax=ax,
        font_size=8,
        font_weight="bold",
        font_color="#2c3e50",
    )

    # Custom Legend
    legend_handles = []
    for ntype, color in color_map.items():
        if any(d.get("type") == ntype for _, d in g.nodes(data=True)):
            legend_handles.append(
                plt.Line2D([0], [0], marker="o", color="w", label=ntype.upper(), markerfacecolor=color, markersize=10)
            )

    if legend_handles:
        ax.legend(handles=legend_handles, loc="upper right", title="Entity Types", frameon=True)

    ax.axis("off")
    plt.tight_layout()

    out_file = Path(output_path).resolve()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_file, bbox_inches="tight")
    plt.close(fig)

    return str(out_file)
