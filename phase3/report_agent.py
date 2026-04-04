"""
report_agent.py — ReportAgent cho Phase 3
Sinh báo cáo Markdown hoàn chỉnh từ phase1_canonical.json + phase3_analysis.json.

Không dùng LLM, không dùng template engine — thuần Python f-strings.
Báo cáo là tổng hợp kết quả reconnaissance và phân tích bề mặt tấn công ban đầu.

Cấu trúc báo cáo:
  1. Thông tin mục tiêu
  2. Kết quả tổng hợp Phase 1
  3. Phân tích bề mặt tấn công
  4. Executive Summary
  5. Khuyến nghị bước tiếp theo
  6. Limitations

Không cần pip install thêm gì — chỉ dùng Python stdlib.
"""

import json
import os
from datetime import datetime, timezone

# ── WhatWeb filter: items không phải technology identifier ────────────────────
# (cookie flags, header names, session token names — không thuộc tech stack)
WHATWEB_NON_TECH_NAMES = {
    "httponly", "secure", "samesite", "path", "domain", "expires", "max-age",
    "jsessionid", "phpsessid", "sid", "session_id", "sessionid",
    "aspnet_sessionid", "aspsessionid", "asp.net_sessionid", "connect.sid",
    "viewstate", "__viewstate", "__eventvalidation",
    "x-frame-options", "x-content-type-options", "x-xss-protection",
    "content-security-policy", "referrer-policy", "permissions-policy",
    "strict-transport-security", "x-powered-by",
    "cookie", "set-cookie", "header", "response",
}

# ── Nhãn hiển thị risk / priority ────────────────────────────────────────────

RISK_LABEL = {
    "high":          "[HIGH]",
    "medium":        "[MEDIUM]",
    "low":           "[LOW]",
    "informational": "[INFO]",
}

PRIORITY_LABEL = {
    "high":   "High",
    "medium": "Medium",
    "low":    "Low",
    "none":   "-",
}


class ReportAgent:
    """
    Agent sinh báo cáo Markdown từ dữ liệu Phase 1 và Phase 3 Analysis.

    Báo cáo hoàn chỉnh, ngôn ngữ học thuật, không chứa exploit steps,
    không kết luận vulnerability confirmed.

    Chạy: report_agent.run(phase1_path, analysis_path, output_dir)
    
    Output hoàn toàn deterministic, rule-based, không dùng LLM.
    """

    def __init__(self):
        """Initialize ReportAgent."""
        # Capture report generation timestamp at init for consistency
        self._report_timestamp = datetime.now(timezone.utc)

    def run(self, phase1_path: str, analysis_path: str, output_dir: str) -> str:
        """
        Đọc dữ liệu, sinh báo cáo Markdown, ghi file.

        Args:
            phase1_path:   Đường dẫn đến phase1_canonical.json
            analysis_path: Đường dẫn đến phase3_analysis.json
            output_dir:    Thư mục để ghi output

        Returns:
            Đường dẫn đến file phase3_report.md đã tạo
        """
        # Reset timestamp at start of each run for consistency within this report
        self._report_timestamp = datetime.now(timezone.utc)
        
        with open(phase1_path, "r", encoding="utf-8") as f:
            p1 = json.load(f)
        with open(analysis_path, "r", encoding="utf-8") as f:
            analysis = json.load(f)

        sections = [
            self._section_header(p1, analysis),
            self._section_target_info(p1),
            self._section_phase1_summary(p1),
            self._section_attack_surface(analysis),
            self._section_executive_summary(p1, analysis),
            self._section_next_steps(analysis),
            self._section_limitations(),
        ]

        report = "\n\n---\n\n".join(sections)

        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "phase3_report.md")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report)

        print(f"  [ReportAgent] Report written: {output_path}")
        return output_path

    # =========================================================================
    # Section builders
    # =========================================================================

    def _section_header(self, p1: dict, analysis: dict) -> str:
        target = p1.get("target", "Unknown Target")
        meta = analysis.get("meta") or {}
        # Use consistent report timestamp for header
        date_str = self._report_timestamp.strftime("%Y-%m-%d")
        ver = meta.get("analyzer_version", "1.0")

        return (
            f"# Attack Surface Analysis Report\n\n"
            f"**Target:** `{target}`  \n"
            f"**Report Date:** {date_str}  \n"
            f"**Phase:** Phase 3 — Reconnaissance-Based Analysis  \n"
            f"**Analyzer Version:** {ver}\n\n"
            f"> **Disclaimer:** This report is based exclusively on passive and active\n"
            f"> reconnaissance data collected during Phase 1. All findings represent\n"
            f"> *initial attack surface indicators* only. No exploitation or vulnerability\n"
            f"> confirmation has been performed. All observations require further\n"
            f"> validation before drawing definitive security conclusions."
        )

    # ── Section 1: Target Information ────────────────────────────────────────

    def _section_target_info(self, p1: dict) -> str:
        target = p1.get("target", "N/A")
        ts = p1.get("timestamp", "N/A")
        passive = p1.get("passive_recon") or {}
        domain = passive.get("domain", "N/A")
        ips = passive.get("ip_addresses") or []
        whois = passive.get("whois") or {}
        summary = p1.get("summary") or {}
        limitations = summary.get("limitations") or []
        shodan = passive.get("shodan") or {}

        ip_str = ", ".join(f"`{ip}`" for ip in ips) if ips else "Not observed"
        ns_str = ", ".join(whois.get("name_servers") or []) or "Not observed"

        org_row = ""
        if shodan.get("org"):
            loc = f"{shodan.get('city', '')}, {shodan.get('country', '')}".strip(", ")
            org_row = f"\n| Organization (Shodan) | {shodan['org']} / {shodan.get('isp', 'N/A')} ({loc}) |"

        lim_block = ""
        if limitations:
            items = "\n".join(f"- {l}" for l in limitations)
            lim_block = f"\n\n**Data Collection Limitations Recorded:**\n{items}"
        else:
            lim_block = "\n\n**Data Collection Limitations Recorded:** None."

        return (
            f"## 1. Target Information\n\n"
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| Target URL | `{target}` |\n"
            f"| Domain | `{domain}` |\n"
            f"| IP Address(es) | {ip_str} |\n"
            f"| Collection Timestamp | {ts} |\n"
            f"| Registrar | {whois.get('registrar', 'N/A')} |\n"
            f"| Domain Created | {whois.get('creation_date', 'N/A')} |\n"
            f"| Domain Expires | {whois.get('expiration_date', 'N/A')} |\n"
            f"| Registered Country | {whois.get('country', 'N/A')} |\n"
            f"| Name Servers (WHOIS) | {ns_str} |{org_row}\n\n"
            f"**Scope:** Reconnaissance-only analysis of the target domain and "
            f"associated observed infrastructure. No active exploitation performed."
            f"{lim_block}"
        )

    # ── Section 2: Phase 1 Summary ────────────────────────────────────────────

    def _section_phase1_summary(self, p1: dict) -> str:
        passive = p1.get("passive_recon") or {}
        active = p1.get("active_recon") or {}
        summary = p1.get("summary") or {}

        parts = [
            "## 2. Phase 1 Reconnaissance Summary",
            self._sub_dns(passive),
            self._sub_subdomains(passive),
            self._sub_ports(active, passive),
            self._sub_http_headers(active),
            self._sub_ssl(passive),
            self._sub_technology(passive),
            self._sub_http_methods(active),
            self._sub_crawl(active, passive, summary),
            self._sub_cookies(active),
            self._sub_waf(active),
            self._sub_tool_sources(active, summary),
        ]
        return "\n\n".join(parts)

    def _sub_dns(self, passive: dict) -> str:
        dns = passive.get("dns_records") or {}
        ips = passive.get("ip_addresses") or []

        def fmt(lst):
            return ", ".join(lst) if lst else "Not observed"

        return (
            f"### 2.1 DNS / IP Information\n\n"
            f"| Record Type | Value |\n"
            f"|------------|-------|\n"
            f"| IP Address(es) | {fmt(ips)} |\n"
            f"| A | {fmt(dns.get('A', []))} |\n"
            f"| AAAA | {fmt(dns.get('AAAA', []))} |\n"
            f"| MX | {fmt(dns.get('MX', []))} |\n"
            f"| NS | {fmt(dns.get('NS', []))} |\n"
            f"| TXT | {fmt(dns.get('TXT', []))} |\n"
            f"| CNAME | {fmt(dns.get('CNAME', []))} |"
        )

    def _sub_subdomains(self, passive: dict) -> str:
        subdomains = passive.get("subdomains") or []

        if not subdomains:
            return "### 2.2 Subdomain Enumeration\n\nNo subdomains observed in Phase 1 data."

        rows = []
        for s in subdomains:
            if isinstance(s, dict):
                rows.append(
                    f"| `{s.get('subdomain', '')}` "
                    f"| {s.get('ip', 'N/A') or 'N/A'} "
                    f"| {s.get('source', 'N/A')} |"
                )
            elif isinstance(s, str):
                rows.append(f"| `{s}` | N/A | N/A |")

        table = "\n".join(rows)
        return (
            f"### 2.2 Subdomain Enumeration\n\n"
            f"Total observed: **{len(subdomains)}**\n\n"
            f"| Subdomain | IP | Discovery Source |\n"
            f"|-----------|-----|------------------|\n"
            f"{table}"
        )

    def _sub_ports(self, active: dict, passive: dict) -> str:
        """
        Hiển thị open ports với deduplication rõ ràng.
        Merge Nmap + Shodan theo port number, ghi rõ source cho từng port.
        Dùng một bảng duy nhất, không tách hai bảng gây nhầm lẫn số liệu.
        """
        nmap_ports = active.get("ports") or []
        shodan_ports = (passive.get("shodan") or {}).get("ports") or []

        if not nmap_ports and not shodan_ports:
            return "### 2.3 Open Ports / Services\n\nNo open port data available in Phase 1 data."

        # Merge với source tracking — dedup theo port number
        merged: dict = {}
        for p in nmap_ports:
            port = p["port"]
            merged[port] = {
                "service": p.get("service", "unknown"),
                "version": p.get("version", "") or "",
                "sources": {p.get("source", "nmap")},
            }
        for sp in shodan_ports:
            port = sp["port"]
            if port in merged:
                merged[port]["sources"].add("shodan")
            else:
                merged[port] = {
                    "service": sp.get("service", "unknown"),
                    "version": sp.get("version", "") or "",
                    "sources": {"shodan"},
                }

        lines = [
            "### 2.3 Open Ports / Services",
            "",
            f"Total observed (Nmap: {len(nmap_ports)}, Shodan: {len(shodan_ports)}, "
            f"deduplicated: **{len(merged)}**)",
            "",
            "| Port | Service | Version | Sources |",
            "|------|---------|---------|---------|",
        ]
        for port in sorted(merged.keys()):
            info = merged[port]
            sources_str = ", ".join(sorted(info["sources"]))
            lines.append(
                f"| {port} | {info['service']} "
                f"| {info['version'] or 'N/A'} "
                f"| {sources_str} |"
            )
        return "\n".join(lines)

    def _sub_http_headers(self, active: dict) -> str:
        headers = active.get("headers") or {}
        avail = active.get("availability") or {}
        redirects = avail.get("redirects") or []

        lines = [
            "### 2.4 HTTP Response Headers",
            "",
            f"- **HTTP Available:** {avail.get('http', 'Not observed')}",
            f"- **HTTPS Available:** {avail.get('https', 'Not observed')}",
            f"- **HTTP Status Code:** {avail.get('status_code', 'N/A')}",
            f"- **Redirects:** {' -> '.join(redirects) if redirects else 'None'}",
        ]

        if headers:
            lines += [
                "",
                "**Observed response headers:**",
                "",
                "| Header | Value |",
                "|--------|-------|",
            ]
            for k, v in headers.items():
                v_str = str(v)
                if len(v_str) > 90:
                    v_str = v_str[:87] + "..."
                lines.append(f"| `{k}` | `{v_str}` |")
        else:
            lines.append("\nHTTP response headers not available in Phase 1 data.")

        return "\n".join(lines)

    def _sub_ssl(self, passive: dict) -> str:
        ssl = passive.get("ssl") or {}
        if not ssl:
            return "### 2.5 SSL/TLS Certificate\n\nSSL/TLS information not available in Phase 1 data."

        days = ssl.get("days_remaining")
        expiry_note = ""
        if days is not None:
            if days < 30:
                expiry_note = f" -- CRITICAL: {days} days remaining"
            elif days < 90:
                expiry_note = f" -- Warning: {days} days remaining"
            else:
                expiry_note = f" -- Valid ({days} days remaining)"

        san_str = ", ".join(ssl.get("san") or []) or "Not observed"

        return (
            f"### 2.5 SSL/TLS Certificate\n\n"
            f"| Field | Value |\n"
            f"|-------|-------|\n"
            f"| Subject | {ssl.get('subject', 'N/A')} |\n"
            f"| Issuer | {ssl.get('issuer', 'N/A')} |\n"
            f"| Protocol | {ssl.get('protocol', 'N/A')} |\n"
            f"| Valid From | {ssl.get('valid_from', 'N/A')} |\n"
            f"| Expiry | {ssl.get('expiry', 'N/A')}{expiry_note} |\n"
            f"| Subject Alternative Names | {san_str} |"
        )

    def _sub_technology(self, passive: dict) -> str:
        tech = passive.get("technology") or {}
        server = tech.get("server", "") or "Not observed"
        cms = tech.get("cms", "") or "Not observed"
        frameworks = tech.get("frameworks") or []
        libraries = tech.get("libraries") or []
        whatweb = tech.get("whatweb") or []
        sec_headers = tech.get("security_headers") or {}

        lines = [
            "### 2.6 Technology Fingerprint",
            "",
            f"- **Server:** {server}",
            f"- **CMS:** {cms}",
            f"- **Frameworks:** {', '.join(frameworks) if frameworks else 'Not observed'}",
            f"- **Libraries:** {', '.join(libraries) if libraries else 'Not observed'}",
        ]

        # Filter WhatWeb: chỉ hiển thị actual technology identifiers
        # Loại bỏ cookie attributes (HttpOnly, Secure), session names (JSESSIONID), etc.
        tech_whatweb = [
            ww for ww in whatweb
            if ww.get("name", "").lower() not in WHATWEB_NON_TECH_NAMES
            and (ww.get("version") or "").lower() not in WHATWEB_NON_TECH_NAMES
        ]

        if tech_whatweb:
            lines += [
                "",
                "**WhatWeb Results (technology identifiers only):**",
                "",
                "| Component | Version |",
                "|-----------|---------|",
            ]
            for ww in tech_whatweb:
                lines.append(f"| {ww.get('name', 'N/A')} | {ww.get('version', 'N/A') or 'N/A'} |")

        if sec_headers:
            lines += [
                "",
                "**Security Headers Status (passive recon):**",
                "",
                "| Header | Status |",
                "|--------|--------|",
            ]
            for h, v in sec_headers.items():
                status = f"`{v}`" if v else "Not observed"
                lines.append(f"| {h} | {status} |")

        return "\n".join(lines)

    def _sub_http_methods(self, active: dict) -> str:
        methods = active.get("http_methods") or []
        methods_str = (
            f"`{', '.join(methods)}`" if methods
            else "Not available in Phase 1 data."
        )
        return f"### 2.7 HTTP Methods\n\nObserved allowed HTTP methods: {methods_str}"

    def _sub_crawl(self, active: dict, passive: dict, summary: dict) -> str:
        crawl = active.get("crawl") or {}
        urls = crawl.get("urls") or []
        forms = crawl.get("forms") or []
        params = crawl.get("params") or []
        notable = crawl.get("notable_endpoints") or []
        js_eps = crawl.get("js_endpoints") or []
        hidden = active.get("hidden_endpoints") or []
        wayback = (passive.get("wayback") or {}).get("urls") or []

        lines = [
            "### 2.8 URLs / Endpoints / Forms / Parameters",
            "",
            "**Asset Summary:**",
            "",
            "| Asset Type | Count |",
            "|------------|-------|",
            f"| Crawled URLs | {len(urls)} |",
            f"| HTML Forms | {len(forms)} |",
            f"| URL / Form Parameters | {len(params)} |",
            f"| Notable Endpoints | {len(notable)} |",
            f"| JavaScript Endpoints | {len(js_eps)} |",
            f"| Hidden Endpoints (ffuf) | {len(hidden)} |",
            f"| Wayback Machine URLs | {len(wayback)} |",
        ]

        # Crawled URLs
        if urls:
            lines += ["", "**Crawled URLs:**", ""]
            for url in urls:
                lines.append(f"- `{url}`")

        # Notable endpoints
        if notable:
            lines += [
                "",
                "**Notable Endpoints:**",
                "",
                "| URL | Category | Method | Source |",
                "|-----|----------|--------|--------|",
            ]
            for ep in notable:
                lines.append(
                    f"| `{ep.get('url', '')}` | {ep.get('category', 'N/A')} "
                    f"| {ep.get('method', 'N/A')} | {ep.get('source', 'N/A')} |"
                )

        # Hidden endpoints
        if hidden:
            lines += [
                "",
                "**Hidden Endpoints (directory fuzzing):**",
                "",
                "| Path | HTTP Status | Source |",
                "|------|-------------|--------|",
            ]
            for ep in hidden:
                url = ep.get("url") or ep.get("path") or ""
                status = ep.get("status") or ep.get("status_code") or "N/A"
                lines.append(f"| `{url}` | {status} | {ep.get('source', 'N/A')} |")

        # HTML Forms
        if forms:
            lines += [
                "",
                "**HTML Forms Observed:**",
                "",
                "| Page | Form Action | Method | Inputs |",
                "|------|-------------|--------|--------|",
            ]
            for form in forms:
                page = form.get("page", "N/A")
                action = form.get("action", "N/A")
                method = form.get("method", "N/A")
                inputs = form.get("inputs") or []
                inputs_str = ", ".join(str(i) for i in inputs) if inputs else "-"
                lines.append(
                    f"| `{page}` | `{action}` | {method} | {inputs_str} |"
                )

        # URL parameters
        if params:
            lines += [
                "",
                "**URL / Form Parameters Observed:**",
                "",
                "| Parameter | Source | Method |",
                "|-----------|--------|--------|",
            ]
            for p in params:
                if isinstance(p, dict):
                    lines.append(
                        f"| `{p.get('name', '')}` | {p.get('source', 'N/A')} "
                        f"| {p.get('method', 'N/A')} |"
                    )
                else:
                    lines.append(f"| `{p}` | N/A | N/A |")

        # JS endpoints
        if js_eps:
            lines += ["", "**JavaScript Endpoints:**", ""]
            for ep in js_eps:
                lines.append(f"- `{ep}`")

        # Wayback (chỉ đếm, không liệt kê hết)
        if wayback:
            lines.append(
                f"\n**Wayback Machine:** {len(wayback)} historical URL(s) observed. "
                f"Refer to `phase1_canonical.json` for full list."
            )

        return "\n".join(lines)

    def _sub_cookies(self, active: dict) -> str:
        cookies = active.get("cookies_analysis") or []
        if not cookies:
            return (
                "### 2.9 Cookie Analysis\n\n"
                "Cookie analysis data not available in Phase 1 data."
            )

        rows = []
        for c in cookies:
            name = c.get("name", "unknown")
            flags = c.get("flags") or {}
            secure = c.get("secure") if c.get("secure") is not None else flags.get("Secure")
            httponly = c.get("httponly") if c.get("httponly") is not None else flags.get("HttpOnly")
            samesite = c.get("samesite") if c.get("samesite") is not None else flags.get("SameSite")
            rows.append(
                f"| `{name}` | {'Yes' if secure else 'No'} "
                f"| {'Yes' if httponly else 'No'} "
                f"| {samesite if samesite else 'Not set'} |"
            )

        table = "\n".join(rows)
        return (
            f"### 2.9 Cookie Analysis\n\n"
            f"| Cookie Name | Secure | HttpOnly | SameSite |\n"
            f"|-------------|--------|----------|----------|\n"
            f"{table}"
        )

    def _sub_waf(self, active: dict) -> str:
        waf = active.get("waf") or {}
        detected = waf.get("detected", False)
        name = waf.get("name", "")
        source = waf.get("source", "N/A")

        if detected:
            detail = f"**WAF Detected:** Yes - {name or 'unknown vendor'} (source: {source})"
        else:
            detail = (
                f"**WAF Detected:** Not detected (source: {source})\n\n"
                f"> Note: WAF absence is an initial indicator only. Requires further validation."
            )

        return f"### 2.10 WAF Detection\n\n{detail}"

    def _sub_tool_sources(self, active: dict, summary: dict) -> str:
        """
        Hiển thị nguồn công cụ theo schema thực tế.
        Ưu tiên: active_recon.tool_sources. Fallback: các *_source trong summary.
        """
        sources = active.get("tool_sources") or {}
        if not sources:
            fallback = {}
            for key in ("nmap_source", "ffuf_source", "whatweb_source"):
                if summary.get(key):
                    fallback[key] = summary.get(key)
            sources = fallback

        if not sources:
            return "### 2.11 Tool Sources\n\nTool source metadata not available in Phase 1 data."

        lines = [
            "### 2.11 Tool Sources",
            "",
            "| Component | Source |",
            "|-----------|--------|",
        ]
        for k, v in sorted(sources.items()):
            lines.append(f"| `{k}` | `{v}` |")
        return "\n".join(lines)

    # ── Section 3: Attack Surface Analysis ───────────────────────────────────

    def _section_attack_surface(self, analysis: dict) -> str:
        findings = analysis.get("findings") or []
        surface = analysis.get("attack_surface_summary") or {}

        ssl_valid = surface.get("ssl_valid")
        ssl_valid_str = "Yes" if ssl_valid is True else ("No" if ssl_valid is False else "Not observed")

        lines = [
            "## 3. Attack Surface Analysis",
            "",
            "> All items in this section are **initial attack surface indicators** "
            "derived from reconnaissance data only.",
            "> None of the following constitutes a confirmed vulnerability. "
            "All require further validation.",
            "",
            "### 3.1 Attack Surface Metrics",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Open Ports | {surface.get('total_open_ports', 'N/A')} |",
            f"| Subdomains | {surface.get('total_subdomains', 'N/A')} |",
            f"| Crawled URLs | {surface.get('total_crawled_urls', 'N/A')} |",
            f"| HTML Forms | {surface.get('total_forms', 'N/A')} |",
            f"| URL Parameters | {surface.get('total_params', 'N/A')} |",
            f"| Notable Endpoints | {surface.get('total_notable_endpoints', 'N/A')} |",
            f"| Hidden Endpoints | {surface.get('total_hidden_endpoints', 'N/A')} |",
            f"| Wayback URLs | {surface.get('total_wayback_urls', 'N/A')} |",
            f"| WAF Detected | {'Yes' if surface.get('waf_detected') else 'No'} |",
            f"| SSL Valid | {ssl_valid_str} |",
        ]

        missing_hdrs = surface.get("security_headers_missing") or []
        if missing_hdrs:
            lines.append(f"| Missing Security Headers | {', '.join(missing_hdrs)} |")

        # 3.2 Findings by category
        lines += ["", "### 3.2 Detailed Findings", ""]

        # Group findings by category
        by_cat: dict = {}
        for f in findings:
            cat = f.get("category", "other")
            by_cat.setdefault(cat, []).append(f)

        if not by_cat:
            lines.append("No findings generated.")
        else:
            for cat, cat_findings in sorted(by_cat.items()):
                cat_title = cat.replace("_", " ").title()
                lines.append(f"#### {cat_title}\n")
                for f in cat_findings:
                    fid = f.get("id", "?")
                    risk = RISK_LABEL.get(f.get("risk_indicator", "informational"), "[INFO]")
                    priority = PRIORITY_LABEL.get(f.get("follow_up_priority", "none"), "-")
                    obs = f.get("observation", "")
                    rec = f.get("recommended_next_check", "")
                    lines += [
                        f"**{fid}** {risk} -- Follow-up Priority: {priority}\n",
                        f"- **Observation:** {obs}",
                        f"- **Recommended Next Check:** {rec}\n",
                    ]

        return "\n".join(lines)

    # ── Section 4: Executive Summary ─────────────────────────────────────────

    def _build_notable_items(self, findings: list, surface: dict) -> list:
        """
        Xây dựng danh sách các điểm đáng chú ý DỰA TRÊN findings thực tế.
        Chỉ đề cập đến những gì thực sự xuất hiện trong analysis output.
        Không hardcode bất kỳ assertion nào.
        """
        notable = []
        # Tập hợp categories có risk medium/high
        med_high_cats = {
            f.get("category") for f in findings
            if f.get("risk_indicator") in ("high", "medium")
        }

        # Chỉ mention authentication nếu có finding endpoint "authentication" trong observation
        auth_ep_found = any(
            "authentication" in f.get("observation", "").lower()
            for f in findings
            if f.get("category") == "sensitive_endpoints"
        )
        if auth_ep_found:
            notable.append("authentication-related endpoints")

        # Chỉ mention non-standard ports nếu có finding riêng về non-standard port
        nonstandard_port = any(
            "Non-standard" in f.get("observation", "")
            for f in findings
            if f.get("category") == "port_exposure"
        )
        if nonstandard_port:
            notable.append("services on non-standard ports")

        # Chỉ mention missing headers nếu có finding về security_headers với risk medium+
        missing_headers = surface.get("security_headers_missing") or []
        if missing_headers and "security_headers" in med_high_cats:
            notable.append(f"{len(missing_headers)} absent HTTP security header(s)")

        # Chỉ mention SSL nếu có finding ssl_tls với risk medium/high
        ssl_days = surface.get("ssl_days_remaining")
        if ssl_days is not None and ssl_days < 90 and "ssl_tls" in med_high_cats:
            notable.append(f"SSL/TLS certificate with {ssl_days} day(s) remaining until expiry")

        # Chỉ mention WAF absence nếu có finding waf_detection
        waf_finding_exists = any(f.get("category") == "waf_detection" for f in findings)
        if waf_finding_exists and not surface.get("waf_detected"):
            notable.append("no WAF coverage confirmed during reconnaissance")

        # Chỉ mention suspicious subdomains nếu có finding medium+ về subdomains
        if "subdomain_exposure" in med_high_cats:
            notable.append("subdomains with notable naming patterns")

        # Chỉ mention wayback nếu có finding wayback_disclosure
        if "wayback_disclosure" in med_high_cats:
            notable.append("historical URLs with potentially sensitive file types")

        return notable

    def _section_executive_summary(self, p1: dict, analysis: dict) -> str:
        """
        Executive Summary được sinh HOÀN TOÀN từ findings và metrics thực tế.
        Không hardcode bất kỳ assertion nào về attack surface components.
        """
        surface = analysis.get("attack_surface_summary") or {}
        findings = analysis.get("findings") or []
        target = p1.get("target", "N/A")
        ts = p1.get("timestamp", "")
        date_str = ts[:10] if ts and len(ts) >= 10 else ts

        # Đếm findings theo risk level
        counts = {"high": 0, "medium": 0, "low": 0, "informational": 0}
        for f in findings:
            r = f.get("risk_indicator", "informational")
            counts[r] = counts.get(r, 0) + 1

        # SSL alert — chỉ nếu có finding ssl_tls với risk medium/high
        ssl_note = ""
        ssl_days = surface.get("ssl_days_remaining")
        ssl_high_finding = any(
            f.get("category") == "ssl_tls"
            and f.get("risk_indicator") in ("high", "medium")
            for f in findings
        )
        if ssl_days is not None and ssl_high_finding:
            level = "CRITICAL" if ssl_days < 30 else "Warning"
            ssl_note = (
                f"\n> **Certificate Expiry ({level}):** SSL/TLS certificate observed "
                f"with only **{ssl_days} day(s)** remaining until expiry "
                f"(source: passive_recon.ssl.days_remaining)."
            )

        # Xây dựng danh sách điểm đáng chú ý từ findings thực tế
        notable_items = self._build_notable_items(findings, surface)

        # Câu kết luận — chỉ mention những gì thực sự có trong findings
        if notable_items:
            if len(notable_items) == 1:
                conclusion_str = notable_items[0]
            elif len(notable_items) == 2:
                conclusion_str = f"{notable_items[0]} and {notable_items[1]}"
            else:
                conclusion_str = (
                    ", ".join(notable_items[:-1]) + f", and {notable_items[-1]}"
                )
            conclusion = (
                f"Based on the analysis of collected reconnaissance data, the following "
                f"areas were identified as initial attack surface indicators: "
                f"{conclusion_str}. "
                f"All findings are *observed configuration indicators* only and require "
                f"further validation in an authorized testing environment."
            )
        else:
            conclusion = (
                "The reconnaissance data provides an initial view of the target's attack surface. "
                "No high-risk indicators were identified from available Phase 1 data. "
                "All findings require further validation in an authorized testing environment."
            )

        # Port note - mention merged count nếu sources khác nhau
        port_note_str = surface.get("total_open_ports_note", "")
        port_note = f" ({port_note_str})" if port_note_str else ""

        return (
            f"## 4. Executive Summary\n\n"
            f"**Target:** `{target}` | **Date:** {date_str}\n\n"
            f"| Category | Count | Risk Distribution | Count |\n"
            f"|----------|-------|--------------------|-------|\n"
            f"| Subdomains | {surface.get('total_subdomains', 0)} | High | {counts['high']} |\n"
            f"| Open Ports{port_note} | {surface.get('total_open_ports', 0)} | Medium | {counts['medium']} |\n"
            f"| Crawled URLs | {surface.get('total_crawled_urls', 0)} | Low | {counts['low']} |\n"
            f"| Forms | {surface.get('total_forms', 0)} | Informational | {counts['informational']} |\n"
            f"| Hidden Endpoints | {surface.get('total_hidden_endpoints', 0)} | | |\n"
            f"{ssl_note}\n\n"
            f"{conclusion}"
        )

    # ── Section 5: Recommended Next Steps ────────────────────────────────────

    def _section_next_steps(self, analysis: dict) -> str:
        findings = analysis.get("findings") or []

        high_pri = [f for f in findings if f.get("follow_up_priority") == "high"]
        med_pri = [f for f in findings if f.get("follow_up_priority") == "medium"]

        lines = [
            "## 5. Recommended Next Steps",
            "",
            "> All actions require explicit authorization.",
            "",
        ]

        if high_pri:
            lines.append("### 5.1 High Priority\n")
            for f in high_pri[:5]:  # Limit to top 5
                cat = f.get("category", "").replace("_", " ").title()
                lines.append(f"- **{cat}:** {f.get('recommended_next_check', '')}")
            if len(high_pri) > 5:
                lines.append(f"\n*+ {len(high_pri) - 5} additional high-priority items*\n")
        else:
            lines.append("### 5.1 High Priority\n")
            lines.append("- No high-priority items from current data.\n")

        if med_pri:
            lines.append("\n### 5.2 Medium Priority\n")
            for f in med_pri[:5]:  # Limit to top 5
                cat = f.get("category", "").replace("_", " ").title()
                lines.append(f"- **{cat}:** {f.get('recommended_next_check', '')}")
            if len(med_pri) > 5:
                lines.append(f"\n*+ {len(med_pri) - 5} additional medium-priority items*")
        else:
            lines.append("\n### 5.2 Medium Priority\n")
            lines.append("- No medium-priority items from current data.")

        # General checklist - simplified and shorter
        lines += [
            "",
            "---",
            "",
            "*Standard testing areas for subsequent phases: authentication endpoints, ",
            "input parameters, security headers, SSL/TLS configuration, and access controls.*",
        ]

        return "\n".join(lines)

    # ── Section 6: Limitations ────────────────────────────────────────────────

    def _section_limitations(self) -> str:
        # Use the consistent timestamp captured at report generation start
        report_time = self._report_timestamp.strftime("%Y-%m-%d %H:%M UTC")
        return (
            f"## 6. Limitations\n\n"
            f"This report is subject to the following limitations:\n\n"
            f"1. **Reconnaissance-only scope:** All findings are based on passive and active\n"
            f"   reconnaissance data collected in Phase 1. No active exploitation,\n"
            f"   authenticated testing, or vulnerability scanning has been performed.\n\n"
            f"2. **No vulnerability confirmation:** Observations represent *observed\n"
            f"   configuration* and *initial attack surface indicators* only. The presence\n"
            f"   of a configuration item does not confirm the existence of an exploitable\n"
            f"   vulnerability.\n\n"
            f"3. **Data completeness:** Some tools may have returned partial or no data due\n"
            f"   to network restrictions, tool availability, or target configuration.\n"
            f"   Where data is unavailable, the report notes `Not available in Phase 1 data`\n"
            f"   or `Not observed`.\n\n"
            f"4. **Time-bound data:** Reconnaissance data reflects the state of the target\n"
            f"   at the time of Phase 1 collection. Infrastructure and configuration changes\n"
            f"   may have occurred since then.\n\n"
            f"5. **Authorization boundary:** This analysis was conducted within the scope of\n"
            f"   an authorized academic exercise. No unauthorized access was attempted.\n\n"
            f"6. **No exploit steps:** This report contains no exploitation guidance. All\n"
            f"   recommended next steps require explicit authorization prior to execution.\n\n"
            f"---\n"
            f"*Report generated by Phase 3 Analysis System v1.0 -- {report_time}*  \n"
            f"*For academic use only.*"
        )
