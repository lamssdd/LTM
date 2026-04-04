"""
analysis_agent.py — AnalysisAgent cho Phase 3
Phân tích bề mặt tấn công dựa hoàn toàn trên dữ liệu phase1_canonical.json.

Không dùng LLM, không dùng RAG, không dùng thư viện ngoài.
Chỉ sinh: observation, risk_indicator, follow_up_priority, recommended_next_check.

Ràng buộc:
  - Không kết luận "vulnerability confirmed"
  - Không viết exploit steps
  - Dùng ngôn ngữ thận trọng: "observed", "potential", "requires further validation"
  - Không classify endpoint dựa trên domain name — chỉ dùng path segments
  - Không sinh duplicate findings cho cùng một URL

Không cần pip install thêm gì — chỉ dùng Python stdlib.
"""

import json
import os
from datetime import datetime, timezone
from urllib.parse import urlparse

# ── Hằng số cấu hình ─────────────────────────────────────────────────────────

ANALYZER_VERSION = "1.0"

# Security headers quan trọng cần kiểm tra
REQUIRED_SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

# Port không phải tiêu chuẩn HTTP/HTTPS
NON_STANDARD_HTTP_PORTS = {8080, 8443, 8000, 8888, 9000, 3000, 9090, 4443}

# HTTP methods tiềm ẩn rủi ro
RISKY_HTTP_METHODS = {"PUT", "DELETE", "TRACE", "PATCH", "CONNECT"}

# ── Endpoint classification ───────────────────────────────────────────────────
#
# QUAN TRỌNG: Các pattern này chỉ được match với PATH SEGMENTS của URL,
# không được match với full URL (tránh nhầm lẫn domain name với path).
#
# Format: (pattern, canonical_category)
# Matching logic: segment_base == pattern  (exact, case-insensitive)
# Trong đó segment_base = path segment sau khi strip file extension.
#
# Không dùng các pattern quá rộng như: "test", "app", "site", "www"
# vì chúng có thể match domain name hoặc path không liên quan.

SENSITIVE_PATH_SEGMENTS = [
    # Authentication
    ("login",         "authentication"),
    ("signin",        "authentication"),
    ("dologin",       "authentication"),
    ("logout",        "authentication"),
    ("logon",         "authentication"),
    ("auth",          "authentication"),
    ("doLogin",       "authentication"),  # camelCase variant

    # Administrative
    ("admin",         "administrative"),
    ("administrator", "administrative"),
    ("management",    "administrative"),
    ("console",       "administrative"),
    ("dashboard",     "administrative"),
    ("panel",         "administrative"),
    ("manager",       "administrative"),

    # File upload
    ("upload",        "file_upload"),
    ("fileupload",    "file_upload"),

    # API docs / exploration
    ("swagger",       "api_docs"),
    ("redoc",         "api_docs"),
    ("openapi",       "api_docs"),
    ("api-docs",      "api_docs"),

    # Web services
    ("ws",            "web_service"),     # /ws.asmx → segment base "ws"
    ("wsdl",          "web_service"),
    ("webservice",    "web_service"),
    ("service",       "web_service"),

    # API endpoints
    ("api",           "api_endpoint"),

    # Debug / diagnostic
    ("phpinfo",       "debug_info"),
    ("debug",         "debug_info"),
    ("trace",         "debug_info"),
    ("diagnostics",   "debug_info"),

    # Backup / sensitive files
    ("backup",        "backup_file"),
    ("bak",           "backup_file"),
    ("old",           "backup_file"),

    # Configuration
    ("config",        "configuration"),
    ("settings",      "configuration"),
    ("configuration", "configuration"),

    # Financial operations (banking context)
    ("transfer",      "financial"),
    ("transaction",   "financial"),
    ("payment",       "financial"),
    ("bank",          "financial"),
    ("account",       "financial"),

    # Search
    ("search",        "search"),

    # Feedback / contact (informational)
    ("feedback",      "feedback"),
]

# Map để normalize category từ Phase 1 notable_endpoints sang canonical
# VD: Phase 1 có category="login" → normalize thành "authentication"
CATEGORY_CANONICAL = {
    "login":          "authentication",
    "signin":         "authentication",
    "dologin":        "authentication",
    "logout":         "authentication",
    "logon":          "authentication",
    "auth":           "authentication",
    "admin":          "administrative",
    "admin_panel":    "administrative",
    "management":     "administrative",
    "console":        "administrative",
    "dashboard":      "administrative",
    "panel":          "administrative",
    "upload":         "file_upload",
    "file_upload":    "file_upload",
    "swagger":        "api_docs",
    "api_docs":       "api_docs",
    "api":            "api_endpoint",
    "api_endpoint":   "api_endpoint",
    "web_service":    "web_service",
    "debug_info":     "debug_info",
    "backup_file":    "backup_file",
    "configuration":  "configuration",
    "financial":      "financial",
    "search":         "search",
    "feedback":       "feedback",
    "notable":        "other_notable",
}

# WhatWeb entries mà KHÔNG phải technology identifier
# (cookie attributes, header attributes, session token names, ...)
WHATWEB_NON_TECH_NAMES = {
    # Cookie flags
    "httponly", "secure", "samesite", "path", "domain", "expires", "max-age",
    # Session cookie names phổ biến
    "jsessionid", "phpsessid", "sid", "session_id", "sessionid",
    "aspnet_sessionid", "aspsessionid", "asp.net_sessionid", "connect.sid",
    "viewstate", "__viewstate", "__eventvalidation",
    # HTTP header names (không phải tech stack)
    "x-frame-options", "x-content-type-options", "x-xss-protection",
    "content-security-policy", "referrer-policy", "permissions-policy",
    "strict-transport-security", "x-powered-by",
    # Generic non-tech labels
    "cookie", "set-cookie", "header", "response",
}

# File extensions nhạy cảm trong Wayback URLs
SENSITIVE_WAYBACK_EXTENSIONS = [
    ".cs", ".java", ".bak", ".xls", ".xlsx",
    ".sql", ".conf", ".xml", ".log",
    ".env", ".key", ".pem", ".zip", ".tar",
]

# Tiền tố subdomain đáng chú ý
SUSPICIOUS_SUBDOMAIN_PREFIXES = {
    "ftp", "admin", "evil", "localhost", "test",
    "dev", "staging", "internal", "vpn", "mail",
    "smtp", "old", "backup", "mgmt", "manage",
}

# Ngưỡng cảnh báo SSL
SSL_CRITICAL_DAYS = 30
SSL_WARN_DAYS = 90

# Tên param gợi ý path traversal / SSRF / redirect
SUSPICIOUS_PARAM_KEYWORDS = {
    "file", "path", "url", "redirect", "content",
    "page", "include", "src", "dest", "load", "next",
    "return", "target", "ref", "link",
}

# Categories có risk cao hơn
HIGH_RISK_CATEGORIES = {
    "administrative", "authentication", "file_upload",
    "api_docs", "backup_file", "debug_info", "web_service", "financial",
}


class AnalysisAgent:
    """
    Agent phân tích bề mặt tấn công từ phase1_canonical.json.

    Mỗi method _check_*() thực hiện một nhóm rule phân tích độc lập.
    Chạy: analysis_agent.run(input_path, output_dir)
    """

    def __init__(self):
        self.findings: list = []
        self._counter: int = 0

    # ── Core helpers ──────────────────────────────────────────────────────────

    def _finding(self, category, observation, risk_indicator,
                 follow_up_priority, recommended_next_check) -> dict:
        """Tạo một finding entry chuẩn hóa."""
        self._counter += 1
        return {
            "id": f"F{self._counter:03d}",
            "category": category,
            "observation": observation,
            "risk_indicator": risk_indicator,       # informational | low | medium | high
            "follow_up_priority": follow_up_priority,  # none | low | medium | high
            "recommended_next_check": recommended_next_check,
        }

    def _get_cookie_flag(self, cookie: dict, flag_name: str):
        """
        Đọc cookie flag, hỗ trợ cả hai schema:
          - Phẳng:  {"secure": false, "httponly": true, "samesite": null}
          - Lồng:   {"flags": {"Secure": false, "HttpOnly": true, ...}}
        """
        flags_dict = cookie.get("flags") or {}

        # Schema phẳng (lowercase) có ưu tiên cao
        val = cookie.get(flag_name.lower())
        if val is not None:
            return val

        # Schema lồng: tìm key theo kiểu case-insensitive
        for k, v in flags_dict.items():
            if str(k).lower() == flag_name.lower():
                return v
        return None

    # ── Endpoint classification helpers ──────────────────────────────────────

    def _get_path_segments(self, url: str) -> list:
        """
        Trích xuất danh sách path segments từ URL.
        Chỉ dùng phần path, KHÔNG dùng domain hay query string.
        VD: "http://testfire.net/bank/login.jsp?uid=1"
            → path = "/bank/login.jsp"
            → segments = ["bank", "login"]  (extension stripped)
        """
        try:
            path = urlparse(url).path  # Chỉ lấy path, bỏ scheme/host/query
        except Exception:
            return []
        segments = []
        for seg in path.split("/"):
            seg = seg.strip()
            if not seg:
                continue
            # Strip file extension để so sánh
            base = seg.split(".")[0] if "." in seg else seg
            if base:
                segments.append(base.lower())
        return segments

    def _classify_path(self, url: str) -> str | None:
        """
        Phân loại URL vào category dựa trên path segments.
        Trả về canonical category hoặc None nếu không match.

        Chỉ match exact segment name (case-insensitive), không dùng substring.
        """
        segments = self._get_path_segments(url)
        if not segments:
            return None
        for seg in segments:
            for pattern, cat in SENSITIVE_PATH_SEGMENTS:
                if seg == pattern.lower():
                    return cat
        return None

    def _normalize_category(self, raw_cat: str) -> str:
        """
        Normalize category từ Phase 1 sang canonical label.
        VD: "login" → "authentication", "admin_panel" → "administrative"
        """
        return CATEGORY_CANONICAL.get(raw_cat.lower(), raw_cat.lower())

    # ── Các rule phân tích ───────────────────────────────────────────────────

    def _check_ssl(self, passive: dict):
        """Rule: Trạng thái SSL/TLS certificate."""
        ssl = passive.get("ssl") or {}
        if not ssl:
            self.findings.append(self._finding(
                category="ssl_tls",
                observation="SSL/TLS certificate information not available in Phase 1 data.",
                risk_indicator="informational",
                follow_up_priority="low",
                recommended_next_check="Verify SSL/TLS configuration through direct certificate inspection.",
            ))
            return

        days = ssl.get("days_remaining")
        issuer = ssl.get("issuer", "N/A")
        subject = ssl.get("subject", "N/A")

        if days is not None:
            if days < SSL_CRITICAL_DAYS:
                self.findings.append(self._finding(
                    category="ssl_tls",
                    observation=(
                        f"SSL/TLS certificate observed with {days} day(s) remaining until expiry "
                        f"(issuer: {issuer}). Below critical threshold of {SSL_CRITICAL_DAYS} days."
                    ),
                    risk_indicator="high",
                    follow_up_priority="high",
                    recommended_next_check="Implement certificate renewal process to prevent service disruption.",
                ))
            elif days < SSL_WARN_DAYS:
                self.findings.append(self._finding(
                    category="ssl_tls",
                    observation=(
                        f"SSL/TLS certificate observed with {days} day(s) remaining until expiry "
                        f"(issuer: {issuer}). Below recommended threshold of {SSL_WARN_DAYS} days."
                    ),
                    risk_indicator="medium",
                    follow_up_priority="medium",
                    recommended_next_check="Plan certificate renewal to ensure continuous availability.",
                ))
            else:
                self.findings.append(self._finding(
                    category="ssl_tls",
                    observation=(
                        f"SSL/TLS certificate observed as valid: {days} day(s) remaining "
                        f"(subject: {subject}, issuer: {issuer})."
                    ),
                    risk_indicator="informational",
                    follow_up_priority="none",
                    recommended_next_check="Monitor certificate expiry and validate TLS protocol configuration.",
                ))

        san = ssl.get("san") or []
        protocol = ssl.get("protocol", "")
        if san or protocol:
            self.findings.append(self._finding(
                category="ssl_tls",
                observation=(
                    f"Observed SSL/TLS configuration: protocol={protocol or 'N/A'}, "
                    f"SAN={', '.join(san) if san else 'Not observed'}."
                ),
                risk_indicator="informational",
                follow_up_priority="low",
                recommended_next_check="Validate SAN entries and TLS protocol version support.",
            ))

    def _check_security_headers(self, passive: dict, active: dict):
        """Rule: Security headers bị thiếu trong HTTP response."""
        active_headers = active.get("headers") or {}
        passive_sec = (passive.get("technology") or {}).get("security_headers") or {}

        missing, present = [], []
        for header in REQUIRED_SECURITY_HEADERS:
            # Header chỉ được coi là observed nếu key tồn tại và value không rỗng/null.
            active_val = next(
                (v for k, v in active_headers.items() if str(k).lower() == header.lower()),
                None
            )
            passive_val = passive_sec.get(header, None)

            in_active = active_val not in (None, "")
            in_passive = passive_val not in (None, "")
            (present if (in_active or in_passive) else missing).append(header)

        if missing:
            self.findings.append(self._finding(
                category="security_headers",
                observation=(
                    f"The following security headers were not observed in HTTP response "
                    f"(source: active_recon.headers / passive_recon.technology.security_headers): "
                    f"{', '.join(missing)}."
                ),
                risk_indicator="medium",
                follow_up_priority="medium",
                recommended_next_check="Configure missing security headers at the web server or application layer.",
            ))
        if present:
            self.findings.append(self._finding(
                category="security_headers",
                observation=f"Security headers observed in HTTP response: {', '.join(present)}.",
                risk_indicator="informational",
                follow_up_priority="none",
                recommended_next_check="Validate header values are correctly configured.",
            ))

    def _check_server_banner(self, active: dict, passive: dict):
        """Rule: Server header và service banners tiết lộ thông tin phần mềm."""
        server_val = (
            (active.get("headers") or {}).get("Server")
            or (passive.get("technology") or {}).get("server")
            or ""
        )
        if server_val:
            self.findings.append(self._finding(
                category="banner_disclosure",
                observation=(
                    f"Server header observed in HTTP response "
                    f"(source: active_recon.headers.Server): '{server_val}'."
                ),
                risk_indicator="low",
                follow_up_priority="low",
                recommended_next_check="Determine whether server version string should be suppressed in production configuration.",
            ))

        for banner in (active.get("banners") or []):
            port = banner.get("port", "?")
            service = banner.get("service", "unknown")
            if banner.get("banner", "").strip():
                self.findings.append(self._finding(
                    category="banner_disclosure",
                    observation=(
                        f"Service banner containing server identity observed on port {port} ({service}) "
                        f"(source: active_recon.banners)."
                    ),
                    risk_indicator="low",
                    follow_up_priority="low",
                    recommended_next_check=f"Review and consider suppressing banner content on port {port}.",
                ))

    def _check_x_powered_by(self, active: dict):
        """Rule: X-Powered-By header tiết lộ framework/runtime."""
        headers = active.get("headers") or {}
        xpb = next((v for k, v in headers.items() if k.lower() == "x-powered-by"), None)
        if xpb:
            self.findings.append(self._finding(
                category="banner_disclosure",
                observation=(
                    f"X-Powered-By header observed (source: active_recon.headers): '{xpb}'. "
                    f"Discloses application framework or runtime to any requester."
                ),
                risk_indicator="low",
                follow_up_priority="low",
                recommended_next_check="Consider suppressing X-Powered-By header to reduce technology disclosure.",
            ))

    def _check_cookies(self, active: dict):
        """Rule: Cookie security flags (Secure, HttpOnly, SameSite)."""
        cookies = active.get("cookies_analysis") or []
        if not cookies:
            self.findings.append(self._finding(
                category="cookie_security",
                observation="Cookie analysis data not available in Phase 1 data (active_recon.cookies_analysis).",
                risk_indicator="informational",
                follow_up_priority="low",
                recommended_next_check="Inspect cookies using browser DevTools or HTTP proxy during further testing.",
            ))
            return

        for cookie in cookies:
            name = cookie.get("name", "unknown")
            secure = self._get_cookie_flag(cookie, "Secure")
            httponly = self._get_cookie_flag(cookie, "HttpOnly")
            samesite = self._get_cookie_flag(cookie, "SameSite")

            issues = []
            if not secure:
                issues.append("Secure flag not observed (cookie may transmit over plaintext HTTP)")
            if not httponly:
                issues.append("HttpOnly flag not observed (cookie accessible via client-side script)")
            if samesite is None:
                issues.append("SameSite attribute not observed (cross-site request concern — requires validation)")

            if issues:
                self.findings.append(self._finding(
                    category="cookie_security",
                    observation=(
                        f"Cookie '{name}' (source: active_recon.cookies_analysis) observed with "
                        f"potential configuration concerns: {'; '.join(issues)}."
                    ),
                    risk_indicator="medium",
                    follow_up_priority="medium",
                    recommended_next_check=(
                        f"Validate cookie '{name}' attributes during authenticated session testing. "
                        f"Confirm cookie role before drawing conclusions."
                    ),
                ))
            else:
                self.findings.append(self._finding(
                    category="cookie_security",
                    observation=f"Cookie '{name}' observed with Secure and HttpOnly flags present.",
                    risk_indicator="informational",
                    follow_up_priority="none",
                    recommended_next_check="Verify SameSite attribute value and cookie scope during further testing.",
                ))

    def _check_open_ports(self, active: dict, passive: dict):
        """
        Rule: Open ports và services.
        Merge Nmap + Shodan với deduplication rõ ràng.
        """
        nmap_ports = active.get("ports") or []
        shodan_ports = (passive.get("shodan") or {}).get("ports") or []

        # Merge với source tracking — dedup theo port number
        merged: dict = {}  # port_num -> {service, version, sources: set}
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

        if not merged:
            self.findings.append(self._finding(
                category="port_exposure",
                observation="No open port data available in Phase 1 data.",
                risk_indicator="informational",
                follow_up_priority="low",
                recommended_next_check="Confirm port scan coverage and methodology.",
            ))
            return

        port_list = sorted(merged.keys())
        service_str = ", ".join(f"{p}/{merged[p]['service']}" for p in port_list)

        # Ghi nhận tổng quan
        self.findings.append(self._finding(
            category="port_exposure",
            observation=(
                f"{len(port_list)} open port(s) observed (sources: Nmap + Shodan, deduplicated): "
                f"{port_list}. Services: {service_str}."
            ),
            risk_indicator="informational",
            follow_up_priority="low",
            recommended_next_check="Verify service versions and whether all open ports are intentionally exposed.",
        ))

        # Cảnh báo riêng cho port không tiêu chuẩn
        for port in port_list:
            if port in NON_STANDARD_HTTP_PORTS:
                svc = merged[port]["service"]
                srcs = ", ".join(sorted(merged[port]["sources"]))
                self.findings.append(self._finding(
                    category="port_exposure",
                    observation=(
                        f"Non-standard HTTP port {port} ({svc}) observed as open "
                        f"(source: {srcs}). May indicate an additional web interface or management service."
                    ),
                    risk_indicator="medium",
                    follow_up_priority="medium",
                    recommended_next_check=(
                        f"Determine whether port {port} exposes an alternate entry point or admin interface."
                    ),
                ))

    def _check_waf(self, active: dict):
        """Rule: WAF detection."""
        waf = active.get("waf") or {}
        detected = waf.get("detected", False)
        waf_name = waf.get("name", "")
        source = waf.get("source", "N/A")

        if detected:
            self.findings.append(self._finding(
                category="waf_detection",
                observation=f"Web Application Firewall (WAF) detected: {waf_name or 'unknown vendor'} (source: {source}).",
                risk_indicator="informational",
                follow_up_priority="low",
                recommended_next_check="Document WAF presence for scope awareness during further testing.",
            ))
        else:
            self.findings.append(self._finding(
                category="waf_detection",
                observation=(
                    f"No Web Application Firewall (WAF) detected during Phase 1 reconnaissance "
                    f"(source: {source}). This is an observed indicator only — requires further validation."
                ),
                risk_indicator="low",
                follow_up_priority="low",
                recommended_next_check="Confirm WAF configuration using additional reconnaissance techniques.",
            ))

    def _check_http_methods(self, active: dict):
        """Rule: HTTP methods."""
        methods = active.get("http_methods") or []
        if not methods:
            self.findings.append(self._finding(
                category="http_methods",
                observation="HTTP methods data not available in Phase 1 data (active_recon.http_methods is empty).",
                risk_indicator="informational",
                follow_up_priority="low",
                recommended_next_check="Verify allowed HTTP methods through direct testing.",
            ))
            return

        risky = [m for m in methods if m.upper() in RISKY_HTTP_METHODS]
        if risky:
            self.findings.append(self._finding(
                category="http_methods",
                observation=(
                    f"Potentially risky HTTP method(s) observed as allowed "
                    f"(source: active_recon.http_methods): {', '.join(risky)}. "
                    f"This is an initial attack surface indicator requiring further validation."
                ),
                risk_indicator="medium",
                follow_up_priority="medium",
                recommended_next_check=(
                    f"Validate whether {', '.join(risky)} method(s) are intentionally enabled "
                    f"and appropriately restricted. Test impact scope during authorized testing."
                ),
            ))
        else:
            self.findings.append(self._finding(
                category="http_methods",
                observation=f"Observed HTTP methods (source: active_recon.http_methods): {', '.join(methods)}. No high-risk methods observed.",
                risk_indicator="informational",
                follow_up_priority="none",
                recommended_next_check="Verify HTTP method restrictions are enforced at the application layer.",
            ))

    def _check_sensitive_endpoints(self, active: dict, passive: dict):
        """
        Rule: Endpoint nhạy cảm.

        Deduplication strategy:
          - Build unified registry: canonical_url → {category, sources}
          - Priority: notable_endpoints (explicit Phase 1 category) > hidden > crawl
          - Same URL từ nhiều source → merge vào một entry, không sinh duplicate finding
          - Classification chỉ dựa trên PATH SEGMENTS, không dùng full URL string

        Findings được group theo category — một finding duy nhất per category.
        """
        crawl = active.get("crawl") or {}
        crawl_urls = crawl.get("urls") or []
        notable = crawl.get("notable_endpoints") or []
        hidden = active.get("hidden_endpoints") or []

        # ── Bước 1: Build unified registry ───────────────────────────────────
        registry = {}  # normalized_url → {"category": str, "sources": set}

        def _norm_key(url: str) -> str:
            """Normalize URL key để dedup."""
            return url.rstrip("/").rstrip("&").strip()

        def _register(url: str, category: str, source: str, priority: int):
            """
            Thêm URL vào registry.
            priority: số cao hơn = nguồn đáng tin hơn.
            Nếu URL đã có với priority cao hơn, chỉ merge sources.
            """
            if not url or not category:
                return
            key = _norm_key(url)
            if key not in registry:
                registry[key] = {
                    "url": url,
                    "category": category,
                    "sources": {source},
                    "priority": priority,
                }
            else:
                registry[key]["sources"].add(source)
                # Upgrade category chỉ khi nguồn mới có priority cao hơn
                if priority > registry[key]["priority"]:
                    registry[key]["category"] = category
                    registry[key]["priority"] = priority

        # Priority 1 (cao nhất): notable_endpoints — category đã được Phase 1 xác định
        for ep in notable:
            url = ep.get("url", "")
            raw_cat = ep.get("category", "")
            if url and raw_cat:
                cat = self._normalize_category(raw_cat)
                _register(url, cat, "notable_endpoints", priority=3)

        # Priority 2: hidden_endpoints — phát hiện qua fuzzing
        for ep in hidden:
            url = ep.get("url") or ep.get("path") or ""
            if not url:
                continue
            cat = self._classify_path(url)
            if cat:
                _register(url, cat, "hidden_endpoints", priority=2)
            else:
                # Không classify được nhưng vẫn ghi nhận là endpoint đáng xem
                _register(url, "other_notable", "hidden_endpoints", priority=1)

        # Priority 3 (thấp nhất): crawl URLs — pattern-based, path-only
        for url in crawl_urls:
            cat = self._classify_path(url)  # chỉ dùng path segment matching
            key = _norm_key(url)
            if cat:
                _register(url, cat, "crawl", priority=1)
            elif key in registry:
                # URL đã có từ nguồn khác — chỉ thêm source
                registry[key]["sources"].add("crawl")

        # ── Bước 2: Group theo category ───────────────────────────────────────
        by_cat: dict = {}
        for entry in registry.values():
            cat = entry["category"]
            by_cat.setdefault(cat, {"urls": [], "all_sources": set()})
            by_cat[cat]["urls"].append(entry["url"])
            by_cat[cat]["all_sources"].update(entry["sources"])

        # ── Bước 3: Sinh một finding per category ────────────────────────────
        for category, data in sorted(by_cat.items()):
            urls = sorted(set(data["urls"]))
            sources = sorted(data["all_sources"])
            total = len(urls)
            sample = urls[:5]
            overflow = total > 5

            sample_str = ", ".join(f"'{u}'" for u in sample)
            if overflow:
                sample_str += f" ... (+{total - 5} more)"

            risk = "medium" if category in HIGH_RISK_CATEGORIES else "low"
            priority = "high" if category in {"administrative", "authentication", "file_upload"} else "medium"

            self.findings.append(self._finding(
                category="sensitive_endpoints",
                observation=(
                    f"Endpoint category '{category}' observed ({total} URL(s), "
                    f"sources: {', '.join(sources)}): {sample_str}."
                ),
                risk_indicator=risk,
                follow_up_priority=priority,
                recommended_next_check=(
                    f"Verify authentication and access control requirements for '{category}' endpoints."
                ),
            ))

        # ── Bước 4: Wayback — file extensions nhạy cảm ───────────────────────
        wayback_urls = (passive.get("wayback") or {}).get("urls") or []
        sensitive_wb = [
            u for u in wayback_urls
            if any(u.lower().endswith(ext) or ext in u.lower() for ext in SENSITIVE_WAYBACK_EXTENSIONS)
        ]
        if sensitive_wb:
            sample = sensitive_wb[:5]
            self.findings.append(self._finding(
                category="wayback_disclosure",
                observation=(
                    f"{len(sensitive_wb)} URL(s) with potentially sensitive file extensions observed "
                    f"in Wayback Machine historical data (source: passive_recon.wayback.urls). "
                    f"Sample: {', '.join(sample)}."
                ),
                risk_indicator="medium",
                follow_up_priority="medium",
                recommended_next_check="Check current accessibility of historical URLs with sensitive extensions.",
            ))

    def _check_hidden_endpoints(self, active: dict):
        """
        Rule: Hidden endpoints phát hiện qua directory fuzzing.
        Note: URLs từ đây cũng được xử lý trong _check_sensitive_endpoints.
        Ở đây chỉ ghi nhận evidence riêng về HTTP status response.
        """
        hidden = active.get("hidden_endpoints") or []
        for ep in hidden:
            url = ep.get("url") or ep.get("path") or ""
            status = ep.get("status") or ep.get("status_code") or "N/A"
            source = ep.get("source", "unknown")
            self.findings.append(self._finding(
                category="hidden_endpoints",
                observation=(
                    f"Path '{url}' responded with HTTP {status} during directory fuzzing "
                    f"(source: {source} -> active_recon.hidden_endpoints)."
                ),
                risk_indicator="medium",
                follow_up_priority="high",
                recommended_next_check=f"Verify authentication and access control for '{url}'.",
            ))

    def _check_hidden_fields(self, active: dict):
        """Rule: Hidden fields trong HTML forms."""
        hidden_fields = (active.get("crawl") or {}).get("hidden_fields") or []
        for hf in hidden_fields:
            name = hf.get("name", "unknown")
            value = hf.get("value", "")
            form = hf.get("form") or hf.get("form_action", "N/A")
            self.findings.append(self._finding(
                category="form_analysis",
                observation=(
                    f"Hidden field '{name}' (value: '{value}') observed "
                    f"in form '{form}' (source: active_recon.crawl.hidden_fields)."
                ),
                risk_indicator="low",
                follow_up_priority="low",
                recommended_next_check=f"Inspect hidden field '{name}' for business logic implications during authorized testing.",
            ))

    def _check_forms(self, active: dict):
        """Rule: HTML forms -- consolidate generic, separate auth/upload."""
        forms = (active.get("crawl") or {}).get("forms") or []
        if not forms:
            self.findings.append(self._finding(
                category="form_analysis",
                observation="No HTML forms observed in Phase 1 crawl data (active_recon.crawl.forms is empty).",
                risk_indicator="informational",
                follow_up_priority="none",
                recommended_next_check="Verify using manual browser navigation or deeper crawl.",
            ))
            return

        auth_forms = []
        upload_forms = []
        generic_forms = []

        login_kw = {"uid", "passw", "password", "username", "pass", "pwd", "user"}
        upload_kw = {"file", "upload", "attachment"}

        for form in forms:
            action = form.get("action", "unknown")
            method = (form.get("method") or "GET").upper()
            raw_inputs = form.get("inputs") or []
            input_names = []
            for inp in raw_inputs:
                if isinstance(inp, str):
                    input_names.append(inp.lower())
                elif isinstance(inp, dict):
                    input_names.append(str(inp.get("name", "")).lower())

            # hidden fields for CSRF detection
            hidden = form.get("hidden_fields") or {}
            hidden_keys = (
                list(hidden.keys()) if isinstance(hidden, dict)
                else [h.get("name", "") for h in hidden if isinstance(h, dict)]
            )
            has_csrf = any("csrf" in k.lower() or "token" in k.lower() for k in hidden_keys)

            is_login = bool(login_kw.intersection(set(input_names)))
            is_upload = bool(upload_kw.intersection(set(input_names)))

            form_data = {"action": action, "method": method, "inputs": raw_inputs, "has_csrf": has_csrf}
            if is_login:
                auth_forms.append(form_data)
            elif is_upload:
                upload_forms.append(form_data)
            else:
                generic_forms.append(form_data)

        # Create findings for authentication forms
        for f in auth_forms:
            csrf_note = (
                "CSRF token observed." if f["has_csrf"]
                else "No CSRF token observed -- requires further validation."
            )
            self.findings.append(self._finding(
                category="form_analysis",
                observation=(
                    f"Authentication form observed (action: '{f['action']}', method: {f['method']}, "
                    f"inputs: {f['inputs']}). {csrf_note}"
                ),
                risk_indicator="medium",
                follow_up_priority="high",
                recommended_next_check="Verify authentication security: session handling, HTTPS, and CSRF protection.",
            ))

        # Create findings for upload forms
        for f in upload_forms:
            self.findings.append(self._finding(
                category="form_analysis",
                observation=(
                    f"File upload form observed (action: '{f['action']}', method: {f['method']})."
                ),
                risk_indicator="medium",
                follow_up_priority="high",
                recommended_next_check="Review file upload restrictions and sanitization policies.",
            ))

        # Consolidate generic forms into a single summary finding
        if generic_forms:
            if len(generic_forms) == 1:
                f = generic_forms[0]
                self.findings.append(self._finding(
                    category="form_analysis",
                    observation=(
                        f"Standard HTML form observed (action: '{f['action']}', method: {f['method']}, "
                        f"inputs: {f['inputs']})."
                    ),
                    risk_indicator="informational",
                    follow_up_priority="low",
                    recommended_next_check="Review form inputs during authorized testing.",
                ))
            else:
                actions = [f["action"] for f in generic_forms[:5]]
                actions_str = ", ".join(actions)
                if len(generic_forms) > 5:
                    actions_str += f", ... (+{len(generic_forms) - 5} more)"
                self.findings.append(self._finding(
                    category="form_analysis",
                    observation=(
                        f"{len(generic_forms)} standard HTML forms observed (actions: {actions_str}). "
                        f"None appear to be authentication or file upload forms."
                    ),
                    risk_indicator="informational",
                    follow_up_priority="low",
                    recommended_next_check="Inspect form inputs for potential injection points during authorized testing.",
                ))

    def _check_subdomains(self, passive: dict):
        """Rule: Subdomain enumeration."""
        subdomains = passive.get("subdomains") or []
        if not subdomains:
            self.findings.append(self._finding(
                category="subdomain_exposure",
                observation="No subdomains observed in Phase 1 data.",
                risk_indicator="informational",
                follow_up_priority="low",
                recommended_next_check="Consider additional subdomain enumeration techniques.",
            ))
            return

        sub_names = []
        for s in subdomains:
            if isinstance(s, dict):
                name = s.get("subdomain", "")
                if name:
                    sub_names.append(name)
            elif isinstance(s, str) and s:
                sub_names.append(s)

        self.findings.append(self._finding(
            category="subdomain_exposure",
            observation=(
                f"{len(sub_names)} subdomain(s) observed "
                f"(source: passive_recon.subdomains): {', '.join(sub_names)}."
            ),
            risk_indicator="informational",
            follow_up_priority="low",
            recommended_next_check="Verify active status and service configuration of each subdomain.",
        ))

        suspicious = [
            name for name in sub_names
            if name.split(".")[0].lower() in SUSPICIOUS_SUBDOMAIN_PREFIXES
        ]
        if suspicious:
            self.findings.append(self._finding(
                category="subdomain_exposure",
                observation=(
                    f"Subdomains with notable naming patterns observed: {', '.join(suspicious)}. "
                    f"May indicate development, administrative, FTP, or legacy services."
                ),
                risk_indicator="medium",
                follow_up_priority="medium",
                recommended_next_check="Review access controls and service exposure for flagged subdomains.",
            ))

    def _check_robots(self, active: dict):
        """
        Rule: robots.txt và sitemap.
        
        IMPORTANT: robots.txt status and sitemap data are handled INDEPENDENTLY.
        A 404 on robots.txt does NOT imply no sitemap data exists.
        """
        discovery = active.get("discovery") or {}
        robots = discovery.get("robots") or {}
        sitemap_urls = discovery.get("sitemap_urls") or []

        status = robots.get("status")
        disallowed = robots.get("disallowed") or []
        sitemaps = robots.get("sitemaps") or []

        # Merge all sitemap sources (robots.txt Sitemap: directives + direct sitemap discovery)
        all_sitemaps = list(dict.fromkeys(sitemaps + sitemap_urls))

        # --- robots.txt finding (independent of sitemap) ---
        if status == 404:
            self.findings.append(self._finding(
                category="robots_sitemap",
                observation=(
                    f"robots.txt returned HTTP 404 "
                    f"(source: active_recon.discovery.robots.status)."
                ),
                risk_indicator="informational",
                follow_up_priority="none",
                recommended_next_check="Confirm robots.txt is intentionally absent or verify URL path.",
            ))
        elif disallowed:
            self.findings.append(self._finding(
                category="robots_sitemap",
                observation=(
                    f"robots.txt Disallow entries observed "
                    f"(source: active_recon.discovery.robots.disallowed): {', '.join(disallowed)}. "
                    f"These paths are excluded from crawlers but may still be accessible."
                ),
                risk_indicator="low",
                follow_up_priority="medium",
                recommended_next_check="Verify accessibility and authentication requirements of Disallow paths.",
            ))
        elif status is not None and status != 404:
            # robots.txt exists but has no disallow entries
            self.findings.append(self._finding(
                category="robots_sitemap",
                observation=(
                    f"robots.txt returned HTTP {status} but contained no Disallow entries "
                    f"(source: active_recon.discovery.robots)."
                ),
                risk_indicator="informational",
                follow_up_priority="none",
                recommended_next_check="Verify robots.txt configuration.",
            ))

        # --- sitemap finding (independent of robots.txt status) ---
        if all_sitemaps:
            self.findings.append(self._finding(
                category="robots_sitemap",
                observation=f"Sitemap URL(s) observed: {', '.join(all_sitemaps[:5])}.",
                risk_indicator="informational",
                follow_up_priority="low",
                recommended_next_check="Review sitemap for additional endpoint discovery.",
            ))
        else:
            self.findings.append(self._finding(
                category="robots_sitemap",
                observation=(
                    "No sitemap data observed "
                    "(source: active_recon.discovery.sitemap_urls and robots.sitemaps are empty)."
                ),
                risk_indicator="informational",
                follow_up_priority="none",
                recommended_next_check="Check for sitemap.xml at common paths.",
            ))

    def _check_url_params(self, active: dict):
        """Rule: URL parameters — tên gợi ý injection hoặc path traversal."""
        params = (active.get("crawl") or {}).get("params") or []
        if not params:
            self.findings.append(self._finding(
                category="url_parameters",
                observation="No URL parameters observed in Phase 1 crawl data (active_recon.crawl.params is empty).",
                risk_indicator="informational",
                follow_up_priority="none",
                recommended_next_check="Perform deeper crawl to discover URL parameters.",
            ))
            return

        param_names = []
        for p in params:
            if isinstance(p, dict):
                name = p.get("name", "")
                if name:
                    param_names.append(name)
            elif isinstance(p, str) and p:
                param_names.append(p)

        self.findings.append(self._finding(
            category="url_parameters",
            observation=(
                f"{len(param_names)} URL/form parameter(s) observed "
                f"(source: active_recon.crawl.params): {', '.join(param_names)}."
            ),
            risk_indicator="informational",
            follow_up_priority="medium",
            recommended_next_check="Validate parameters for injection susceptibility during authorized testing.",
        ))

        suspicious = [n for n in param_names if n.lower() in SUSPICIOUS_PARAM_KEYWORDS]
        if suspicious:
            self.findings.append(self._finding(
                category="url_parameters",
                observation=(
                    f"Parameter(s) with naming patterns associated with path/URL manipulation observed: "
                    f"{', '.join(suspicious)}. "
                    f"This is a potential risk indicator requiring further validation."
                ),
                risk_indicator="medium",
                follow_up_priority="high",
                recommended_next_check="Investigate parameter behavior and validate input handling.",
            ))

    def _check_technology(self, passive: dict):
        """
        Rule: Technology stack — server, framework, CMS.

        CONSTRAINT: Chỉ bao gồm actual technology identifiers.
        Filter out: cookie attributes, header names, session token names
        (HttpOnly, JSESSIONID, Secure, etc. KHÔNG phải tech stack).
        """
        tech = passive.get("technology") or {}
        server = tech.get("server", "")
        frameworks = tech.get("frameworks") or []
        cms = tech.get("cms", "")
        whatweb = tech.get("whatweb") or []

        parts = []
        if server:
            parts.append(f"Server: {server}")
        if frameworks:
            parts.append(f"Frameworks: {', '.join(frameworks)}")
        if cms:
            parts.append(f"CMS: {cms}")

        # Filter WhatWeb — loại bỏ non-technology entries
        for ww in whatweb:
            name = ww.get("name", "")
            # Skip nếu name là cookie attribute, header attribute, hay session token name
            if not name or name.lower() in WHATWEB_NON_TECH_NAMES:
                continue
            ver = ww.get("version", "")
            # Cũng skip nếu version là một cookie/session token name
            if ver and ver.lower() in WHATWEB_NON_TECH_NAMES:
                ver = ""
            entry = name + (f" {ver}" if ver else "")
            # Tránh duplicate với framework đã có
            if entry and not any(entry.lower() in p.lower() for p in parts):
                parts.append(entry)

        if parts:
            self.findings.append(self._finding(
                category="technology_fingerprint",
                observation=(
                    f"Technology stack identified from reconnaissance "
                    f"(source: passive_recon.technology): {'; '.join(parts)}."
                ),
                risk_indicator="low",
                follow_up_priority="low",
                recommended_next_check="Cross-reference identified components against known vulnerability databases.",
            ))
        else:
            self.findings.append(self._finding(
                category="technology_fingerprint",
                observation="Technology fingerprint data not available or could not be determined from Phase 1 data.",
                risk_indicator="informational",
                follow_up_priority="low",
                recommended_next_check="Consider additional fingerprinting techniques for technology identification.",
            ))

    def _check_spf_record(self, passive: dict):
        """Rule: SPF TXT record."""
        txt_records = (passive.get("dns_records") or {}).get("TXT") or []
        mx_records = (passive.get("dns_records") or {}).get("MX") or []
        spf_records = [r for r in txt_records if "v=spf1" in r.lower()]

        if spf_records:
            self.findings.append(self._finding(
                category="dns_email",
                observation=f"SPF TXT record observed (source: passive_recon.dns_records.TXT): {spf_records[0]}.",
                risk_indicator="informational",
                follow_up_priority="none",
                recommended_next_check="Validate SPF policy strictness. Also check DMARC and DKIM records.",
            ))
        elif mx_records:
            self.findings.append(self._finding(
                category="dns_email",
                observation=(
                    f"MX records observed but no SPF TXT record found "
                    f"(source: passive_recon.dns_records). This is an observed indicator only."
                ),
                risk_indicator="low",
                follow_up_priority="low",
                recommended_next_check="Verify SPF, DMARC, and DKIM configuration for email security.",
            ))

    # ── Attack surface summary ────────────────────────────────────────────────

    def _compute_missing_security_headers(self, passive: dict, active: dict) -> list:
        """
        Compute missing security headers using the SAME logic as _check_security_headers.
        A header is considered present if it exists with a non-empty value in EITHER
        active_recon.headers OR passive_recon.technology.security_headers.
        """
        active_headers = active.get("headers") or {}
        passive_sec = (passive.get("technology") or {}).get("security_headers") or {}

        missing = []
        for header in REQUIRED_SECURITY_HEADERS:
            # Check active headers (case-insensitive lookup)
            active_val = next(
                (v for k, v in active_headers.items() if str(k).lower() == header.lower()),
                None
            )
            passive_val = passive_sec.get(header, None)

            in_active = active_val not in (None, "")
            in_passive = passive_val not in (None, "")

            if not (in_active or in_passive):
                missing.append(header)

        return missing

    def _build_attack_surface_summary(self, data: dict) -> dict:
        """
        Tính toán các số liệu tổng quan bề mặt tấn công.
        Port count dùng merged (Nmap + Shodan, deduplicated).
        Security headers use same logic as _check_security_headers.
        """
        passive = data.get("passive_recon") or {}
        active = data.get("active_recon") or {}
        summary = data.get("summary") or {}
        crawl = active.get("crawl") or {}

        # Port count: dùng merged deduplicated — cùng logic với _check_open_ports
        nmap_ports = active.get("ports") or []
        shodan_ports = (passive.get("shodan") or {}).get("ports") or []
        merged_ports = {p["port"]: p for p in nmap_ports}
        for sp in shodan_ports:
            if sp["port"] not in merged_ports:
                merged_ports[sp["port"]] = sp

        # Security headers: use unified logic (same as _check_security_headers)
        missing_headers = self._compute_missing_security_headers(passive, active)

        return {
            # Dùng merged deduplicated count cho ports
            "total_open_ports": len(merged_ports),
            "total_open_ports_note": (
                f"Nmap: {len(nmap_ports)}, Shodan: {len(shodan_ports)}, "
                f"deduplicated: {len(merged_ports)}"
            ),
            "total_subdomains": summary.get("total_subdomains", len(passive.get("subdomains") or [])),
            "total_crawled_urls": summary.get("total_urls", len(crawl.get("urls") or [])),
            "total_forms": summary.get("total_forms", len(crawl.get("forms") or [])),
            "total_params": summary.get("total_params", len(crawl.get("params") or [])),
            "total_notable_endpoints": summary.get("total_notable_endpoints", 0),
            "total_hidden_endpoints": summary.get(
                "total_hidden_endpoints",
                len(active.get("hidden_endpoints") or [])
            ),
            "total_wayback_urls": summary.get(
                "total_wayback_urls",
                len((passive.get("wayback") or {}).get("urls") or [])
            ),
            "total_js_endpoints": summary.get("total_js_endpoints", 0),
            "total_emails_found": summary.get("total_emails", 0),
            "security_headers_missing": missing_headers,
            "waf_detected": (active.get("waf") or {}).get("detected", False),
            "ssl_valid": summary.get("ssl_valid"),
            "ssl_days_remaining": (passive.get("ssl") or {}).get("days_remaining"),
        }

    # ── Entry point ───────────────────────────────────────────────────────────

    def run(self, input_path: str, output_dir: str) -> str:
        """
        Đọc phase1_canonical.json, chạy tất cả rule, ghi phase3_analysis.json.
        """
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        passive = data.get("passive_recon") or {}
        active = data.get("active_recon") or {}

        self.findings = []
        self._counter = 0

        # Chạy từng nhóm rule
        self._check_ssl(passive)
        self._check_security_headers(passive, active)
        self._check_server_banner(active, passive)
        self._check_x_powered_by(active)
        self._check_cookies(active)
        self._check_open_ports(active, passive)
        self._check_waf(active)
        self._check_http_methods(active)
        self._check_sensitive_endpoints(active, passive)  # includes dedup logic
        self._check_hidden_endpoints(active)              # HTTP status evidence
        self._check_hidden_fields(active)
        self._check_forms(active)
        self._check_subdomains(passive)
        self._check_robots(active)
        self._check_url_params(active)
        self._check_technology(passive)
        self._check_spf_record(passive)

        output = {
            "meta": {
                "target": data.get("target", ""),
                "timestamp_phase1": data.get("timestamp", ""),
                "timestamp_analysis": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "analyzer_version": ANALYZER_VERSION,
                "input_file": os.path.basename(input_path),
            },
            "attack_surface_summary": self._build_attack_surface_summary(data),
            "findings": self.findings,
        }

        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "phase3_analysis.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)

        print(f"  [AnalysisAgent] {len(self.findings)} findings generated.")
        return output_path
