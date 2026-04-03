"""
memory.py — Agent Memory cho pipeline Phase 1 + Phase 3.

Scope hien tai:
  - Phase 1: Reconnaissance + Crawl
  - Phase 3: Report

`recon_data` la source of truth cho du lieu ky thuat va crawl. Cac field lien
quan den Phase 2 van duoc giu o muc backward compatibility, nhung runtime path
chinh khong con su dung `raw_findings`, `final_findings`, hay `phase2_summary`.
"""
import json
import os
import time


class ScanMemory:
    """
    Shared memory cho ReconAgent, CrawlerAgent, va ReportAgent.

    Runtime path chinh:
      ReconAgent   -> set_recon_data()
      CrawlerAgent -> set_crawl_data()
      ReportAgent  -> build_phase1_output() / save_phase1_output()

    Legacy Phase 2 fields van ton tai de tranh gay code cu, nhung khong con la
    mot phan cua runtime path mac dinh.
    """

    def __init__(self, target: str):
        self._ctx: dict = {
            "target":          target,
            "scan_start_time": time.strftime("%d/%m/%Y %H:%M:%S"),
            # ── Phase 1: Recon data (Attack Surface Discovery) ───────────────
            # Output tu ReconAgent: curl, whatweb, ffuf, nmap
            "recon_data": {
                "target_url":       target,    # URL goc nguoi dung nhap
                "host":             "",        # hostname goc
                "ip":               "",        # resolved IP address
                "status":           0,         # HTTP status code cua target chinh
                "server":           "",        # server banner
                "open_ports":       [],        # nmap/socket: [{"port": 80, "service": "http", "version": "..."}]
                "nmap_available":   False,     # Nmap binary co chay duoc khong
                "source":           "none",    # "nmap" | "socket" | "none"
                "dns_records":      {},        # A, AAAA, MX, NS, ...
                "ssl_info":         {},        # SSL cert info (optional)
                "technologies":     [],        # whatweb: Detected web technologies
                "http_headers":     {},        # curl: HTTP headers
                "http_methods":     [],        # allowed / observed methods
                "redirects":        [],        # redirect chain
                "cookies":          [],        # curl: Cookies
                "discovered_paths": [],        # ffuf: file/thu muc/endpoint tim duoc
                "robots_txt":       {},        # curl: robots.txt content
                # ── Phase 1 crawl output (dung truc tiep boi Phase 2) ────────
                "urls":             [],        # internal URLs tim duoc khi crawl
                "forms":            [],        # forms (action, method, inputs, hidden_fields)
                "params":           {},        # query/form params: {param_name: [example_values]}
                "notable_endpoints": [],       # endpoints dang chu y de dua vao report
                "limitations":      [],        # gioi han / loi non-fatal
                "attack_surface":   {          # entrypoints da phan loai
                    "entrypoints":           [],  # tat ca endpoint (deduped)
                    "auth_pages":            [],  # login/logout/register/...
                    "upload_points":         [],  # upload/file endpoints
                    "api_like_endpoints":    [],  # /api/, /v1/, /graphql/...
                    "admin_pages":           [],  # admin/dashboard/panel/...
                    "categorized_endpoints": [],  # [{url, category, method, source}]
                },
            },
            # assessment_context: du lieu Phase 2 thu thap qua requests + BeautifulSoup
            "assessment_context": {
                "http_headers":    {},   # Headers quan sat duoc qua requests
                "ssl_info":        {},   # SSL/TLS status qua requests
                "http_methods":    [],   # Dangerous HTTP methods
                "forms":           [],   # BeautifulSoup: Forms cho SQLi/XSS testing
                "redirects":       [],   # requests: redirect chains
                "crawled_links":   [],   # BeautifulSoup: internal links
                "query_params":    {},   # BeautifulSoup: query parameters
            },
            # 3-layer data contract (Phase 2 pipeline)
            "raw_findings":        [],  # ScannerAgent: ket qua tho, chua xu ly
            "normalized_findings": [],  # CorrelationAgent: da chuan hoa OWASP/CWE
            "final_findings":      [],  # RiskAssessmentAgent: dedup+score+exploit_status
            "phase2_summary":      {},  # RiskAssessmentAgent: tong ket Phase 2
            # backward compat — ReportAgent + checkpoint doc tu day
            "vulnerabilities": [],
            "risk_score":      0,
            "risk_label":      "",
            "scan_time":       "",
            "report_path":     "",
            "pdf_path":        "",
            # ── Phase 1 canonical schema (3-agent pipeline) ──────────────
            "passive_recon":   {},   # PassiveReconAgent output
            "active_recon":    {},   # ActiveReconAgent output
            "canonical_phase1": {},  # ReconAggregatorAgent canonical JSON
        }

    # ── Passive Recon (PassiveReconAgent) ─────────────────────────────────
    def set_passive_recon(self, data: dict) -> None:
        self._ctx["passive_recon"] = dict(data or {})

    def get_passive_recon(self) -> dict:
        return self._ctx.get("passive_recon", {})

    # ── Active Recon (ActiveReconAgent) ───────────────────────────────────
    def set_active_recon(self, data: dict) -> None:
        self._ctx["active_recon"] = dict(data or {})

    def get_active_recon(self) -> dict:
        return self._ctx.get("active_recon", {})

    # ── Canonical Phase 1 (ReconAggregatorAgent) ─────────────────────────
    def set_canonical_phase1(self, data: dict) -> None:
        self._ctx["canonical_phase1"] = dict(data or {})

    def get_canonical_phase1(self) -> dict:
        return self._ctx.get("canonical_phase1", {})

    # ── Assessment Context (internal helper data) ─────────────────────
    def set_assessment_context(self, context_data: dict) -> None:
        """
        VulnAgent (Phase 2) luu du lieu thu thap qua requests + BeautifulSoup:
          - headers, SSL: qua requests
          - forms, links, query_params: qua BeautifulSoup
        Day la du lieu Phase 2 thu thap, KHONG phai Phase 1 recon.
        """
        self._ctx["assessment_context"].update(context_data)

    def get_assessment_context(self) -> dict:
        """Doc du lieu context ho tro."""
        return self._ctx["assessment_context"]

    # ── Recon Data (ReconAgent output - Phase 1) ─────────────────────────
    def set_recon_data(self, recon_result: dict) -> None:
        """
        ReconAgent luu ket qua recon (Nmap scan, DNS, SSL) vao memory.

        Expected schema:
        {
            "host":           str,    # hostname goc
            "ip":             str,    # resolved IP
            "open_ports":     [       # list cac port mo
                {"port": 80, "service": "http", "version": "Apache/2.4"},
            ],
            "nmap_available": bool,   # Nmap binary chay duoc khong
            "source":         str,    # "nmap" | "socket" | "none"
            "dns_records":    dict,   # optional DNS records
            "ssl_info":       dict,   # optional SSL cert info
            "technologies":   list,   # optional detected technologies
        }
        """
        self._ctx["recon_data"].update(recon_result or {})

    def get_recon_data(self) -> dict:
        """Tra ve ket qua recon tu ReconAgent."""
        return self._ctx.get("recon_data", {})

    def get_open_ports(self) -> list:
        """Shortcut: tra ve danh sach open ports tu recon_data."""
        return self._ctx.get("recon_data", {}).get("open_ports", [])

    def is_nmap_available(self) -> bool:
        """Shortcut: kiem tra Nmap co san khong tu recon_data."""
        return self._ctx.get("recon_data", {}).get("nmap_available", False)

    def set_crawl_data(self, crawl_result: dict) -> None:
        """
        Merge ket qua crawl vao `recon_data`.

        `crawl_result` co the den tu CrawlerAgent hoac utility script, voi mot
        trong cac field:
          - urls
          - forms
          - params / parameters
          - notable_endpoints / endpoints
          - limitations
        """
        crawl_result = crawl_result or {}
        recon_data = self._ctx["recon_data"]

        if crawl_result.get("urls"):
            urls = list(dict.fromkeys([
                *recon_data.get("urls", []),
                *crawl_result.get("urls", []),
            ]))
            recon_data["urls"] = urls

        if crawl_result.get("forms"):
            recon_data["forms"] = list(crawl_result.get("forms", []))

        raw_params = crawl_result.get("params", crawl_result.get("parameters"))
        if raw_params:
            recon_data["params"] = raw_params

        notable = crawl_result.get("notable_endpoints", crawl_result.get("endpoints"))
        if notable:
            recon_data["notable_endpoints"] = list(notable)

        if crawl_result.get("limitations"):
            existing = recon_data.get("limitations", [])
            recon_data["limitations"] = list(dict.fromkeys([
                *existing,
                *crawl_result.get("limitations", []),
            ]))

    def add_limitation(self, message: str) -> None:
        """Ghi nhan mot limitation non-fatal cho Phase 1."""
        if not message:
            return
        recon_data = self._ctx["recon_data"]
        limitations = recon_data.setdefault("limitations", [])
        if message not in limitations:
            limitations.append(message)

    @staticmethod
    def _normalize_forms(forms: list) -> list:
        normalized = []
        seen = set()

        for form in forms or []:
            if not isinstance(form, dict):
                continue

            page = form.get("page") or form.get("page_url") or form.get("url") or ""
            action = form.get("action") or form.get("url") or page
            method = str(form.get("method", "GET")).upper()

            hidden_fields = dict(form.get("hidden_fields", {}) or {})
            user_inputs = []

            raw_inputs = form.get("inputs", [])
            for item in raw_inputs:
                if isinstance(item, dict):
                    name = str(item.get("name", "")).strip()
                    input_type = str(item.get("type", "text")).lower()
                    if not name:
                        continue
                    if input_type == "hidden":
                        hidden_fields.setdefault(name, item.get("value", ""))
                    elif input_type not in {"submit", "button", "image"}:
                        user_inputs.append(name)
                elif isinstance(item, str):
                    if item and item not in hidden_fields:
                        user_inputs.append(item)

            user_inputs = list(dict.fromkeys(user_inputs))
            form_obj = {
                "page": page,
                "action": action,
                "method": method,
                "inputs": user_inputs,
                "hidden_fields": hidden_fields,
            }
            key = (
                form_obj["page"],
                form_obj["action"],
                form_obj["method"],
                tuple(form_obj["inputs"]),
                tuple(sorted(form_obj["hidden_fields"].keys())),
            )
            if key in seen:
                continue
            seen.add(key)
            normalized.append(form_obj)

        return normalized

    @staticmethod
    def _normalize_params(params, forms: list) -> list:
        """
        Normalize params from various sources into unified schema.
        
        Deduplicates params by (page, name, source) to avoid double-counting
        when params appear in both crawl output and forms.
        """
        normalized = []
        seen = set()

        def add_param(page: str, name: str, source: str, examples=None, method: str = ""):
            name = str(name or "").strip()
            if not name:
                return
            key = (page or "", name, source)
            if key in seen:
                return
            seen.add(key)
            item = {
                "page": page or "",
                "name": name,
                "source": source,
            }
            if method:
                item["method"] = method
            if examples:
                cleaned = [str(v) for v in examples if v not in (None, "")]
                if cleaned:
                    item["examples"] = cleaned[:3]
            normalized.append(item)

        # ── Process existing params from crawl ────────────────────────────────
        if isinstance(params, dict):
            if any(k in params for k in ("query_params", "form_params", "all_param_names")):
                for item in params.get("query_params", []) or []:
                    if isinstance(item, dict):
                        add_param(item.get("page", ""), item.get("name", ""), "query", item.get("examples"))
                for item in params.get("form_params", []) or []:
                    if isinstance(item, dict):
                        add_param(item.get("page", item.get("form_url", "")), item.get("name", ""), "form", item.get("examples"), item.get("method", ""))
                for name in params.get("all_param_names", []) or []:
                    add_param("", name, "unknown")
            else:
                for name, values in params.items():
                    add_param("", name, "unknown", values if isinstance(values, list) else [values])
        elif isinstance(params, list):
            for item in params:
                if not isinstance(item, dict):
                    continue
                source = item.get("source", "unknown")
                page = item.get("page") or item.get("url") or ""
                names = item.get("params") if isinstance(item.get("params"), list) else [item.get("name")]
                for name in names:
                    add_param(page, name, source, item.get("examples"), item.get("method", ""))

        # ── Add form inputs as params (skip if already added from crawl) ──────
        # Only add if they weren't already captured from crawl data above.
        # This prevents double-counting when ActiveReconAgent.crawl already
        # collected form params and passed them in the params arg.
        for form in forms:
            form_page = form.get("page", "")
            form_method = form.get("method", "")
            
            # User inputs (text, email, etc — non-hidden)
            for name in form.get("inputs", []):
                # Check if this param was already added with source "form"
                key = (form_page, name, "form")
                if key not in seen:
                    add_param(form_page, name, "form", method=form_method)
            
            # Hidden fields — only add if not already tracked
            # (We don't double-count hidden fields as params since they're
            # not user-controllable inputs in most attack scenarios)
            # for name in form.get("hidden_fields", {}).keys():
            #     key = (form_page, name, "hidden")
            #     if key not in seen:
            #         add_param(form_page, name, "hidden", method=form_method)

        return normalized

        return normalized

    @staticmethod
    def _collect_notable_endpoints(recon_data: dict) -> list:
        notable = []
        seen = set()

        def add_endpoint(url: str, category: str, source: str, method: str = "GET"):
            url = str(url or "").strip()
            if not url:
                return
            key = (url, category, source, method)
            if key in seen:
                return
            seen.add(key)
            notable.append({
                "url": url,
                "category": category,
                "source": source,
                "method": method,
            })

        for item in recon_data.get("notable_endpoints", []) or []:
            if isinstance(item, dict):
                add_endpoint(
                    item.get("url", ""),
                    item.get("category", "page"),
                    item.get("source", "crawl"),
                    item.get("method", "GET"),
                )

        attack_surface = recon_data.get("attack_surface", {}) or {}
        for url in attack_surface.get("auth_pages", []) or []:
            add_endpoint(url, "auth", "attack_surface")
        for url in attack_surface.get("upload_points", []) or []:
            add_endpoint(url, "upload", "attack_surface")
        for url in attack_surface.get("api_like_endpoints", []) or []:
            add_endpoint(url, "api", "attack_surface")
        for url in attack_surface.get("admin_pages", []) or []:
            add_endpoint(url, "admin", "attack_surface")
        for item in attack_surface.get("categorized_endpoints", []) or []:
            if isinstance(item, dict):
                add_endpoint(
                    item.get("url", ""),
                    item.get("category", "page"),
                    item.get("source", "attack_surface"),
                    item.get("method", "GET"),
                )

        return notable

    def build_phase1_output(self) -> dict:
        """Chuan hoa `recon_data` thanh schema cong khai cho Phase 3."""
        recon_data = self.get_recon_data()
        headers = dict(recon_data.get("http_headers", {}) or {})
        forms = self._normalize_forms(recon_data.get("forms", []))
        params = self._normalize_params(recon_data.get("params", {}), forms)
        notable_endpoints = self._collect_notable_endpoints(recon_data)
        limitations = list(dict.fromkeys(recon_data.get("limitations", []) or []))

        if not recon_data.get("nmap_available"):
            limitations.append("Nmap khong co san; ket qua ports co the den tu fallback socket.")
        if not forms and not recon_data.get("urls"):
            limitations.append("Crawler khong thu thap duoc URL/form noi bo trong lan chay nay.")

        summary = {
            "total_urls": len(recon_data.get("urls", []) or []),
            "total_forms": len(forms),
            "total_params": len(params),
            "limitations": list(dict.fromkeys(limitations)),
        }

        return {
            "target": self._ctx["target"],
            "recon": {
                "ip": recon_data.get("ip", ""),
                "status": recon_data.get("status", 0),
                "headers": headers,
                "server": recon_data.get("server") or headers.get("Server", ""),
                "technologies": list(dict.fromkeys(recon_data.get("technologies", []) or [])),
                "methods": list(dict.fromkeys(recon_data.get("http_methods", []) or [])),
                "ssl": recon_data.get("ssl_info", {}) or {},
                "ports": recon_data.get("open_ports", []) or [],
            },
            "crawl": {
                "urls": recon_data.get("urls", []) or [],
                "forms": forms,
                "params": params,
                "notable_endpoints": notable_endpoints,
            },
            "summary": summary,
        }

    def get_phase1_output(self) -> dict:
        """Alias ro nghia hon cho build_phase1_output()."""
        return self.build_phase1_output()

    def save_phase1_output(self, path: str = None) -> str:
        """Ghi output Phase 1 canonical ra JSON de ReportAgent va tool khac dung."""
        if path is None:
            data_dir = os.path.join(os.path.dirname(__file__), "data")
            os.makedirs(data_dir, exist_ok=True)
            path = os.path.join(data_dir, "phase1_recon.json")

        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.build_phase1_output(), f, ensure_ascii=False, indent=2)
        return path

    # ── Raw Findings (ScannerAgent output) ───────────────────────────────
    def set_raw_findings(self, findings: list) -> None:
        """ScannerAgent luu ket qua tho chua qua xu ly."""
        self._ctx["raw_findings"] = list(findings or [])

    def get_raw_findings(self) -> list:
        """Tra ve raw findings tu ScannerAgent."""
        return self._ctx["raw_findings"]

    # ── Normalized Findings (CorrelationAgent output) ─────────────────────
    def set_normalized_findings(self, findings: list) -> None:
        """CorrelationAgent luu findings da chuan hoa schema + OWASP/CWE map."""
        self._ctx["normalized_findings"] = list(findings or [])

    def get_normalized_findings(self) -> list:
        """Tra ve normalized findings tu CorrelationAgent."""
        return self._ctx["normalized_findings"]

    # ── Final Findings (RiskAssessmentAgent output) ───────────────────────
    def set_final_findings(self, findings: list) -> None:
        """
        RiskAssessmentAgent luu final findings (dedup + score + exploit_status).
        Dong thoi dong bo vao vulnerabilities de backward compat voi checkpoint.
        """
        self._ctx["final_findings"] = list(findings or [])
        # Sync vao vulnerabilities de report + checkpoint doc duoc
        self._ctx["vulnerabilities"] = []
        for v in (findings or []):
            self.add_vulnerability(v)

    def get_final_findings(self) -> list:
        """Tra ve final findings tu RiskAssessmentAgent."""
        return self._ctx["final_findings"]

    # ── Phase 2 Summary (RiskAssessmentAgent output) ──────────────────────
    def set_phase2_summary(self, summary: dict) -> None:
        """
        RiskAssessmentAgent luu tong ket Phase 2.

        Expected schema:
        {
          "total":                int,
          "by_severity":          {"CRITICAL": n, "HIGH": n, "MEDIUM": n, "LOW": n, "INFO": n},
          "confirmed_count":      int,
          "potential_count":      int,
          "unconfirmed_count":    int,
          "high_confidence_count": int,
          "deduped_count":        int,
          "top_findings":         [...],
          "scan_time":            "HH:MM:SS",
          "scanners_used":        ["VulnAgent", "ZAP", ...],
        }
        """
        self._ctx["phase2_summary"] = dict(summary or {})
        # Sync scan_time neu co
        if summary and summary.get("scan_time"):
            self._ctx["scan_time"] = summary["scan_time"]

    def get_phase2_summary(self) -> dict:
        """Tra ve phase2_summary tu RiskAssessmentAgent."""
        return self._ctx.get("phase2_summary", {})

    # Backward compatibility aliases (deprecated - use assessment_context)
    def set_recon(self, recon_result: dict) -> None:
        """DEPRECATED: Dung set_assessment_context() thay the."""
        self._ctx["assessment_context"].update(recon_result)

    def get_recon(self) -> dict:
        """DEPRECATED: Dung get_assessment_context() thay the."""
        return self._ctx["assessment_context"]

    def set_crawl(self, crawl_result: dict) -> None:
        """DEPRECATED: Dung set_crawl_data() thay the."""
        self.set_crawl_data(crawl_result)
        if "forms" in (crawl_result or {}):
            self._ctx["assessment_context"]["forms"] = crawl_result["forms"]

    def get_crawl(self) -> dict:
        """DEPRECATED: Tra ve crawl data tu recon_data."""
        return {
            "urls": self._ctx["recon_data"].get("urls", []),
            "forms": self._ctx["recon_data"].get("forms", []),
            "params": self._ctx["recon_data"].get("params", {}),
            "notable_endpoints": self._ctx["recon_data"].get("notable_endpoints", []),
        }

    # ── Vulnerabilities ───────────────────────────────────────────────

    # Fields bat buoc — phai co gia tri khac rong
    _REQUIRED_VULN_FIELDS = ("title", "severity", "description",
                             "recommendation", "category")
    # Fields nen co gia tri — luu warning neu rong de de debug
    _EXPECTED_NONEMPTY    = ("url", "evidence")
    _VALID_SEVERITIES     = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

    def add_vulnerability(self, vuln: dict) -> None:
        """
        Them mot lo hong vao memory voi validation.

        Fields bat buoc (phai co gia tri):
            title, severity, description, recommendation, category

        Fields nen co (warning neu rong, nhung van luu):
            url      — endpoint bi anh huong
            evidence — bang chung ky thuat cu the

        Fields tu dong dien neu chua co:
            cwe, owasp_id, owasp_name, confidence, severity_score,
            impact, prompt, reasoning, timestamp
            
        Backward compatibility:
            - "type" alias cho "category" (final_findings dung "type")
            - "cwe_name" alias cho "cwe" (neu chi co cwe_name)
        """
        if not isinstance(vuln, dict):
            return

        # ── Field aliasing for backward compatibility ──────────────────────
        # final_findings from RiskAssessmentAgent uses "type", not "category"
        if not vuln.get("category") and vuln.get("type"):
            vuln["category"] = vuln["type"]
        
        # Some findings may have cwe_name but not cwe
        if not vuln.get("cwe") and vuln.get("cwe_name"):
            vuln["cwe"] = vuln["cwe_name"]
        
        # Default description from title if missing
        if not vuln.get("description") and vuln.get("title"):
            vuln["description"] = vuln["title"]
        
        # Default recommendation if missing but we have category
        if not vuln.get("recommendation") and vuln.get("category"):
            vuln["recommendation"] = f"Review and remediate this {vuln['category']} issue."

        # Reject neu thieu bat ky field bat buoc nao
        for field in self._REQUIRED_VULN_FIELDS:
            if not vuln.get(field):
                return

        # Chuan hoa severity
        sev = str(vuln.get("severity", "INFO")).upper()
        if sev not in self._VALID_SEVERITIES:
            sev = "INFO"
        vuln["severity"] = sev

        import time as _t

        # Dien defaults cho optional fields (chi khi key chua ton tai)
        defaults = {
            "url":            "",
            "evidence":       "",
            "cwe":            "",
            "owasp_id":       "",
            "owasp_name":     "",
            "confidence":     0,
            "severity_score": 0,
            "impact":         "",
            "prompt":         "",
            "reasoning":      "",
            "timestamp":      _t.strftime("%H:%M:%S"),
        }
        for key, default in defaults.items():
            vuln.setdefault(key, default)

        # Ghi nhan warnings cho url/evidence rong — de debug, van luu vuln
        warnings = [
            f for f in self._EXPECTED_NONEMPTY if not vuln.get(f)
        ]
        if warnings:
            vuln["_incomplete"] = warnings  # flag de Phase 3 / bao cao biet

        self._ctx["vulnerabilities"].append(vuln)

    def set_vulnerabilities(self, vulns: list) -> None:
        """VulnAgent goi ham nay de luu toan bo danh sach lo hong."""
        self._ctx["vulnerabilities"] = []
        for v in (vulns or []):
            self.add_vulnerability(v)

    def get_vulnerabilities(self) -> list:
        """Tra ve danh sach lo hong day du."""
        return self._ctx["vulnerabilities"]

    def get_vulnerabilities_by_severity(self, severity: str) -> list:
        """
        Loc lo hong theo severity.
        Vi du: memory.get_vulnerabilities_by_severity("HIGH")
        """
        sev = severity.upper()
        return [v for v in self._ctx["vulnerabilities"]
                if v.get("severity") == sev]

    def get_summary(self) -> dict:
        """
        Tao summary nhanh cho Phase 3 / API response.

        Returns:
            {
              "total": int,
              "by_severity": {"CRITICAL": n, "HIGH": n, ...},
              "top_findings": [top 5 theo severity],
              "risk_score": int (tinh so bo)
            }
        """
        vulns = self._ctx["vulnerabilities"]
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        weights = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 3, "INFO": 0}

        by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns:
            s = v.get("severity", "INFO")
            if s in by_sev:
                by_sev[s] += 1

        # Risk score so bo (dung cong thuc day du trong ReportAgent)
        scores = sorted(
            [weights.get(v.get("severity", "INFO"), 0) for v in vulns],
            reverse=True
        )
        raw = scores[0] + sum(s / (1 + 0.3 * i)
                              for i, s in enumerate(scores[1:], 1)) * 0.4 if scores else 0
        quick_risk = int(min(round(raw), 100))

        top = sorted(vulns, key=lambda v: order.get(v.get("severity", "INFO"), 4))[:5]
        top_findings = [
            {
                "severity": v.get("severity"),
                "title":    v.get("title"),
                "category": v.get("category"),
                "cwe":      v.get("cwe"),
                "url":      v.get("url"),
            }
            for v in top
        ]

        return {
            "total":       len(vulns),
            "by_severity": by_sev,
            "top_findings": top_findings,
            "risk_score":  quick_risk,
        }

    # ── Risk Score ────────────────────────────────────────────────────
    def set_risk(self, score: int, label: str) -> None:
        """ReportAgent luu diem rui ro vao memory."""
        self._ctx["risk_score"] = score
        self._ctx["risk_label"] = label

    def get_risk_score(self) -> int:
        return self._ctx["risk_score"]

    def get_risk_label(self) -> str:
        return self._ctx["risk_label"]

    # ── Report path ───────────────────────────────────────────────────
    def set_report_path(self, path: str) -> None:
        self._ctx["report_path"] = path

    def get_report_path(self) -> str:
        return self._ctx.get("report_path", "")

    def set_pdf_path(self, path: str) -> None:
        self._ctx["pdf_path"] = path

    def get_pdf_path(self) -> str:
        return self._ctx.get("pdf_path", "")

    # ── Generic get/set ───────────────────────────────────────────────
    def get(self, key: str, default=None):
        return self._ctx.get(key, default)

    def set(self, key: str, value) -> None:
        self._ctx[key] = value

    # ── Snapshot / JSON export ────────────────────────────────────────
    def snapshot(self) -> dict:
        """Tra ve ban sao toan bo context (dung cho ReportAgent)."""
        return dict(self._ctx)

    def to_json(self, indent: int = 2) -> str:
        """Xuat memory ra chuoi JSON (de debug / log)."""
        return json.dumps(self._ctx, ensure_ascii=False, indent=indent)

    # ── Checkpoint: luu/doc ket qua Phase 1 + Phase 2 ra file ───────────────────
    def save_checkpoint(self, path: str = None) -> str:
        """
        Ghi ket qua Phase 1 (recon) + Phase 2 (vulns) ra file JSON.
        Goi sau khi pipeline hoan tat — Phase 3 co the doc lai neu can.

        Args:
            path: Duong dan file (mac dinh: data/vuln_checkpoint.json)
        Returns:
            Duong dan file da ghi.
        """
        if path is None:
            data_dir = os.path.join(os.path.dirname(__file__), "data")
            os.makedirs(data_dir, exist_ok=True)
            path = os.path.join(data_dir, "vuln_checkpoint.json")

        checkpoint = {
            "target":               self._ctx["target"],
            "scan_start_time":      self._ctx["scan_start_time"],
            "recon_data":           self._ctx["recon_data"],       # Phase 1
            "assessment_context":   self._ctx["assessment_context"],
            "raw_findings":         self._ctx["raw_findings"],
            "normalized_findings":  self._ctx["normalized_findings"],
            "final_findings":       self._ctx["final_findings"],
            "phase2_summary":       self._ctx["phase2_summary"],
            "vulnerabilities":      self._ctx["vulnerabilities"],
            "summary":              self.get_summary(),
            "saved_at":             time.strftime("%d/%m/%Y %H:%M:%S"),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(checkpoint, f, ensure_ascii=False, indent=2)
        return path

    def load_checkpoint(self, path: str = None) -> bool:
        """
        Doc lai ket qua Phase 1 + Phase 2 tu file checkpoint.
        Chi load neu vulnerabilities hien tai rong (tranh ghi de khi da co data).

        Args:
            path: Duong dan file (mac dinh: data/vuln_checkpoint.json)
        Returns:
            True neu load thanh cong, False neu khong co file hoac loi.
        """
        if path is None:
            path = os.path.join(os.path.dirname(__file__), "data", "vuln_checkpoint.json")

        if not os.path.isfile(path):
            return False

        # Chi load neu memory dang rong
        if self._ctx["vulnerabilities"]:
            return False

        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)

            # Chi nap neu cung target (tranh dung checkpoint cua target khac)
            if data.get("target") != self._ctx["target"]:
                return False

            # Restore recon_data (Phase 1) neu co
            if data.get("recon_data"):
                self._ctx["recon_data"].update(data["recon_data"])

            self._ctx["assessment_context"].update(
                data.get("assessment_context", {})
            )
            # Restore 3-layer data contract neu co
            if data.get("raw_findings"):
                self._ctx["raw_findings"] = data["raw_findings"]
            if data.get("normalized_findings"):
                self._ctx["normalized_findings"] = data["normalized_findings"]
            if data.get("final_findings"):
                self._ctx["final_findings"] = data["final_findings"]
            if data.get("phase2_summary"):
                self._ctx["phase2_summary"] = data["phase2_summary"]
            # Dung set_vulnerabilities() de chay validation
            self.set_vulnerabilities(data.get("vulnerabilities", []))
            return True

        except (json.JSONDecodeError, OSError):
            return False

    def __repr__(self) -> str:
        recon = self._ctx.get("recon_data", {})
        return (f"ScanMemory(target={self._ctx['target']!r}, "
                f"urls={len(recon.get('urls', []))}, "
                f"forms={len(recon.get('forms', []))})")
