"""
ReconAggregatorAgent — Phase 1c: Aggregate & Normalize

Doc passive_recon + active_recon tu ScanMemory, tong hop thanh JSON canonical
theo schema chuan cua do an, tinh summary, luu artifact.

JSON canonical schema:
{
  "target":      str,
  "timestamp":   str,
  "passive_recon": { domain, ip_addresses, whois, dns_records, ssl, technology },
  "active_recon":  { availability, headers, http_methods, ports, crawl, hidden_endpoints },
  "summary":       { total_urls, total_forms, total_params,
                     total_notable_endpoints, total_hidden_endpoints,
                     ssl_valid, nmap_used, ffuf_used, limitations }
}
"""
import json
import os
import time

from agents.base_agent import BaseAgent

_EMPTY_PASSIVE = {
    "domain": "",
    "ip_addresses": [],
    "whois": {},
    "dns_records": {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []},
    "subdomains": [],
    "ssl": {},
    "technology": {
        "server": "", "cms": "", "frameworks": [],
        "libraries": [], "security_headers": {}, "whatweb": [],
    },
    "theharvester":  {"emails": [], "hosts": [], "ips": [], "source": ""},
    "amass":         {"subdomains": [], "source": ""},
    "subfinder":     {"subdomains": [], "source": ""},
    "crtsh":         {"subdomains": [], "source": ""},
    "wayback":       {"urls": [], "source": ""},
    "shodan":        {"ports": [], "vulns": [], "hostnames": [], "source": ""},
    "google_dorks":  {"files": [], "pages": [], "exposed": [], "source": ""},
}

_EMPTY_ACTIVE = {
    "availability": {"http": False, "https": False, "status_code": None, "redirects": []},
    "headers": {},
    "http_methods": [],
    "ports": [],
    "waf":     {"detected": False, "name": "", "manufacturer": "", "source": ""},
    "banners": [],
    "syn_scan": {"ports": [], "source": ""},
    "crawl": {
        "urls": [], "forms": [], "params": [], "notable_endpoints": [],
        "js_endpoints": [], "hidden_fields": [],
    },
    "discovery": {"robots": {}, "sitemap_urls": []},
    "cookies_analysis": [],
    "hidden_endpoints": [],
    "tool_sources": {"nmap_tcp": "none", "syn_scan": "none", "ffuf": "none", "wafw00f": "none", "banner": "none"},
}


class ReconAggregatorAgent(BaseAgent):
    """Phase 1c — Tong hop passive + active recon, xuat JSON canonical."""

    PROMPT = (
        "[ReconAggregatorAgent] Aggregate passive + active recon, "
        "compute summary, save canonical Phase 1 JSON artifact."
    )

    def __init__(self, log_callback=None, memory=None, output_dir: str = "data"):
        super().__init__("ReconAggregatorAgent", log_callback, memory)
        self.output_dir = output_dir

    # ── Main ─────────────────────────────────────────────────────────────────
    def execute(self, target: str, context: dict) -> dict:
        if not self.memory:
            raise ValueError("ReconAggregatorAgent requires ScanMemory.")

        raw_passive = self.memory.get_passive_recon() or {}
        raw_active  = self.memory.get_active_recon()  or {}

        canonical = {
            "target":       target,
            "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%S"),
            "passive_recon": self._build_passive(raw_passive),
            "active_recon":  self._build_active(raw_active),
            "summary":       {},
        }
        canonical["summary"] = self._build_summary(
            canonical["passive_recon"],
            canonical["active_recon"],
            raw_passive=raw_passive,
        )

        # Save JSON artifact
        os.makedirs(self.output_dir, exist_ok=True)
        json_path = os.path.join(self.output_dir, "phase1_canonical.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(canonical, f, ensure_ascii=False, indent=2)
        self.log(f"Canonical JSON saved: {json_path}", "success")

        # Save to memory
        self.memory.set_canonical_phase1(canonical)
        self._sync_recon_data_compat(canonical)

        s = canonical["summary"]
        self.log(
            f"Summary: {s['total_urls']} URLs | {s['total_forms']} forms | "
            f"{s['total_params']} params | {s['total_notable_endpoints']} notable | "
            f"{s['total_hidden_endpoints']} hidden | {s['total_js_endpoints']} JS endpoints | "
            f"robots={s['total_discovered_from_robots']} sitemap={s['total_discovered_from_sitemap']}",
            "success",
        )
        return canonical

    # ── Build sub-sections ────────────────────────────────────────────────────

    def _build_passive(self, p: dict) -> dict:
        raw_tech = p.get("technology", {})
        technology = {
            "server":           raw_tech.get("server", ""),
            "cms":              raw_tech.get("cms", ""),
            "frameworks":       raw_tech.get("frameworks", []),
            "libraries":        raw_tech.get("libraries", []),
            "security_headers": raw_tech.get("security_headers", {}),
            "whatweb":          raw_tech.get("whatweb", []),
        }
        return {
            "domain":        p.get("domain", ""),
            "ip_addresses":  p.get("ip_addresses", []),
            "whois":         p.get("whois", {}),
            "dns_records":   p.get("dns_records", _EMPTY_PASSIVE["dns_records"]),
            "subdomains":    p.get("subdomains", []),
            "ssl":           p.get("ssl", {}),
            "technology":    technology,
            "theharvester":  p.get("theharvester",  _EMPTY_PASSIVE["theharvester"]),
            "amass":         p.get("amass",         _EMPTY_PASSIVE["amass"]),
            "subfinder":     p.get("subfinder",     _EMPTY_PASSIVE["subfinder"]),
            "crtsh":         p.get("crtsh",         _EMPTY_PASSIVE["crtsh"]),
            "wayback":       p.get("wayback",       _EMPTY_PASSIVE["wayback"]),
            "shodan":        p.get("shodan",        _EMPTY_PASSIVE["shodan"]),
            "google_dorks":  p.get("google_dorks",  _EMPTY_PASSIVE["google_dorks"]),
        }

    def _build_active(self, a: dict) -> dict:
        crawl = a.get("crawl", {})
        raw_avail = a.get("availability", _EMPTY_ACTIVE["availability"])
        avail = {
            "http":        raw_avail.get("http", False),
            "https":       raw_avail.get("https", False),
            "status_code": raw_avail.get("status_code"),
            "redirects":   raw_avail.get("redirects", []),
        }
        raw_disc = a.get("discovery", {})
        raw_waf = a.get("waf", _EMPTY_ACTIVE["waf"])
        return {
            "availability":     avail,
            "headers":          a.get("headers", {}),
            "http_methods":     a.get("http_methods", []),
            "ports":            a.get("ports", []),
            "waf": {
                "detected":     raw_waf.get("detected", False),
                "name":         raw_waf.get("name", ""),
                "manufacturer": raw_waf.get("manufacturer", ""),
                "source":       raw_waf.get("source", ""),
            },
            "banners":          a.get("banners", []),
            "syn_scan":         a.get("syn_scan", _EMPTY_ACTIVE["syn_scan"]),
            "crawl": {
                "urls":              crawl.get("urls", []),
                "forms":             crawl.get("forms", []),
                "params":            crawl.get("params", []),
                "notable_endpoints": crawl.get("notable_endpoints", []),
                "js_endpoints":      crawl.get("js_endpoints", []),
                "hidden_fields":     crawl.get("hidden_fields", []),
            },
            "discovery": {
                "robots":       raw_disc.get("robots", {}),
                "sitemap_urls": raw_disc.get("sitemap_urls", []),
            },
            "cookies_analysis": a.get("cookies_analysis", []),
            "hidden_endpoints": a.get("hidden_endpoints", []),
            "tool_sources":     a.get("tool_sources", _EMPTY_ACTIVE["tool_sources"]),
        }

    def _build_summary(self, passive: dict, active: dict, raw_passive: dict = None) -> dict:
        """
        raw_passive: the original PassiveReconAgent output dict (contains _meta fields).
        passive:     the already-normalized passive section of canonical (no _meta fields).
        """
        crawl   = active.get("crawl", {})
        notable = crawl.get("notable_endpoints", [])
        hidden  = active.get("hidden_endpoints", [])
        ports   = active.get("ports", [])
        raw     = raw_passive or {}

        is_local      = raw.get("_is_local", False)
        dns_source    = raw.get("_dns_source", "")      # "dnspython" | "socket_fallback" | ""
        whatweb_src   = raw.get("_whatweb_source", "")  # "kali_whatweb" | "not_available" | "skipped_localhost"

        limitations = []

        # --- localhost / private IP context note ---
        if is_local:
            limitations.append(
                "Target is localhost/private IP: WHOIS, public DNS records, "
                "and subdomain enumeration are not applicable."
            )

        # --- WHOIS ---
        whois = passive.get("whois", {})
        if whois.get("error") and not is_local:
            limitations.append(f"WHOIS: {whois['error']}")

        # --- DNS ---
        dns = passive.get("dns_records", {})
        has_dns_data = any(v for v in dns.values())
        if not has_dns_data:
            if dns_source == "socket_fallback":
                limitations.append(
                    "DNS: dnspython not installed — only A record attempted via socket fallback. "
                    "Install dnspython for full DNS record types."
                )
            elif is_local:
                pass  # already noted in context note above
            else:
                limitations.append("DNS: no records returned for this hostname.")

        # --- Subdomains ---
        if not passive.get("subdomains") and not is_local:
            # Only add if not already noted by local check
            pass  # Absence of subdomains is normal, not a limitation

        # --- SSL ---
        ssl = passive.get("ssl", {})
        if ssl.get("error") and not is_local:
            limitations.append(f"SSL: {ssl['error']}")
        elif ssl.get("error") and is_local:
            # For localhost, SSL error is expected — mention only if informative
            err = ssl.get("error", "")
            if "Port 443 not open" not in err and "No certificate" not in err:
                limitations.append(f"SSL: {err}")

        # --- Ports ---
        if not ports:
            limitations.append("Port scan: no open ports found (target may be behind a firewall)")

        # --- Crawl ---
        if not crawl.get("urls"):
            limitations.append("Crawl: no internal URLs collected — site may require authentication")

        # --- Tools (use tool_sources metadata from ActiveReconAgent) ---
        tool_src = active.get("tool_sources", {})
        nmap_src = tool_src.get("nmap_tcp", "")
        ffuf_src = tool_src.get("ffuf", "")
        # Fallback: infer from port/hidden source fields if metadata missing
        if not nmap_src:
            if any(p.get("source") in ("nmap", "kali_nmap") for p in ports):
                nmap_src = next((p["source"] for p in ports if "nmap" in p.get("source", "")), "nmap")
            elif ports:
                nmap_src = "socket"
        if not ffuf_src:
            if any(h.get("source") in ("ffuf", "kali_ffuf") for h in hidden):
                ffuf_src = next((h["source"] for h in hidden if "ffuf" in h.get("source", "")), "ffuf")
            elif hidden:
                ffuf_src = "probe"
        nmap_used = nmap_src in ("local_nmap", "kali_nmap", "nmap")
        ffuf_used = ffuf_src in ("local_ffuf", "kali_ffuf", "ffuf")

        if not nmap_used and ports:
            limitations.append("Port scan: nmap not available, socket probe used (less accurate)")
        if not ffuf_used:
            limitations.append("Hidden endpoint discovery: ffuf not available, HTTP HEAD probe used (limited wordlist)")

        ssl_valid = bool(
            ssl.get("subject") and
            ssl.get("days_remaining") is not None and
            ssl["days_remaining"] > 0
        )

        disc = active.get("discovery", {})
        robots = disc.get("robots", {})
        raw = raw_passive or {}
        return {
            "total_urls":                   len(crawl.get("urls", [])),
            "total_forms":                  len(crawl.get("forms", [])),
            "total_params":                 len(crawl.get("params", [])),
            "total_notable_endpoints":      len(notable),
            "total_hidden_endpoints":       len(hidden),
            "total_js_endpoints":           len(crawl.get("js_endpoints", [])),
            "total_hidden_fields":          len(crawl.get("hidden_fields", [])),
            "total_discovered_from_robots": len(robots.get("disallowed", [])),
            "total_discovered_from_sitemap": len(disc.get("sitemap_urls", [])),
            "total_subdomains":             len(passive.get("subdomains", [])),
            "total_emails":                 len(raw.get("theharvester", {}).get("emails", [])),
            "total_wayback_urls":           len(raw.get("wayback", {}).get("urls", [])),
            "total_crtsh_subdomains":       len(raw.get("crtsh", {}).get("subdomains", [])),
            "ssl_valid":                    ssl_valid,
            "nmap_used":                    nmap_used,
            "nmap_source":                  nmap_src or "none",
            "ffuf_used":                    ffuf_used,
            "ffuf_source":                  ffuf_src or "none",
            "whatweb_source":               whatweb_src or "none",
            "limitations":                  list(dict.fromkeys(limitations)),
        }

    def _sync_recon_data_compat(self, canonical: dict) -> None:
        """
        Dong bo canonical data vao memory.recon_data (legacy schema)
        de ReportAgent va backward-compat code van hoat dong.
        """
        passive = canonical["passive_recon"]
        active  = canonical["active_recon"]
        crawl   = active["crawl"]
        ports   = active["ports"]
        tech    = passive.get("technology", {})

        compat = {
            "host":             passive["domain"],
            "ip":               passive["ip_addresses"][0] if passive["ip_addresses"] else "",
            "status":           active["availability"].get("status_code") or 0,
            "open_ports":       ports,
            "nmap_available":   any(p.get("source") == "nmap" for p in ports),
            "source":           "nmap" if any(p.get("source") == "nmap" for p in ports) else "socket",
            "dns_records":      passive["dns_records"],
            "ssl_info":         passive["ssl"],
            "technologies":     tech.get("frameworks", []) + tech.get("libraries", []),
            "http_headers":     active["headers"],
            "http_methods":     active["http_methods"],
            "cookies":          [],
            "discovered_paths": [h.get("path", "") for h in active["hidden_endpoints"] if h.get("path")],
            "robots_txt":       {},
            "urls":             crawl["urls"],
            "forms":            crawl["forms"],
            "params":           {p["name"]: p.get("examples", []) for p in crawl["params"]},
            "notable_endpoints": crawl["notable_endpoints"],
            "limitations":      canonical["summary"].get("limitations", []),
            "attack_surface": {
                "entrypoints":           [e["url"] for e in crawl["notable_endpoints"]],
                "auth_pages":            [e["url"] for e in crawl["notable_endpoints"] if e["category"] == "login"],
                "upload_points":         [e["url"] for e in crawl["notable_endpoints"] if e["category"] == "upload"],
                "api_like_endpoints":    [e["url"] for e in crawl["notable_endpoints"] if e["category"] == "api"],
                "admin_pages":           [e["url"] for e in crawl["notable_endpoints"] if e["category"] == "admin"],
                "categorized_endpoints": crawl["notable_endpoints"],
            },
        }
        self.memory.set_recon_data(compat)
