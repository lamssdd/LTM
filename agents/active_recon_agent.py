"""
ActiveReconAgent — Phase 1b: Active Reconnaissance

Thu thap thong tin bang cach gui request toi muc tieu:
- HTTP/HTTPS availability check
- Response headers + cookie flags analysis
- HTTP methods discovery (OPTIONS-first, tranh false positive)
- Port scan (nmap uu tien, socket fallback)
- robots.txt / sitemap.xml discovery
- Website crawl: URLs, forms, params, notable endpoints, JS endpoints
- Hidden endpoint discovery (ffuf neu co, HTTP probe fallback)
- Authenticated crawl (neu user cung cap cookies/headers)

Khong test payload, khong SQLi/XSS, khong bruteforce.
"""
import concurrent.futures
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import tempfile
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qs

import requests
import requests.packages.urllib3
from bs4 import BeautifulSoup
requests.packages.urllib3.disable_warnings()

from agents.base_agent import BaseAgent
from utils import make_session, build_tool_config, is_localhost_target

# ── Crawl limits (defaults — overridable via tool_config["crawl"]) ───────────
MAX_CRAWL_URLS   = 120
MAX_CRAWL_DEPTH  = 3
CRAWL_WORKERS    = 8

# ── Skip extensions (binary / media / style files) ───────────────────────────
SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".mp4", ".mp3", ".avi", ".pdf", ".zip", ".rar", ".gz",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".map", ".exe",
}

# ── Notable endpoint patterns ─────────────────────────────────────────────────
NOTABLE_PATTERNS = {
    "login":  re.compile(r"/(login|signin|sign[-_]in|auth|oauth|sso|token|session)", re.I),
    "admin":  re.compile(r"/(admin|administrator|dashboard|panel|cp|controlpanel|backend|manage)", re.I),
    "upload": re.compile(r"/(upload|uploads|files?|media|attachment|avatar|photo|image)", re.I),
    "api":    re.compile(r"/(api|rest|graphql|service|v\d+)/", re.I),
    "search": re.compile(r"/(search|find|query|lookup)", re.I),
}

# ── Web ports to scan ─────────────────────────────────────────────────────────
SCAN_PORTS = [21, 22, 80, 443, 3000, 3306, 5000, 5432, 8000, 8080, 8443, 27017]

# ── Common hidden paths for probe/ffuf ───────────────────────────────────────
COMMON_HIDDEN = [
    "admin", "admin/", "admin.php", "administrator/",
    "dashboard/", "panel/", "cp/", "console/", "manage/", "manager/",
    "login", "login.php", "logout", "register", "signup",
    "api/", "api/v1/", "api/v2/", "api/v3/", "graphql", "graphiql",
    "upload", "uploads/", "files/", "media/", "assets/",
    "config.php", "phpinfo.php", "info.php", "test.php",
    ".env", ".git/HEAD", ".htaccess", ".gitignore",
    "phpmyadmin/", "phpmyadmin",
    "backup/", "backup.zip", "backup.sql", "db.sql",
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "wp-admin/", "wp-login.php", "wp-config.php",
    "server-status", "server-info", "actuator/health", "actuator/",
    "test/", "tmp/", "temp/", "cache/",
    "docs/", "swagger/", "swagger-ui/", "openapi.json", "api-docs/",
    "status/", "health/", "healthcheck", "ping",
]

# ── JS endpoint heuristic patterns ────────────────────────────────────────────
_JS_EP_PATTERNS = [
    re.compile(r'''(?:fetch|axios\.(?:get|post|put|delete|patch)|axios)\s*\(\s*['"]([/][^'"<>\s]{2,100})['"]''', re.I),
    re.compile(r'''\.open\s*\(['"]\w+['"]\s*,\s*['"]([/][^'"<>\s]{2,100})['"]''', re.I),
    re.compile(r'''['"]([/](?:api|graphql|rest|v\d+)[^'"<>\s]{0,80})['"]''', re.I),
    re.compile(r'''url\s*[:=]\s*['"]([/][^'"<>\s]{3,80})['"]''', re.I),
]

TIMEOUT = (5, 10)


class ActiveReconAgent(BaseAgent):
    """Phase 1b — HTTP availability, port scan, crawl, endpoint discovery."""

    PROMPT = (
        "[ActiveReconAgent] HTTP/HTTPS availability, response headers, "
        "safe HTTP methods check, port scan, crawl (URLs/forms/params), "
        "notable endpoint classification, hidden endpoint probe."
    )

    def __init__(self, log_callback=None, memory=None, tool_config: dict = None):
        super().__init__("ActiveReconAgent", log_callback, memory)
        self._tool_config = tool_config or build_tool_config()
        self._ssh = None  # KaliSSHClient — lazy init
        # auth config: {"cookies": {}, "extra_headers": {}}
        self._auth_cfg  = self._tool_config.get("auth", {})
        # crawl config: {"max_pages": int, "max_depth": int, "workers": int}
        self._crawl_cfg = self._tool_config.get("crawl", {})

    # ── Main ─────────────────────────────────────────────────────────────────
    def execute(self, target: str, context: dict) -> dict:
        from utils import normalize_url
        base_url = normalize_url(target)
        parsed   = urlparse(base_url)
        hostname = parsed.hostname or ""
        site_root = f"{parsed.scheme}://{parsed.netloc}"

        mode = self._tool_config.get("mode", "auto")

        # ── Build session (with optional auth cookies/headers) ────────────────
        session = make_session(base_url)
        auth_cookies = self._auth_cfg.get("cookies", {})
        auth_headers = self._auth_cfg.get("extra_headers", {})
        if auth_cookies:
            session.cookies.update(auth_cookies)
        if auth_headers:
            session.headers.update(auth_headers)
        auth_used = bool(auth_cookies or auth_headers)

        # ── Crawl config ──────────────────────────────────────────────────────
        max_pages = int(self._crawl_cfg.get("max_pages", MAX_CRAWL_URLS))
        max_depth = int(self._crawl_cfg.get("max_depth", MAX_CRAWL_DEPTH))
        workers   = int(self._crawl_cfg.get("workers",   CRAWL_WORKERS))

        # ── Log config summary ────────────────────────────────────────────────
        self.log("═══ ActiveReconAgent Config ═══", "info")
        self.log(f"  Tool mode: {mode}", "info")
        self.log(f"  Target: {base_url}", "info")
        self.log(f"  Hostname: {hostname}", "info")
        self.log(f"  Auth session: {'yes (user-provided cookies/headers)' if auth_used else 'no'}", "info")
        self.log(f"  Crawl: max_pages={max_pages} max_depth={max_depth} workers={workers}", "info")
        if mode in ("kali_ssh", "auto"):
            kali_host = self._tool_config.get("kali_host", "")
            kali_user = self._tool_config.get("kali_user", "")
            if kali_host and kali_user:
                self.log(f"  Kali SSH configured: {kali_user}@{kali_host}", "info")
        local_nmap = shutil.which("nmap")
        local_ffuf = shutil.which("ffuf")
        self.log(f"  Local nmap: {'found' if local_nmap else 'not found'}", "info")
        self.log(f"  Local ffuf: {'found' if local_ffuf else 'not found'}", "info")
        self.log("═══════════════════════════════", "info")

        result = {
            "availability":  {"http": False, "https": False, "status_code": None, "redirects": []},
            "headers":       {},
            "http_methods":  [],
            "ports":         [],
            "syn_scan":      {"ports": [], "source": ""},
            "banners":       [],
            "waf":           {"detected": False, "name": "", "manufacturer": "", "source": ""},
            "crawl": {
                "urls":              [],
                "forms":             [],
                "params":            [],
                "notable_endpoints": [],
                "js_endpoints":      [],
                "hidden_fields":     [],
            },
            "discovery": {
                "robots":       {},
                "sitemap_urls": [],
            },
            "cookies_analysis": [],
            "hidden_endpoints": [],
            "tool_sources": {"nmap_tcp": "none", "syn_scan": "none", "ffuf": "none", "wafw00f": "none", "banner": "none"},
        }

        # Lay ToolTracker tu tool_config (optional)
        tracker = (self._tool_config or {}).get("tool_tracker")

        # 1. HTTP Checker — Availability + Headers + Cookies
        if tracker: tracker.start("http_probe")
        self.log("Checking HTTP/HTTPS availability...")
        result["availability"] = self._check_availability(base_url, hostname)
        avail = result["availability"]
        self.log(
            f"http={avail['http']} | https={avail['https']} | status={avail['status_code']}",
            "success" if avail.get("status_code") else "warning",
        )
        self.log("Collecting response headers...")
        result["headers"] = self._get_headers(session, base_url)
        self.log(f"Collected {len(result['headers'])} response headers", "info")
        result["cookies_analysis"] = self._analyze_cookies(result["headers"])
        if result["cookies_analysis"]:
            self.log(f"Cookie flags analyzed: {len(result['cookies_analysis'])} cookie(s)", "info")
        if tracker: tracker.done("http_probe",
            summary=f"HTTP:{avail['http']} HTTPS:{avail['https']} | {len(result['headers'])} headers | {len(result['cookies_analysis'])} cookies",
            result=avail)

        # 3. HTTP methods (OPTIONS-first, safe)
        if tracker: tracker.start("http_methods")
        self.log("Probing HTTP methods (OPTIONS-first)...")
        result["http_methods"] = self._check_http_methods(session, base_url)
        if result["http_methods"]:
            self.log(f"Dangerous methods found: {result['http_methods']}", "warning")
            if tracker: tracker.done("http_methods",
                summary=f"Dangerous: {', '.join(result['http_methods'])}",
                result={"methods": result["http_methods"]})
        else:
            self.log("No dangerous HTTP methods detected", "info")
            if tracker: tracker.done("http_methods",
                summary="No dangerous methods detected",
                result={"methods": []})

        # 4. nmap TCP — Port scan
        if tracker: tracker.start("nmap_tcp")
        self.log("Port scan (nmap if available, else socket)...")
        result["ports"], nmap_src = self._scan_ports(hostname)
        result["tool_sources"]["nmap_tcp"] = nmap_src
        self.log(f"Open ports: {len(result['ports'])} (source={nmap_src})", "success")
        if tracker: tracker.done("nmap_tcp",
            summary=f"{len(result['ports'])} open ports (source={nmap_src})",
            result={"ports": result["ports"], "source": nmap_src})

        # 4b. WAF Detection (wafw00f via Kali SSH)
        if tracker: tracker.start("wafw00f")
        self.log("WAF detection (wafw00f via Kali SSH)...")
        result["waf"], waf_src = self._run_wafw00f(base_url)
        result["tool_sources"]["wafw00f"] = waf_src
        if result["waf"]["detected"]:
            self.log(
                f"WAF detected: {result['waf']['name']} ({result['waf']['manufacturer']})",
                "warning",
            )
            if tracker: tracker.done("wafw00f",
                summary=f"WAF: {result['waf']['name']} ({result['waf']['manufacturer']})",
                result=result["waf"])
        else:
            self.log(f"No WAF detected (source={waf_src})", "info")
            if tracker: tracker.done("wafw00f",
                summary=f"No WAF detected ({waf_src})",
                result=result["waf"])

        # 4c. Banner Grabbing (Python socket)
        if tracker: tracker.start("banner_grab")
        if result["ports"]:
            self.log("Banner grabbing on open ports...")
            result["banners"], banner_src = self._grab_banners(hostname, result["ports"])
            result["tool_sources"]["banner"] = banner_src
            if result["banners"]:
                self.log(f"Banner grabbing: {len(result['banners'])} banners captured", "success")
                if tracker: tracker.done("banner_grab",
                    summary=f"{len(result['banners'])} banners captured",
                    result={"banners": result["banners"]})
            else:
                self.log("Banner grabbing: no banners captured", "info")
                if tracker: tracker.done("banner_grab", summary="No banners captured")
        else:
            result["tool_sources"]["banner"] = "skipped_no_ports"
            if tracker: tracker.done("banner_grab", summary="Skipped — no open ports")

        # 4d. TCP SYN Scanner (Scapy)
        if tracker: tracker.start("syn_scan")
        self.log("TCP SYN scan (Scapy-based stealth scan)...")
        syn_result, syn_src = self._run_syn_scan(hostname)
        result["syn_scan"] = syn_result
        result["tool_sources"]["syn_scan"] = syn_src
        if syn_result.get("ports"):
            self.log(f"SYN scan: {len(syn_result['ports'])} ports detected (source={syn_src})", "success")
            if tracker: tracker.done("syn_scan",
                summary=f"{len(syn_result['ports'])} ports (source={syn_src})",
                result=syn_result)
        else:
            self.log(f"SYN scan: no results (source={syn_src})", "info")
            if tracker: tracker.done("syn_scan",
                summary=f"No results (source={syn_src})",
                result=syn_result)

        # 5. robots.txt + sitemap discovery
        if tracker: tracker.start("robots")
        self.log("Fetching robots.txt...")
        robots = self._fetch_robots(session, site_root)
        result["discovery"]["robots"] = robots
        if robots.get("status") == 200:
            self.log(
                f"robots.txt: {len(robots['disallowed'])} disallowed | "
                f"{len(robots['allowed'])} allowed | {len(robots['sitemaps'])} sitemaps",
                "success",
            )
        else:
            self.log("robots.txt: not found or unavailable", "info")

        self.log("Fetching sitemap.xml...")
        sitemap_urls = self._fetch_sitemap(session, site_root, robots.get("sitemaps", []))
        result["discovery"]["sitemap_urls"] = sitemap_urls
        if sitemap_urls:
            self.log(f"Sitemap: {len(sitemap_urls)} URLs discovered", "success")
        else:
            self.log("Sitemap: not found or empty", "info")
        if tracker: tracker.done("robots",
            summary=f"robots:{robots.get('status','?')} | sitemap:{len(sitemap_urls)} URLs",
            result=result["discovery"])

        # 6. Crawl
        if tracker: tracker.start("crawl")
        self.log(f"Crawling site (depth={max_depth}, max={max_pages} pages)...")
        result["crawl"] = self._crawl_site(
            session, base_url,
            max_pages=max_pages, max_depth=max_depth, workers=workers,
        )
        crawl = result["crawl"]
        self.log(
            f"Crawl: {len(crawl['urls'])} URLs | {len(crawl['forms'])} forms | "
            f"{len(crawl['params'])} params | {len(crawl['notable_endpoints'])} notable | "
            f"{len(crawl['js_endpoints'])} JS endpoints | {len(crawl['hidden_fields'])} hidden fields",
            "success",
        )
        if tracker: tracker.done("crawl",
            summary=f"{len(crawl['urls'])} URLs | {len(crawl['forms'])} forms | "
                    f"{len(crawl['notable_endpoints'])} notable | {len(crawl['js_endpoints'])} JS endpoints",
            result={"url_count": len(crawl["urls"]), "form_count": len(crawl["forms"]),
                    "param_count": len(crawl["params"]),
                    "notable_count": len(crawl["notable_endpoints"])})

        # 7. Hidden endpoint discovery
        if tracker: tracker.start("ffuf")
        self.log("Discovering hidden endpoints...")
        result["hidden_endpoints"], ffuf_src = self._discover_hidden(base_url, session)
        result["tool_sources"]["ffuf"] = ffuf_src
        self.log(
            f"Hidden endpoints: {len(result['hidden_endpoints'])} (source={ffuf_src})",
            "success" if result["hidden_endpoints"] else "info",
        )
        if tracker: tracker.done("ffuf",
            summary=f"{len(result['hidden_endpoints'])} hidden endpoints (source={ffuf_src})",
            result={"hidden_endpoints": result["hidden_endpoints"], "source": ffuf_src})

        if self.memory:
            self.memory.set_active_recon(result)
            self.log("Saved active recon to memory.", "info")

        if self._ssh:
            self._ssh.close()
            self._ssh = None

        return result

    # ── Availability ──────────────────────────────────────────────────────────

    def _check_availability(self, base_url: str, hostname: str) -> dict:
        avail = {"http": False, "https": False, "status_code": None, "redirects": []}
        for scheme in ("http", "https"):
            url = f"{scheme}://{hostname}"
            try:
                r = requests.get(url, timeout=(5, 8), verify=False, allow_redirects=True)
                avail[scheme] = True
                if avail["status_code"] is None:
                    avail["status_code"] = r.status_code
            except Exception:
                pass
        # Final status + redirect chain from original URL
        try:
            r = requests.get(base_url, timeout=(5, 8), verify=False, allow_redirects=True)
            avail["status_code"] = r.status_code
            redirects = []
            for resp in r.history:
                redirects.append({
                    "from":        resp.url,
                    "to":          resp.headers.get("Location", ""),
                    "status_code": resp.status_code,
                })
            avail["redirects"] = redirects
        except Exception:
            pass
        return avail

    # ── Headers ───────────────────────────────────────────────────────────────

    def _get_headers(self, session, base_url: str) -> dict:
        IMPORTANT = [
            "Server", "X-Powered-By", "Content-Type",
            "X-Frame-Options", "Strict-Transport-Security",
            "Content-Security-Policy", "X-Content-Type-Options",
            "Referrer-Policy", "Permissions-Policy",
            "Access-Control-Allow-Origin", "X-XSS-Protection",
            "Set-Cookie", "Cache-Control", "X-Request-ID",
        ]
        try:
            resp = session.get(base_url, timeout=TIMEOUT, verify=False, allow_redirects=True)
            return {h: resp.headers[h] for h in IMPORTANT if h in resp.headers}
        except Exception as e:
            self.log(f"Headers error: {e}", "warning")
            return {}

    # ── HTTP Methods (safe, OPTIONS-first) ────────────────────────────────────

    def _check_http_methods(self, session, base_url: str) -> list:
        """
        Dung OPTIONS de lay Allow header.
        Chi flag TRACE, PUT, DELETE, PATCH la nguy hiem.
        Tranh kiem tra tung method rieng le (de bi false positive voi catch-all handlers).
        """
        DANGEROUS = {"TRACE", "PUT", "DELETE", "PATCH"}
        dangerous = []
        try:
            # Method 1: OPTIONS — most reliable
            resp = session.options(base_url, timeout=(5, 8), verify=False)
            allow = resp.headers.get("Allow", "")
            if allow:
                for m in DANGEROUS:
                    if m in allow.upper():
                        dangerous.append(m)
                return dangerous  # Trust Allow header

            # Method 2: If OPTIONS returns no Allow, probe TRACE only (hardest to fake)
            r = session.request("TRACE", base_url, timeout=(5, 8), verify=False)
            if r.status_code == 200 and "TRACE" not in dangerous:
                dangerous.append("TRACE")
        except Exception:
            pass
        return dangerous

    # ── SSH helper ────────────────────────────────────────────────────────────

    def _get_ssh(self):
        """Lazy-init KaliSSHClient from tool_config. Returns connected client or None."""
        if self._ssh is not None:
            return self._ssh
        from tools.kali_ssh_client import KaliSSHClient
        cfg = self._tool_config
        ssh = KaliSSHClient(
            host=cfg.get("kali_host", ""),
            port=cfg.get("kali_port", 22),
            user=cfg.get("kali_user", ""),
            password=cfg.get("kali_pass", ""),
            key_path=cfg.get("kali_key_path", ""),
            connect_timeout=cfg.get("kali_timeout", 10),
            log_callback=self.log,
        )
        if ssh.connect():
            self._ssh = ssh
        return self._ssh if self._ssh else None

    # ── Port Scan ─────────────────────────────────────────────────────────────

    def _scan_ports(self, hostname: str) -> tuple:
        """Returns (ports_list, source_string)."""
        mode = self._tool_config.get("mode", "auto")
        is_local = is_localhost_target(hostname)

        # Log mode and target context
        self.log(
            f"Port scan mode: {mode} | target: {hostname} "
            f"({'localhost' if is_local else 'remote'})",
            "info"
        )

        # ── Localhost + kali_ssh validation ───────────────────────────────────
        if is_local and mode == "kali_ssh":
            self.log(
                f"WARNING: Target '{hostname}' is localhost but mode is 'kali_ssh'. "
                f"This would scan Kali's localhost, not your intended target. "
                f"Falling back to local/socket scan.",
                "warning"
            )
            # Force local scan for localhost targets in kali_ssh mode
            mode = "local"

        # ── local nmap ────────────────────────────────────────────────────────
        if mode in ("local", "auto"):
            nmap_bin = shutil.which("nmap")
            if nmap_bin:
                self.log("Port scan: using local nmap", "info")
                ports = self._scan_nmap(nmap_bin, hostname)
                if ports:
                    return ports, "local_nmap"
                self.log("Local nmap returned no results", "info")
            else:
                self.log("Local nmap not found", "info")

        # ── kali nmap ─────────────────────────────────────────────────────────
        if mode in ("kali_ssh", "auto") and not is_local:
            ssh = self._get_ssh()
            if ssh:
                self.log(f"Kali SSH connected: {ssh.user}@{ssh.host}:{ssh.port}", "success")
                kali_nmap = ssh.which("nmap")
                if kali_nmap:
                    self.log(f"Port scan: using Kali nmap ({ssh.host})", "info")
                    ports = self._scan_nmap_kali(ssh, kali_nmap, hostname)
                    if ports:
                        return ports, "kali_nmap"
                    self.log("Kali nmap returned no results", "info")
                else:
                    self.log("nmap not found on Kali", "warning")
            elif mode == "kali_ssh":
                self.log("kali_ssh mode but SSH unavailable — falling back to socket", "warning")

        # ── socket fallback ───────────────────────────────────────────────────
        self.log("Port scan: using socket probe fallback", "info")
        return self._scan_socket(hostname), "socket"

    def _scan_nmap(self, nmap_bin: str, hostname: str) -> list:
        ports_str = ",".join(str(p) for p in SCAN_PORTS)
        try:
            proc = subprocess.run(
                [nmap_bin, "-Pn", "-T4", "--open", f"-p{ports_str}", hostname],
                capture_output=True, text=True, timeout=30,
            )
            ports = []
            for line in proc.stdout.split("\n"):
                m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line.strip())
                if m:
                    ports.append({
                        "port":    int(m.group(1)),
                        "service": m.group(2),
                        "version": m.group(3).strip(),
                        "source":  "nmap",
                    })
            return ports
        except Exception as e:
            self.log(f"Nmap error: {e}", "warning")
            return []

    def _scan_socket(self, hostname: str) -> list:
        SVC = {
            21: "ftp", 22: "ssh", 80: "http", 443: "https",
            3000: "node", 3306: "mysql", 5000: "flask", 5432: "postgres",
            8000: "dev", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
        }
        open_ports = []

        def probe(port):
            try:
                with socket.create_connection((hostname, port), timeout=1.5):
                    return port
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            futures = {pool.submit(probe, port): port for port in SCAN_PORTS}
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append({
                            "port":    port,
                            "service": SVC.get(port, "unknown"),
                            "version": "",
                            "source":  "socket",
                        })
                except Exception:
                    pass
        open_ports.sort(key=lambda x: x["port"])
        return open_ports

    def _scan_nmap_kali(self, ssh, nmap_bin: str, hostname: str) -> list:
        """Run nmap on Kali via SSH. Same output format as _scan_nmap."""
        ports_str = ",".join(str(p) for p in SCAN_PORTS)
        cmd = f"{nmap_bin} -Pn -T4 --open -p{ports_str} {shlex.quote(hostname)}"
        self.log(f"Kali nmap: {cmd}", "info")
        out, err, rc = ssh.run(cmd, timeout=45)
        if rc != 0 and not out:
            self.log(f"Kali nmap error: {err.strip()[:120]}", "warning")
            return []
        ports = []
        for line in out.split("\n"):
            m = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line.strip())
            if m:
                ports.append({
                    "port":    int(m.group(1)),
                    "service": m.group(2),
                    "version": m.group(3).strip(),
                    "source":  "kali_nmap",
                })
        return ports

    # ── Banner Grabbing (Python socket) ───────────────────────────────────────

    def _grab_banners(self, hostname: str, ports: list) -> tuple:
        """Grab service banners from open ports using raw socket connections.

        Returns: (banners_list, source_string)
        banners_list: [{"port": int, "banner": str, "service": str}, ...]
        """
        banners = []

        # Common banner-grabbing probes for different services
        PROBES = {
            21:   b"",                           # FTP - server sends banner first
            22:   b"",                           # SSH - server sends banner first
            25:   b"EHLO scanner\r\n",           # SMTP
            80:   b"HEAD / HTTP/1.0\r\n\r\n",    # HTTP
            110:  b"",                           # POP3 - server sends banner first
            143:  b"",                           # IMAP - server sends banner first
            443:  b"",                           # HTTPS - needs SSL, skip raw socket
            3306: b"",                           # MySQL - server sends banner first
            3389: b"",                           # RDP
            5432: b"",                           # PostgreSQL
            6379: b"INFO\r\n",                   # Redis
            8080: b"HEAD / HTTP/1.0\r\n\r\n",    # HTTP alt
            8443: b"",                           # HTTPS alt - needs SSL
            27017: b"",                          # MongoDB
        }

        def grab_single(port_info):
            port = port_info["port"]
            service = port_info.get("service", "unknown")

            # Skip SSL/TLS ports - they need special handling
            if port in (443, 8443):
                return None

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((hostname, port))

                # Send probe if we have one
                probe = PROBES.get(port, b"")
                if probe:
                    sock.send(probe)

                # Receive banner
                banner = sock.recv(1024)
                sock.close()

                if banner:
                    # Decode and clean up banner
                    try:
                        banner_str = banner.decode('utf-8', errors='replace').strip()
                    except:
                        banner_str = banner.decode('latin-1', errors='replace').strip()

                    # Truncate long banners
                    if len(banner_str) > 500:
                        banner_str = banner_str[:500] + "..."

                    return {
                        "port": port,
                        "service": service,
                        "banner": banner_str,
                    }
            except socket.timeout:
                pass
            except ConnectionRefusedError:
                pass
            except Exception as e:
                self.log(f"Banner grab error on port {port}: {e}", "warning")

            return None

        # Grab banners in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            futures = {pool.submit(grab_single, p): p for p in ports}
            for future in concurrent.futures.as_completed(futures, timeout=30):
                try:
                    result = future.result()
                    if result:
                        banners.append(result)
                except Exception:
                    pass

        return banners, "socket" if banners else "no_banners"

    # ── WAF Detection (wafw00f via Kali SSH) ──────────────────────────────────

    def _run_wafw00f(self, target_url: str) -> tuple:
        """Run wafw00f via Kali SSH to detect Web Application Firewall.

        Returns: (waf_dict, source_string)
        waf_dict: {"detected": bool, "name": str, "manufacturer": str, "source": str}
        """
        waf_result = {"detected": False, "name": "", "manufacturer": "", "source": "not_available"}

        mode = self._tool_config.get("mode", "auto")
        is_local = is_localhost_target(target_url)

        # Skip for localhost targets
        if is_local:
            waf_result["source"] = "skipped_localhost"
            return waf_result, "skipped_localhost"

        # Try Kali SSH first
        if mode in ("kali_ssh", "auto"):
            ssh = self._get_ssh()
            if ssh:
                wafw00f_bin = ssh.which("wafw00f")
                if not wafw00f_bin:
                    self.log("wafw00f not found on Kali", "info")
                else:
                    # Run wafw00f (text output mode for reliable parsing)
                    cmd = f"{wafw00f_bin} {shlex.quote(target_url)} 2>&1"
                    self.log(f"Kali wafw00f: {target_url}", "info")
                    out, err, rc = ssh.run(cmd, timeout=60)

                    if out.strip():
                        waf_result = self._parse_wafw00f_output(out)
                        waf_result["source"] = "kali_wafw00f"
                        return waf_result, "kali_wafw00f"

        # Try local wafw00f
        local_wafw00f = shutil.which("wafw00f")
        if local_wafw00f:
            try:
                proc = subprocess.run(
                    [local_wafw00f, target_url],
                    capture_output=True, text=True, timeout=45,
                )
                output = proc.stdout + proc.stderr
                if output.strip():
                    waf_result = self._parse_wafw00f_output(output)
                    waf_result["source"] = "local_wafw00f"
                    return waf_result, "local_wafw00f"
            except Exception as e:
                self.log(f"Local wafw00f error: {e}", "warning")

        return waf_result, "not_available"

    def _parse_wafw00f_output(self, output: str) -> dict:
        """Parse wafw00f output to extract WAF information."""
        result = {"detected": False, "name": "", "manufacturer": "", "source": ""}

        # Strip ANSI color codes first
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        output = ansi_escape.sub('', output)

        lines = output.strip().splitlines()

        for line in lines:
            line_lower = line.lower()

            # Check for WAF detection patterns
            # Pattern: "The site https://example.com is behind Cloudflare (Cloudflare Inc.) WAF"
            if "is behind" in line_lower and "waf" in line_lower:
                result["detected"] = True
                # Extract WAF name and manufacturer
                match = re.search(r"is behind\s+(.+?)\s*\(([^)]+)\)\s*waf", line, re.I)
                if match:
                    result["name"] = match.group(1).strip()
                    result["manufacturer"] = match.group(2).strip()
                else:
                    # Try without manufacturer
                    match = re.search(r"is behind\s+(.+?)\s*waf", line, re.I)
                    if match:
                        result["name"] = match.group(1).strip()
                break

            # Pattern: "No WAF detected"
            elif "no waf" in line_lower or "is not behind" in line_lower:
                result["detected"] = False
                break

            # JSON output pattern (if -o json was used)
            elif line.strip().startswith("{"):
                try:
                    import json
                    data = json.loads(line.strip())
                    if data.get("firewall"):
                        result["detected"] = True
                        result["name"] = data.get("firewall", "")
                        result["manufacturer"] = data.get("manufacturer", "")
                except:
                    pass

        return result

    # ── Crawl ─────────────────────────────────────────────────────────────────

    def _crawl_site(self, session, base_url: str,
                    max_pages: int = MAX_CRAWL_URLS,
                    max_depth: int = MAX_CRAWL_DEPTH,
                    workers:   int = CRAWL_WORKERS) -> dict:
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc

        visited        = set()
        queue          = deque([(base_url, 0)])
        all_urls       = []
        all_forms      = []
        seen_forms     = set()
        all_params     = []
        seen_params    = set()
        notable        = []
        seen_notable   = set()
        all_js_eps     = []
        seen_js_eps    = set()
        all_hidden_fld = []
        seen_hf        = set()   # (action, name)

        while queue and len(visited) < max_pages:
            batch = []
            while queue and len(batch) < workers:
                url, depth = queue.popleft()
                norm = url.split("?")[0].rstrip("/").lower()
                if norm in visited:
                    continue
                visited.add(norm)
                batch.append((url, depth))

            if not batch:
                continue

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(self._fetch_page, session, url): (url, depth)
                    for url, depth in batch
                }
                for fut in concurrent.futures.as_completed(futures):
                    url, depth = futures[fut]
                    page = fut.result()
                    if page is None:
                        continue

                    all_urls.append(url)

                    # Notable endpoint check on URL itself
                    for cat, pat in NOTABLE_PATTERNS.items():
                        if pat.search(url) and url not in seen_notable:
                            notable.append({"url": url, "category": cat, "source": "crawl", "method": "GET"})
                            seen_notable.add(url)
                            break

                    # URL query params (including from redirect URLs)
                    pu = urlparse(url)
                    if pu.query:
                        for name, vals in parse_qs(pu.query).items():
                            key = (pu.path, name)
                            if key not in seen_params:
                                seen_params.add(key)
                                all_params.append({
                                    "page":     url.split("?")[0],
                                    "name":     name,
                                    "source":   "url",
                                    "examples": vals[:2],
                                })

                    # JS endpoints from inline scripts
                    for ep in page.get("js_endpoints", []):
                        path = ep.get("path", "")
                        if path and path not in seen_js_eps:
                            seen_js_eps.add(path)
                            all_js_eps.append(ep)

                    # Forms
                    for form in page.get("forms", []):
                        action = form["action"]
                        method = form["method"]
                        inputs = tuple(sorted(form["user_inputs"]))
                        fkey   = (action, method, inputs)
                        if fkey not in seen_forms:
                            seen_forms.add(fkey)
                            form_obj = {
                                "page":          url,
                                "action":        action,
                                "method":        method,
                                "inputs":        form["user_inputs"],
                                "hidden_fields": form["hidden_fields"],
                            }
                            all_forms.append(form_obj)
                            # Form action as notable endpoint
                            for cat, pat in NOTABLE_PATTERNS.items():
                                if pat.search(action) and action not in seen_notable:
                                    notable.append({"url": action, "category": cat,
                                                    "source": "form", "method": method})
                                    seen_notable.add(action)
                                    break
                        # Form params
                        for name in form["user_inputs"]:
                            key = (action, name)
                            if key not in seen_params:
                                seen_params.add(key)
                                all_params.append({
                                    "page":   url,
                                    "name":   name,
                                    "source": "form",
                                    "method": method,
                                })
                        # Hidden fields inventory (separate from params)
                        for hf_name, hf_val in form.get("hidden_fields", {}).items():
                            hf_key = (action, hf_name)
                            if hf_key not in seen_hf:
                                seen_hf.add(hf_key)
                                all_hidden_fld.append({
                                    "page":   url,
                                    "form":   action,
                                    "name":   hf_name,
                                    "value":  hf_val,
                                })

                    # Queue new links
                    if depth < max_depth:
                        for link in page.get("links", []):
                            abs_link = urljoin(url, link)
                            pl = urlparse(abs_link)
                            if pl.netloc != base_domain:
                                continue
                            ext = ("." + pl.path.rsplit(".", 1)[-1].lower()
                                   if "." in pl.path.split("/")[-1] else "")
                            if ext in SKIP_EXT:
                                continue
                            clean = f"{pl.scheme}://{pl.netloc}{pl.path}"
                            if pl.query:
                                clean += "?" + pl.query
                            queue.append((clean, depth + 1))

        return {
            "urls":              list(dict.fromkeys(all_urls))[:max_pages],
            "forms":             all_forms[:30],
            "params":            all_params[:150],
            "notable_endpoints": notable,
            "js_endpoints":      all_js_eps[:80],
            "hidden_fields":     all_hidden_fld[:50],
        }

    def _fetch_page(self, session, url: str) -> dict | None:
        path = urlparse(url).path
        ext  = ("." + path.rsplit(".", 1)[-1].lower()
                if "." in path.split("/")[-1] else "")
        if ext in SKIP_EXT:
            return None
        try:
            resp = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                return {"links": [], "forms": [], "js_endpoints": []}
            soup = BeautifulSoup(resp.text, "html.parser")
            return {
                "links":        self._extract_links(soup),
                "forms":        self._extract_forms(soup, resp.url),
                "js_endpoints": self._extract_js_endpoints(resp.text),
            }
        except Exception:
            return None

    @staticmethod
    def _extract_links(soup: BeautifulSoup) -> list:
        links = []
        for tag in soup.find_all(["a", "area"], href=True):
            href = tag["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                links.append(href)
        for form in soup.find_all("form", action=True):
            action = form["action"].strip()
            if action and not action.startswith(("javascript:", "#")):
                links.append(action)
        return links

    @staticmethod
    def _extract_forms(soup: BeautifulSoup, page_url: str) -> list:
        """Extract forms; filter out submit/button/reset/image inputs."""
        SKIP_TYPES = {"submit", "button", "reset", "image"}
        forms = []
        for form_tag in soup.find_all("form"):
            user_inputs  = []
            hidden_fields = {}
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                name  = (inp.get("name") or "").strip()
                itype = inp.get("type", "text").lower()
                if not name:
                    continue
                if itype == "hidden":
                    hidden_fields[name] = inp.get("value", "")
                elif itype not in SKIP_TYPES:
                    if name not in user_inputs:   # dedup within same form
                        user_inputs.append(name)

            raw_action = (form_tag.get("action") or "").strip()
            if not raw_action:
                action = page_url
            elif raw_action.startswith(("http://", "https://")):
                action = raw_action
            else:
                action = urljoin(page_url, raw_action)

            method = (form_tag.get("method") or "GET").upper()
            forms.append({
                "action":        action,
                "method":        method,
                "user_inputs":   user_inputs,
                "hidden_fields": hidden_fields,
            })
        return forms

    # ── Hidden endpoint discovery ─────────────────────────────────────────────

    def _discover_hidden(self, base_url: str, session) -> tuple:
        """Returns (endpoints_list, source_string)."""
        parsed    = urlparse(base_url)
        site_root = f"{parsed.scheme}://{parsed.netloc}"
        hostname  = parsed.hostname or ""
        mode      = self._tool_config.get("mode", "auto")
        is_local  = is_localhost_target(hostname)

        # Log mode and target context
        self.log(
            f"Hidden endpoint discovery mode: {mode} | target: {site_root} "
            f"({'localhost' if is_local else 'remote'})",
            "info"
        )

        # ── Localhost + kali_ssh validation ───────────────────────────────────
        if is_local and mode == "kali_ssh":
            self.log(
                f"WARNING: Target '{hostname}' is localhost but mode is 'kali_ssh'. "
                f"Kali cannot reach your localhost. Falling back to local probe.",
                "warning"
            )
            mode = "local"

        # ── local ffuf ────────────────────────────────────────────────────────
        if mode in ("local", "auto"):
            ffuf_bin = shutil.which("ffuf")
            if ffuf_bin:
                self.log("Hidden endpoint discovery: using local ffuf", "info")
                result = self._run_ffuf(ffuf_bin, site_root)
                if result is not None:
                    return result, "local_ffuf"
                self.log("Local ffuf failed — trying next source", "info")
            else:
                self.log("Local ffuf not found", "info")

        # ── kali ffuf ─────────────────────────────────────────────────────────
        if mode in ("kali_ssh", "auto") and not is_local:
            ssh = self._get_ssh()
            if ssh:
                kali_ffuf = ssh.which("ffuf")
                if kali_ffuf:
                    self.log(f"Hidden endpoint discovery: using Kali ffuf ({ssh.host})", "info")
                    result = self._run_ffuf_kali(ssh, kali_ffuf, site_root)
                    if result is not None:
                        return result, "kali_ffuf"
                    self.log("Kali ffuf failed — falling back to HTTP probe", "info")
                else:
                    self.log("ffuf not found on Kali", "warning")
            elif mode == "kali_ssh":
                self.log("kali_ssh mode but SSH unavailable — falling back to HTTP probe", "warning")

        # ── HTTP probe fallback ───────────────────────────────────────────────
        self.log("Hidden endpoint discovery: using HTTP HEAD probe fallback", "info")
        return self._probe_paths(site_root, session), "probe"

    def _run_ffuf(self, ffuf_bin: str, site_root: str) -> list | None:
        """Run ffuf binary, parse JSON output, return list of found endpoint dicts."""
        wl_path  = None
        out_file = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
                f.write("\n".join(COMMON_HIDDEN))
                wl_path = f.name
            out_file = wl_path + "_ffuf.json"

            proc = subprocess.run(
                [
                    ffuf_bin, "-u", f"{site_root}/FUZZ",
                    "-w", wl_path,
                    "-mc", "200,301,302,403",
                    "-of", "json", "-o", out_file,
                    "-t", "20", "-timeout", "3", "-maxtime", "15", "-s",
                ],
                capture_output=True, timeout=20,
            )
            endpoints = []
            if out_file and os.path.exists(out_file):
                with open(out_file) as f:
                    data = json.load(f)
                for r in data.get("results", []):
                    fuzz_val = r.get("input", {}).get("FUZZ", "")
                    path     = "/" + fuzz_val.lstrip("/")
                    endpoints.append({
                        "url":    site_root.rstrip("/") + path,
                        "path":   path,
                        "status": r.get("status", 0),
                        "source": "ffuf",
                    })
            self.log(f"ffuf found {len(endpoints)} hidden endpoints", "success" if endpoints else "info")
            return endpoints
        except Exception as e:
            self.log(f"ffuf error: {e} — falling back to probe", "warning")
            return None
        finally:
            for p in [wl_path, out_file]:
                if p and os.path.exists(p):
                    try:
                        os.unlink(p)
                    except Exception:
                        pass

    def _run_ffuf_kali(self, ssh, ffuf_bin: str, site_root: str) -> list | None:
        """Run ffuf on Kali via SSH. Wordlist written to Kali /tmp, output parsed as JSON."""
        import uuid
        uid  = uuid.uuid4().hex[:8]
        wl   = f"/tmp/_ffuf_wl_{uid}.txt"
        out_f = f"/tmp/_ffuf_out_{uid}.json"

        # Write wordlist to Kali
        wordlist_content = "\n".join(COMMON_HIDDEN)
        write_cmd = f"printf '%s\\n' {' '.join(shlex.quote(p) for p in COMMON_HIDDEN)} > {wl}"
        _, err, rc = ssh.run(write_cmd, timeout=10)
        if rc != 0:
            self.log(f"Kali ffuf wordlist write failed: {err[:80]}", "warning")
            return None

        # Run ffuf
        ffuf_cmd = (
            f"{ffuf_bin} -u {shlex.quote(site_root.rstrip('/') + '/FUZZ')} "
            f"-w {wl} -mc 200,301,302,403 -of json -o {out_f} "
            f"-t 20 -timeout 3 -maxtime 20 -s"
        )
        self.log(f"Kali ffuf: {site_root}/FUZZ", "info")
        ssh.run(ffuf_cmd, timeout=30)

        # Fetch JSON output
        out, err, rc = ssh.run(f"cat {out_f} 2>/dev/null; rm -f {wl} {out_f}", timeout=10)
        if not out.strip():
            self.log("Kali ffuf produced no output", "info")
            return []

        try:
            import json as _json
            data = _json.loads(out)
            endpoints = []
            for r in data.get("results", []):
                fuzz_val = r.get("input", {}).get("FUZZ", "")
                path     = "/" + fuzz_val.lstrip("/")
                endpoints.append({
                    "url":    site_root.rstrip("/") + path,
                    "path":   path,
                    "status": r.get("status", 0),
                    "source": "kali_ffuf",
                })
            self.log(f"Kali ffuf found {len(endpoints)} hidden endpoints", "success" if endpoints else "info")
            return endpoints
        except Exception as exc:
            self.log(f"Kali ffuf JSON parse error: {exc}", "warning")
            return None

    # ── New recon helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _extract_js_endpoints(html_text: str) -> list:
        """Heuristic: extract likely API endpoint paths from inline <script> blocks."""
        found = {}
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            for script in soup.find_all("script"):
                if script.get("src"):
                    continue
                text = script.get_text()
                for pat in _JS_EP_PATTERNS:
                    for m in pat.findall(text):
                        ep = m.strip()
                        if ep and 2 < len(ep) < 120 and ep not in found:
                            found[ep] = True
        except Exception:
            pass
        return [{"path": ep, "source": "js_inline"} for ep in sorted(found)]

    def _fetch_robots(self, session, site_root: str) -> dict:
        """Fetch /robots.txt and parse disallow/allow/sitemap directives."""
        url = site_root.rstrip("/") + "/robots.txt"
        try:
            r = session.get(url, timeout=(5, 8), verify=False, allow_redirects=False)
            if r.status_code != 200:
                return {"status": r.status_code, "disallowed": [], "allowed": [], "sitemaps": []}
            raw = r.text[:10000]
            disallowed, allowed, sitemaps = [], [], []
            for line in raw.splitlines():
                line = line.strip()
                lc = line.lower()
                if lc.startswith("disallow:"):
                    p = line[9:].split("#")[0].strip()
                    if p:
                        disallowed.append(p)
                elif lc.startswith("allow:"):
                    p = line[6:].split("#")[0].strip()
                    if p:
                        allowed.append(p)
                elif lc.startswith("sitemap:"):
                    p = line[8:].split("#")[0].strip()
                    if p:
                        sitemaps.append(p)
            return {
                "status":     200,
                "disallowed": disallowed[:60],
                "allowed":    allowed[:20],
                "sitemaps":   sitemaps[:5],
            }
        except Exception as e:
            return {"status": None, "disallowed": [], "allowed": [], "sitemaps": [],
                    "error": str(e)[:80]}

    def _fetch_sitemap(self, session, site_root: str, sitemap_hints: list) -> list:
        """Fetch sitemap.xml and extract <loc> URLs."""
        to_try = list(sitemap_hints[:2]) + [site_root.rstrip("/") + "/sitemap.xml"]
        found, seen = [], set()
        for sm_url in to_try:
            try:
                r = session.get(sm_url, timeout=(5, 10), verify=False, allow_redirects=True)
                if r.status_code != 200:
                    continue
                for m in re.findall(r"<loc>\s*(https?://[^\s<>]+)\s*</loc>", r.text, re.I):
                    if m not in seen:
                        seen.add(m)
                        found.append(m)
                if found:
                    break
            except Exception:
                pass
        return found[:100]

    def _analyze_cookies(self, headers: dict) -> list:
        """Analyze Set-Cookie header for security flags (HttpOnly, Secure, SameSite)."""
        raw = headers.get("Set-Cookie", "")
        if not raw:
            return []
        results = []
        for entry in raw.split(", ") if ", " in raw else [raw]:
            parts = [p.strip() for p in entry.split(";") if p.strip()]
            if not parts:
                continue
            name = parts[0].split("=")[0].strip() if "=" in parts[0] else parts[0]
            flags = [p.strip().lower() for p in parts[1:]]
            samesite = next(
                (p.split("=", 1)[-1].strip() for p in parts[1:]
                 if p.strip().lower().startswith("samesite")), None
            )
            results.append({
                "name":     name,
                "httponly": "httponly" in flags,
                "secure":   "secure" in flags,
                "samesite": samesite,
            })
        return results

    def _probe_paths(self, site_root: str, session) -> list:
        """HTTP HEAD probe on common hidden paths."""
        endpoints = []

        def probe(path):
            url = site_root.rstrip("/") + "/" + path.lstrip("/")
            try:
                r = session.head(url, timeout=(3, 5), verify=False, allow_redirects=False)
                if r.status_code in (200, 301, 302, 403):
                    return {
                        "url":    url,
                        "path":   urlparse(url).path,
                        "status": r.status_code,
                        "source": "probe",
                    }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as pool:
            for result in pool.map(probe, COMMON_HIDDEN):
                if result:
                    endpoints.append(result)

        self.log(f"HTTP probe found {len(endpoints)} hidden endpoints", "success" if endpoints else "info")
        return endpoints

    # ── TCP SYN Scanner (Scapy) ───────────────────────────────────────────────

    def _run_syn_scan(self, hostname: str) -> tuple:
        """TCP SYN scan using Scapy for stealth port scanning.
        
        Priority: 
        1. Kali SSH with sudo (most reliable)
        2. Local Scapy with root/admin
        3. Fallback to nmap SYN scan via Kali

        Returns: (syn_result_dict, source_string)
        syn_result_dict: {"ports": [...], "source": "scapy"|"not_available"}
        """
        result = {"ports": [], "source": "not_available"}

        # Common ports to scan (top 50 for speed)
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
            1723, 3306, 3389, 5900, 8080, 8443, 8888, 9090, 27017, 1433, 5432,
            6379, 11211, 5000, 8000, 3000, 4443, 9200, 5601, 9001,
            873, 123, 161, 1080, 8081, 465, 587, 992, 5050, 10000, 8008, 9000, 7000, 6000
        ]
        
        ports_str = ",".join(map(str, common_ports))

        # ═══════════════════════════════════════════════════════════════════════
        # Method 1: Kali SSH with sudo nmap SYN scan (preferred)
        # ═══════════════════════════════════════════════════════════════════════
        ssh = self._get_ssh()
        if ssh:
            try:
                # Use nmap with sudo for SYN scan (-sS requires root)
                # -Pn: skip host discovery, -n: no DNS resolution
                cmd = f"sudo nmap -sS -Pn -n -T4 --open -p {ports_str} {hostname} 2>/dev/null | grep -E '^[0-9]+/tcp'"
                self.log(f"SYN scan via Kali SSH: {hostname}", "info")

                output, _, _ = ssh.run(cmd, timeout=120)
                
                if output:
                    open_ports = []
                    for line in output.strip().split('\n'):
                        if '/tcp' in line and 'open' in line:
                            parts = line.split()
                            if parts:
                                port_part = parts[0].split('/')[0]
                                try:
                                    port = int(port_part)
                                    service = parts[2] if len(parts) > 2 else self._guess_service(port)
                                    open_ports.append({
                                        "port": port,
                                        "state": "open",
                                        "service": service,
                                    })
                                except ValueError:
                                    pass
                    
                    if open_ports:
                        result["ports"] = open_ports
                        result["total_scanned"] = len(common_ports)
                        result["source"] = "kali_nmap_syn"
                        self.log(f"SYN scan found {len(open_ports)} open ports", "success")
                        return result, "kali_nmap_syn"
                    else:
                        # Scan completed but no open ports found
                        result["total_scanned"] = len(common_ports)
                        result["source"] = "kali_nmap_syn"
                        self.log("SYN scan: no open ports found in top 50", "info")
                        return result, "kali_nmap_syn"
                        
            except Exception as e:
                self.log(f"Kali SYN scan failed: {e}, trying local Scapy", "warning")

        # ═══════════════════════════════════════════════════════════════════════
        # Method 2: Local Scapy (requires admin/root)
        # ═══════════════════════════════════════════════════════════════════════
        try:
            # Check if scapy is available
            try:
                from scapy.all import IP, TCP, sr1, conf
                conf.verb = 0  # Disable verbose output
            except ImportError:
                self.log("Scapy not installed locally", "info")
                result["source"] = "scapy_not_available"
                return result, "scapy_not_available"

            # Check if running as admin/root (required for raw sockets)
            import os as _os
            if _os.name == 'nt':
                # Windows: check if admin
                import ctypes
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                # Unix: check if root
                is_admin = _os.geteuid() == 0

            if not is_admin:
                self.log("Local SYN scan requires admin/root (use Kali SSH instead)", "warning")
                result["source"] = "no_privileges"
                return result, "no_privileges"

            self.log(f"Local Scapy SYN scan: {hostname} ({len(common_ports)} ports)", "info")

            # Resolve hostname to IP
            try:
                import socket
                target_ip = socket.gethostbyname(hostname)
            except Exception as e:
                self.log(f"SYN scan: DNS resolution failed: {e}", "warning")
                return result, "dns_failed"

            open_ports = []

            # SYN scan with timeout
            for port in common_ports:
                try:
                    # Send SYN packet
                    syn_packet = IP(dst=target_ip) / TCP(dport=port, flags="S")

                    # Wait for response (timeout 2 seconds)
                    response = sr1(syn_packet, timeout=2, verbose=0)

                    if response is not None:
                        # Check if SYN-ACK received (port open)
                        if response.haslayer(TCP):
                            tcp_layer = response.getlayer(TCP)
                            if tcp_layer.flags == 0x12:  # SYN-ACK
                                open_ports.append({
                                    "port": port,
                                    "state": "open",
                                    "service": self._guess_service(port),
                                })

                                # Send RST to close connection (stealth)
                                rst_packet = IP(dst=target_ip) / TCP(dport=port, flags="R")
                                sr1(rst_packet, timeout=1, verbose=0)

                except KeyboardInterrupt:
                    self.log("SYN scan interrupted by user", "warning")
                    break
                except Exception as e:
                    # Silent fail for individual ports
                    pass

            result["ports"] = open_ports
            result["total_scanned"] = len(common_ports)
            result["source"] = "scapy"

            return result, "scapy"

        except Exception as e:
            self.log(f"SYN scan error: {e}", "warning")
            return result, "error"

    def _guess_service(self, port: int) -> str:
        """Guess service name from port number."""
        services = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
            3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
            8080: "http-proxy", 8443: "https-alt", 27017: "mongodb",
        }
        return services.get(port, "unknown")
