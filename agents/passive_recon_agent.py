"""
PassiveReconAgent — Phase 1a: Passive Reconnaissance

Thu thap thong tin khong can active probing:
- IP resolution
- WHOIS lookup (optional: python-whois)
- DNS records: A, AAAA, CNAME, MX, NS, TXT (optional: dnspython)
- Subdomain enumeration nhe (common prefixes, passive DNS only)
- SSL/TLS certificate info
- Technology fingerprinting tu HTTP headers + body
- WhatWeb fingerprinting via Kali SSH (optional)

Khong crawl, khong port scan, khong gui payload.
"""
import concurrent.futures
import re
import shlex
import socket
import ssl
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

from agents.base_agent import BaseAgent
from utils import make_session, should_bypass_env_proxy, build_tool_config

# ── Security headers can kiem tra ────────────────────────────────────────────
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

# ── Technology signatures (header / body keyword) ────────────────────────────
TECH_SIGS = {
    "Apache":    ["apache"],
    "Nginx":     ["nginx"],
    "IIS":       ["microsoft-iis"],
    "PHP":       ["php/"],
    "ASP.NET":   ["x-aspnet-version", "asp.net"],
    "Node.js":   ["x-powered-by: express"],
    "Flask":     ["werkzeug"],
    "WordPress": ["wp-content", "wp-includes"],
    "Joomla":    ["joomla", "/component/"],
    "Drupal":    ["drupal.settings", "x-drupal-cache"],
    "Django":    ["csrfmiddlewaretoken"],
    "Laravel":   ["laravel_session"],
    "jQuery":    ["jquery"],
    "React":     ["react-dom", "__next_data__"],
}

CMS_SIGS = {
    "WordPress":  ["wp-content", "wp-includes", "wp-login.php"],
    "Joomla":     ["joomla", "index.php?option=com_"],
    "Drupal":     ["drupal.settings", "sites/default/files"],
    "Magento":    ["mage-", "magento"],
}

TIMEOUT = (8, 15)

# ── WhatWeb plugin → technology category mapping ─────────────────────────────
WHATWEB_FRAMEWORK = {
    "Apache", "Nginx", "IIS", "LiteSpeed", "Cherokee", "Lighttpd",
    "PHP", "ASP", "ASP.NET", "ColdFusion", "JSP",
    "Django", "Flask", "Symfony", "Laravel", "CakePHP", "Yii", "CodeIgniter",
    "Express", "NodeJS", "Rails", "Java", "Spring",
}
WHATWEB_LIBRARY = {
    "jQuery", "Bootstrap", "React", "Angular", "AngularJS", "Vue.js",
    "Prototype", "MooTools", "Dojo", "Modernizr",
}
WHATWEB_CMS = {
    "WordPress", "Joomla", "Drupal", "Magento", "TYPO3", "DNN",
    "Sitefinity", "OpenCart", "PrestaShop", "Moodle",
}
# WhatWeb plugin names to skip (noise / meta info)
WHATWEB_SKIP_PLUGINS = {
    "IP", "Country", "HTTPServer", "Meta-Refresh", "RedirectLocation",
    "Title", "UncommonHeaders", "HTML5", "Script", "Email", "Cookies",
    "Charset", "Frame", "PasswordField", "FormAction",
}


class PassiveReconAgent(BaseAgent):
    """Phase 1a — IP, WHOIS, DNS, SSL, technology fingerprinting."""

    PROMPT = "[PassiveReconAgent] IP resolution, WHOIS, DNS records, SSL cert, technology fingerprinting."

    def __init__(self, log_callback=None, memory=None, tool_config: dict = None):
        super().__init__("PassiveReconAgent", log_callback, memory)
        self._tool_config = tool_config or build_tool_config()
        self._ssh = None  # KaliSSHClient — lazy init

    # ── Main ─────────────────────────────────────────────────────────────────
    def execute(self, target: str, context: dict) -> dict:
        from utils import normalize_url
        base_url = normalize_url(target)
        parsed   = urlparse(base_url)
        hostname = parsed.hostname or target.split("/")[0].split(":")[0]

        is_local = should_bypass_env_proxy(base_url)

        result = {
            "domain":       hostname,
            "ip_addresses": [],
            "whois":        {},
            "dns_records":  {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []},
            "subdomains":   [],
            "ssl":          {},
            "technology": {
                "server":           "",
                "cms":              "",
                "frameworks":       [],
                "libraries":        [],
                "security_headers": {},
                "whatweb":          [],
            },
            "theharvester": {"emails": [], "hosts": [], "ips": [], "source": ""},
            "amass":        {"subdomains": [], "source": ""},
            "subfinder":    {"subdomains": [], "source": ""},
            "crtsh":        {"subdomains": [], "source": ""},
            "wayback":      {"urls": [], "source": ""},
            "shodan":       {"ports": [], "vulns": [], "hostnames": [], "source": ""},
            "google_dorks": {"files": [], "pages": [], "exposed": [], "source": ""},
            # internal meta — used by aggregator for accurate limitation messages
            "_dns_source":      "",
            "_is_local":        is_local,
            "_whatweb_source":  "",
        }

        # Lay ToolTracker tu tool_config (optional — khong bat buoc)
        tracker = (self._tool_config or {}).get("tool_tracker")
        mode    = (self._tool_config or {}).get("mode", "auto")

        # 1. IP resolution
        if tracker: tracker.start("ip_resolve")
        self.log("Resolving IP address...")
        result["ip_addresses"] = self._resolve_ips(hostname)
        if result["ip_addresses"]:
            self.log(f"IP: {result['ip_addresses']}", "success")
            if tracker: tracker.done("ip_resolve",
                summary=f"Found {len(result['ip_addresses'])} IP(s): {result['ip_addresses'][0] if result['ip_addresses'] else 'N/A'}",
                result={"ips": result["ip_addresses"]})
        else:
            self.log("IP resolution failed", "warning")
            if tracker: tracker.error("ip_resolve", "IP resolution failed")

        # 2. DNS records
        if tracker: tracker.start("dns")
        self.log("DNS records lookup...")
        records, dns_source = self._get_dns_records(hostname)
        result["dns_records"] = records
        result["_dns_source"] = dns_source
        types_found = [k for k, v in records.items() if v]
        self.log(
            f"DNS types found: {types_found or ['none']} (via {dns_source})",
            "success" if types_found else "info",
        )
        if tracker: tracker.done("dns",
            summary=f"{len(types_found)} record types via {dns_source}",
            result=records)

        # 3. WHOIS
        if tracker: tracker.start("whois")
        self.log("WHOIS lookup...")
        result["whois"] = self._get_whois(hostname)
        if result["whois"].get("registrar"):
            self.log(f"Registrar: {result['whois']['registrar']}", "success")
            if tracker: tracker.done("whois",
                summary=f"Registrar: {result['whois']['registrar']}",
                result=result["whois"])
        elif result["whois"].get("error"):
            self.log(f"WHOIS: {result['whois']['error']}", "warning")
            if tracker: tracker.error("whois", result["whois"]["error"])
        else:
            if tracker: tracker.done("whois", summary="No registrar info", result=result["whois"])

        # 4. DNS bruteforce (khong track rieng — ket qua gop vao subdomains chung)
        self.log("Subdomain enumeration (DNS bruteforce)...")
        result["subdomains"] = self._enumerate_subdomains(hostname, is_local)
        self.log(
            f"DNS bruteforce: {len(result['subdomains'])} subdomains found",
            "success" if result["subdomains"] else "info",
        )

        # 5. SSL
        if tracker: tracker.start("ssl")
        self.log("SSL/TLS certificate check...")
        result["ssl"] = self._get_ssl_info(hostname)
        if result["ssl"].get("subject"):
            days = result["ssl"].get("days_remaining", "?")
            self.log(f"SSL OK — {days} days remaining, issuer={result['ssl'].get('issuer', '')}", "success")
            if tracker: tracker.done("ssl",
                summary=f"Valid — {days} days left, issuer: {result['ssl'].get('issuer','')}",
                result=result["ssl"])
        elif result["ssl"].get("error"):
            self.log(f"SSL: {result['ssl']['error']}", "warning")
            if tracker: tracker.error("ssl", result["ssl"]["error"])
        else:
            if tracker: tracker.done("ssl", summary="No SSL info", result=result["ssl"])

        # 6. WhatWeb — Technology fingerprinting (HTTP headers + Kali WhatWeb)
        if tracker: tracker.start("whatweb")
        self.log("Technology fingerprinting from HTTP response...")
        session = make_session(base_url)
        result["technology"] = self._fingerprint_tech(session, base_url)
        tech = result["technology"]
        self.log(
            f"Server: {tech['server'] or 'unknown'} | "
            f"Frameworks: {tech['frameworks']} | CMS: {tech['cms'] or 'none'}",
            "success",
        )
        if not is_local and mode in ("kali_ssh", "auto"):
            self.log("WhatWeb fingerprinting (via Kali SSH)...")
            ww_plugins, ww_source = self._run_whatweb(base_url)
            result["_whatweb_source"] = ww_source
            if ww_plugins:
                self._merge_whatweb(result["technology"], ww_plugins)
                self.log(
                    f"WhatWeb: {len(ww_plugins)} plugins detected (source={ww_source})",
                    "success",
                )
                if tracker: tracker.done("whatweb",
                    summary=f"Server:{tech['server'] or '?'} | {len(ww_plugins)} plugins via {ww_source}",
                    result={"server": tech["server"], "plugins": list(ww_plugins.keys()) if isinstance(ww_plugins, dict) else []})
            else:
                self.log(f"WhatWeb: no results (source={ww_source})", "info")
                if tracker: tracker.done("whatweb",
                    summary=f"Server:{tech['server'] or '?'} | No WhatWeb results ({ww_source})")
        elif is_local:
            result["_whatweb_source"] = "skipped_localhost"
            self.log("WhatWeb skipped — localhost/private IP target", "info")
            if tracker: tracker.done("whatweb", summary="Skipped — localhost target")
        else:
            result["_whatweb_source"] = "skipped_local_mode"
            self.log("WhatWeb skipped — mode=local (no Kali SSH)", "info")
            if tracker: tracker.done("whatweb", summary=f"Server:{tech['server'] or '?'} | WhatWeb skipped (local mode)")

        # 8. theHarvester — email & subdomain harvesting via Kali SSH
        if tracker: tracker.start("theharvester")
        if not is_local and mode in ("kali_ssh", "auto"):
            self.log("theHarvester — email/subdomain harvesting (via Kali SSH)...")
            harvester_result = self._run_theharvester(hostname)
            result["theharvester"] = harvester_result
            emails = harvester_result.get("emails", [])
            hosts  = harvester_result.get("hosts",  [])
            if emails or hosts:
                self.log(
                    f"theHarvester: {len(emails)} emails, {len(hosts)} hosts found",
                    "success",
                )
                if tracker: tracker.done("theharvester",
                    summary=f"{len(emails)} emails, {len(hosts)} hosts",
                    result=harvester_result)
            else:
                self.log("theHarvester: no results", "info")
                if tracker: tracker.done("theharvester", summary="No results", result=harvester_result)
        elif is_local:
            result["theharvester"] = {"emails": [], "hosts": [], "source": "skipped_localhost"}
            self.log("theHarvester skipped — localhost/private IP target", "info")
            if tracker: tracker.done("theharvester", summary="Skipped — localhost target")
        else:
            result["theharvester"] = {"emails": [], "hosts": [], "source": "skipped_local_mode"}
            self.log("theHarvester skipped — mode=local (no Kali SSH)", "info")
            if tracker: tracker.done("theharvester", summary="Skipped — local mode")

        # 9. Amass — Advanced subdomain enumeration (Kali SSH)
        if tracker: tracker.start("amass")
        if not is_local and mode in ("kali_ssh", "auto"):
            self.log("Amass — Advanced subdomain enumeration (via Kali SSH)...")
            amass_result = self._run_amass(hostname)
            result["amass"] = amass_result
            if amass_result.get("subdomains"):
                self.log(
                    f"Amass: {len(amass_result['subdomains'])} subdomains found",
                    "success",
                )
                existing_subs = {s["subdomain"] for s in result["subdomains"]}
                for sub in amass_result["subdomains"]:
                    if sub not in existing_subs:
                        result["subdomains"].append({"subdomain": sub, "ip": "", "source": "amass"})
                        existing_subs.add(sub)
                if tracker: tracker.done("amass",
                    summary=f"{len(amass_result['subdomains'])} subdomains",
                    result=amass_result)
            else:
                self.log("Amass: no results", "info")
                if tracker: tracker.done("amass", summary="No results", result=amass_result)
        elif is_local:
            result["amass"] = {"subdomains": [], "source": "skipped_localhost"}
            self.log("Amass skipped — localhost/private IP target", "info")
            if tracker: tracker.done("amass", summary="Skipped — localhost target")
        else:
            result["amass"] = {"subdomains": [], "source": "skipped_local_mode"}
            self.log("Amass skipped — mode=local (no Kali SSH)", "info")
            if tracker: tracker.done("amass", summary="Skipped — local mode")

        # 11. subfinder — Fast subdomain discovery (Kali SSH)
        if tracker: tracker.start("subfinder")
        if not is_local and mode in ("kali_ssh", "auto"):
            self.log("subfinder — Fast subdomain discovery (via Kali SSH)...")
            subfinder_result = self._run_subfinder(hostname)
            result["subfinder"] = subfinder_result
            if subfinder_result.get("subdomains"):
                self.log(
                    f"subfinder: {len(subfinder_result['subdomains'])} subdomains found",
                    "success",
                )
                existing_subs = {s["subdomain"] for s in result["subdomains"]}
                for sub in subfinder_result["subdomains"]:
                    if sub not in existing_subs:
                        result["subdomains"].append({"subdomain": sub, "ip": "", "source": "subfinder"})
                        existing_subs.add(sub)
                if tracker: tracker.done("subfinder",
                    summary=f"{len(subfinder_result['subdomains'])} subdomains",
                    result=subfinder_result)
            else:
                self.log("subfinder: no results", "info")
                if tracker: tracker.done("subfinder", summary="No results", result=subfinder_result)
        elif is_local:
            result["subfinder"] = {"subdomains": [], "source": "skipped_localhost"}
            self.log("subfinder skipped — localhost/private IP target", "info")
            if tracker: tracker.done("subfinder", summary="Skipped — localhost target")
        else:
            result["subfinder"] = {"subdomains": [], "source": "skipped_local_mode"}
            self.log("subfinder skipped — mode=local (no Kali SSH)", "info")
            if tracker: tracker.done("subfinder", summary="Skipped — local mode")

        # 12. crt.sh — Certificate Transparency subdomain discovery
        if tracker: tracker.start("crtsh")
        if not is_local:
            self.log("crt.sh — Certificate Transparency subdomain discovery...")
            crtsh_result = self._run_crtsh(hostname)
            result["crtsh"] = crtsh_result
            if crtsh_result.get("subdomains"):
                self.log(
                    f"crt.sh: {len(crtsh_result['subdomains'])} subdomains found",
                    "success",
                )
                existing_subs = {s["subdomain"] for s in result["subdomains"]}
                for sub in crtsh_result["subdomains"]:
                    if sub not in existing_subs:
                        result["subdomains"].append({"subdomain": sub, "ip": "", "source": "crtsh"})
                        existing_subs.add(sub)
                if tracker: tracker.done("crtsh",
                    summary=f"{len(crtsh_result['subdomains'])} subdomains",
                    result=crtsh_result)
            else:
                self.log("crt.sh: no results", "info")
                if tracker: tracker.done("crtsh", summary="No results", result=crtsh_result)
        else:
            result["crtsh"] = {"subdomains": [], "source": "skipped_localhost"}
            self.log("crt.sh skipped — localhost/private IP target", "info")
            if tracker: tracker.done("crtsh", summary="Skipped — localhost target")

        # 11. Wayback Machine — Historical URL discovery
        if tracker: tracker.start("wayback")
        if not is_local:
            self.log("Wayback Machine — Historical URL discovery...")
            wayback_result = self._run_wayback(hostname)
            result["wayback"] = wayback_result
            if wayback_result.get("urls"):
                self.log(
                    f"Wayback Machine: {len(wayback_result['urls'])} historical URLs found",
                    "success",
                )
                if tracker: tracker.done("wayback",
                    summary=f"{len(wayback_result['urls'])} historical URLs",
                    result=wayback_result)
            else:
                self.log("Wayback Machine: no results", "info")
                if tracker: tracker.done("wayback", summary="No results", result=wayback_result)
        else:
            result["wayback"] = {"urls": [], "source": "skipped_localhost"}
            self.log("Wayback Machine skipped — localhost/private IP target", "info")
            if tracker: tracker.done("wayback", summary="Skipped — localhost target")

        # 12. Shodan — Host intelligence lookup
        if tracker: tracker.start("shodan")
        if not is_local and result["ip_addresses"]:
            self.log("Shodan — Host intelligence lookup...")
            shodan_result = self._run_shodan(result["ip_addresses"][0])
            result["shodan"] = shodan_result
            if shodan_result.get("ports") or shodan_result.get("vulns"):
                self.log(
                    f"Shodan: {len(shodan_result.get('ports', []))} ports, "
                    f"{len(shodan_result.get('vulns', []))} vulns found",
                    "success",
                )
                if tracker: tracker.done("shodan",
                    summary=f"{len(shodan_result.get('ports', []))} ports, {len(shodan_result.get('vulns', []))} vulns",
                    result=shodan_result)
            else:
                self.log(f"Shodan: no results ({shodan_result.get('source', 'unknown')})", "info")
                if tracker: tracker.done("shodan", summary="No results", result=shodan_result)
        elif is_local:
            result["shodan"] = {"ports": [], "vulns": [], "hostnames": [], "source": "skipped_localhost"}
            self.log("Shodan skipped — localhost/private IP target", "info")
            if tracker: tracker.done("shodan", summary="Skipped — localhost target")
        else:
            result["shodan"] = {"ports": [], "vulns": [], "hostnames": [], "source": "no_ip"}
            self.log("Shodan skipped — no IP address resolved", "info")
            if tracker: tracker.done("shodan", summary="Skipped — no IP")

        # 13. Google Dorks — Search Engine Dorking (via Python requests)
        if tracker: tracker.start("google_dorks")
        if not is_local:
            self.log("Google Dorks — Search Engine Dorking...")
            dorks_result = self._run_google_dorks(hostname)
            result["google_dorks"] = dorks_result
            files = dorks_result.get("files", [])
            pages = dorks_result.get("pages", [])
            exposed = dorks_result.get("exposed", [])
            total_findings = len(files) + len(pages) + len(exposed)
            if total_findings > 0:
                self.log(
                    f"Google Dorks: {len(files)} files, {len(pages)} pages, {len(exposed)} exposed items",
                    "success",
                )
                if tracker: tracker.done("google_dorks",
                    summary=f"{len(files)} files, {len(pages)} pages, {len(exposed)} exposed",
                    result=dorks_result)
            else:
                self.log("Google Dorks: no results", "info")
                if tracker: tracker.done("google_dorks", summary="No results", result=dorks_result)
        else:
            result["google_dorks"] = {"files": [], "pages": [], "exposed": [], "source": "skipped_localhost"}
            self.log("Google Dorks skipped — localhost/private IP target", "info")
            if tracker: tracker.done("google_dorks", summary="Skipped — localhost target")

        if self.memory:
            self.memory.set_passive_recon(result)
            self.log("Saved passive recon to memory.", "info")

        # Close SSH if opened
        if self._ssh:
            self._ssh.close()
            self._ssh = None

        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _resolve_ips(self, hostname: str) -> list:
        try:
            infos = socket.getaddrinfo(hostname, None)
            ips = list(dict.fromkeys(i[4][0] for i in infos))
            return ips[:5]
        except Exception as e:
            self.log(f"IP resolve error: {e}", "warning")
            return []

    def _get_dns_records(self, hostname: str) -> tuple:
        """Returns (records_dict, source_string).

        source_string is "dnspython" when dnspython library is available,
        or "socket_fallback" when only socket.gethostbyname is used.
        Empty records with source="dnspython" means the hostname has no
        public DNS records (e.g. localhost), NOT that the library is missing.
        """
        records = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []}
        try:
            import dns.resolver
            for rtype in records:
                try:
                    ans = dns.resolver.resolve(hostname, rtype, lifetime=5)
                    records[rtype] = [str(r) for r in ans]
                except Exception:
                    pass
            return records, "dnspython"
        except ImportError:
            self.log("dnspython not installed — only A record via socket", "info")
            try:
                records["A"] = [socket.gethostbyname(hostname)]
            except Exception:
                pass
            return records, "socket_fallback"

    def _enumerate_subdomains(self, hostname: str, is_local: bool) -> list:
        """Enhanced subdomain enumeration via DNS brute-force with 100+ prefixes.

        Skips automatically for localhost / private IP targets (no public DNS).
        Uses comprehensive prefix list covering common subdomain patterns.
        """
        if is_local:
            self.log("Subdomain enum skipped — localhost/private IP target", "info")
            return []

        # Only meaningful for real domain names (at least one dot)
        if "." not in hostname:
            self.log("Subdomain enum skipped — hostname has no dot", "info")
            return []

        # Comprehensive 100+ subdomain prefixes (sorted by likelihood)
        PREFIXES = [
            # Most common
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
            "vpn", "admin", "api", "dev", "staging", "test", "beta", "demo", "app",
            # Web services
            "www2", "www3", "web", "web1", "web2", "portal", "secure", "shop", "store",
            "blog", "forum", "support", "help", "docs", "wiki", "status", "cdn",
            # Mail related
            "mail2", "email", "mx", "mx1", "mx2", "imap", "pop3", "exchange", "owa",
            "autodiscover", "mailgate", "newsletter", "lists",
            # Infrastructure
            "ns", "ns3", "ns4", "dns", "dns1", "dns2", "proxy", "gateway", "firewall",
            "router", "switch", "server", "server1", "server2", "host", "node",
            # Development & Testing
            "dev1", "dev2", "development", "stage", "stage1", "uat", "qa", "testing",
            "sandbox", "preview", "alpha", "pre", "preprod", "prod", "production",
            # Cloud & Services
            "cloud", "aws", "azure", "gcp", "s3", "storage", "backup", "db", "database",
            "mysql", "postgres", "mongo", "redis", "cache", "elastic", "search",
            # Security & Auth
            "login", "auth", "sso", "ldap", "ad", "directory", "identity", "oauth",
            "vpn2", "ssl", "cert", "pki", "security",
            # Internal services
            "intranet", "internal", "private", "corp", "corporate", "office", "hr",
            "erp", "crm", "billing", "invoice", "payment", "checkout",
            # Monitoring & Management
            "monitor", "monitoring", "nagios", "zabbix", "grafana", "prometheus",
            "jenkins", "ci", "cd", "git", "gitlab", "bitbucket", "svn", "repo",
            # Mobile & API
            "mobile", "m", "wap", "api2", "api3", "rest", "graphql", "ws", "websocket",
            "socket", "realtime", "push", "notify", "notification",
            # Media & Assets
            "img", "images", "image", "static", "assets", "media", "video", "stream",
            "download", "upload", "files", "file", "ftp2", "sftp",
            # Regional / Language
            "en", "de", "fr", "es", "cn", "jp", "kr", "br", "ru", "us", "eu", "uk",
            # Legacy & Misc
            "old", "new", "legacy", "v1", "v2", "v3", "temp", "tmp", "bak", "backup2",
        ]
        found = []

        def resolve_sub(prefix):
            sub = f"{prefix}.{hostname}"
            try:
                ip = socket.gethostbyname(sub)
                return {"subdomain": sub, "ip": ip, "source": "dns_bruteforce"}
            except Exception:
                return None

        self.log(f"DNS brute-force with {len(PREFIXES)} prefixes...")
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
                futures = {pool.submit(resolve_sub, p): p for p in PREFIXES}
                for fut in concurrent.futures.as_completed(futures, timeout=30):
                    r = fut.result()
                    if r:
                        found.append(r)
        except concurrent.futures.TimeoutError:
            self.log("Subdomain enum timed out (partial results)", "warning")
        except Exception as e:
            self.log(f"Subdomain enum error: {e}", "warning")

        self.log(f"DNS brute-force: {len(found)} subdomains found", "info")
        return found

    def _get_whois(self, hostname: str) -> dict:
        try:
            import whois as _whois
            w = _whois.whois(hostname)

            def _str(v):
                if isinstance(v, list):
                    return str(v[0]) if v else ""
                return str(v) if v else ""

            return {
                "registrar":       _str(w.registrar),
                "creation_date":   _str(w.creation_date),
                "expiration_date": _str(w.expiration_date),
                "country":         _str(w.country),
                "name_servers":    list(w.name_servers or [])[:4],
            }
        except ImportError:
            return {"error": "python-whois not installed (pip install python-whois)"}
        except Exception as e:
            return {"error": str(e)[:120]}

    def _get_ssl_info(self, hostname: str) -> dict:
        """Get SSL certificate information using multiple methods."""
        
        # Method 1: Try with certificate verification enabled (gets full cert info)
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    proto = ssock.version()
                    
            if cert:
                return self._parse_cert_dict(cert, proto)
        except ssl.SSLCertVerificationError:
            pass  # Will try method 2
        except Exception:
            pass
        
        # Method 2: Use openssl command via Kali SSH for detailed cert info
        try:
            ssh = self._get_ssh()
            if ssh:
                cmd = f"echo | timeout 10 openssl s_client -connect {hostname}:443 -servername {hostname} 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null"
                output, _, _ = ssh.run(cmd, timeout=15)
                
                if output and "subject=" in output.lower():
                    return self._parse_openssl_output(output, hostname)
        except Exception:
            pass
        
        # Method 3: Get binary cert and decode manually
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    proto = ssock.version()
                    
            if cert_bin:
                # Try to decode with cryptography library
                try:
                    from cryptography import x509
                    from cryptography.hazmat.backends import default_backend
                    
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    # Extract subject CN
                    subject_cn = ""
                    for attr in cert.subject:
                        if attr.oid == x509.oid.NameOID.COMMON_NAME:
                            subject_cn = attr.value
                            break
                    
                    # Extract issuer
                    issuer_org = ""
                    issuer_cn = ""
                    for attr in cert.issuer:
                        if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                            issuer_org = attr.value
                        if attr.oid == x509.oid.NameOID.COMMON_NAME:
                            issuer_cn = attr.value
                    
                    # Extract SANs
                    sans = []
                    try:
                        san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                        sans = [name.value for name in san_ext.value if isinstance(name, x509.DNSName)][:10]
                    except x509.ExtensionNotFound:
                        pass
                    
                    # Calculate days remaining
                    from datetime import datetime, timezone
                    now = datetime.now(timezone.utc)
                    expiry = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
                    days_remaining = (expiry - now).days
                    
                    return {
                        "subject": subject_cn,
                        "issuer": issuer_org or issuer_cn,
                        "expiry": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
                        "valid_from": (cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before).strftime("%b %d %H:%M:%S %Y GMT"),
                        "days_remaining": days_remaining,
                        "protocol": proto,
                        "san": sans,
                        "serial": format(cert.serial_number, 'x'),
                    }
                except ImportError:
                    # cryptography not installed, return basic info
                    return {
                        "subject": hostname,
                        "issuer": "Unknown (install cryptography for details)",
                        "protocol": proto,
                        "san": [],
                        "note": "Certificate exists but details require 'cryptography' package"
                    }
                    
        except ConnectionRefusedError:
            return {"error": "Port 443 not open"}
        except socket.timeout:
            return {"error": "SSL connection timeout"}
        except Exception as e:
            return {"error": f"SSL Error: {e}"}
        
        return {"error": "Could not retrieve certificate"}
    
    def _parse_cert_dict(self, cert: dict, proto: str) -> dict:
        """Parse certificate dict from getpeercert()."""
        raw_exp = cert.get("notAfter", "")
        try:
            exp = datetime.strptime(raw_exp.replace(" GMT", ""), "%b %d %H:%M:%S %Y")
            exp = exp.replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
        except Exception:
            days = None

        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))
        sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"][:10]

        return {
            "subject": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
            "expiry": raw_exp,
            "days_remaining": days,
            "protocol": proto,
            "san": sans,
        }
    
    def _parse_openssl_output(self, output: str, hostname: str) -> dict:
        """Parse openssl x509 command output."""
        result = {
            "subject": "",
            "issuer": "",
            "expiry": "",
            "valid_from": "",
            "days_remaining": None,
            "protocol": "TLS",
            "san": [],
        }
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith("subject="):
                # Extract CN from subject
                parts = line.split("CN=")
                if len(parts) > 1:
                    result["subject"] = parts[-1].split(",")[0].strip()
            elif line.startswith("issuer="):
                # Extract O or CN from issuer
                if "O=" in line:
                    parts = line.split("O=")
                    if len(parts) > 1:
                        result["issuer"] = parts[-1].split(",")[0].strip()
                elif "CN=" in line:
                    parts = line.split("CN=")
                    if len(parts) > 1:
                        result["issuer"] = parts[-1].split(",")[0].strip()
            elif line.startswith("notBefore="):
                result["valid_from"] = line.replace("notBefore=", "").strip()
            elif line.startswith("notAfter="):
                result["expiry"] = line.replace("notAfter=", "").strip()
                # Calculate days remaining
                try:
                    exp_str = result["expiry"]
                    # Parse format like "Jan 30 06:59:59 2027 GMT"
                    exp = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                    exp = exp.replace(tzinfo=timezone.utc)
                    result["days_remaining"] = (exp - datetime.now(timezone.utc)).days
                except Exception:
                    pass
            elif "DNS:" in line:
                # Extract SANs
                dns_entries = [x.strip().replace("DNS:", "") for x in line.split(",") if "DNS:" in x]
                result["san"].extend(dns_entries[:10])
        
        return result

    def _fingerprint_tech(self, session, base_url: str) -> dict:
        tech = {
            "server":           "",
            "cms":              "",
            "frameworks":       [],
            "libraries":        [],
            "security_headers": {},
        }
        try:
            resp = session.get(base_url, timeout=TIMEOUT, verify=False, allow_redirects=True)
            headers_str = str({k.lower(): v for k, v in resp.headers.items()}).lower()
            body        = resp.text.lower()[:25000]  # first 25 KB only

            # Server header
            tech["server"] = resp.headers.get("Server", "")

            # Technology detection
            framework_names = {"Apache", "Nginx", "IIS", "PHP", "ASP.NET", "Node.js",
                               "Flask", "WordPress", "Joomla", "Drupal", "Django", "Laravel"}
            library_names   = {"jQuery", "React"}
            detected        = set()

            for name, sigs in TECH_SIGS.items():
                for sig in sigs:
                    if sig in headers_str or sig in body:
                        detected.add(name)
                        break

            for d in detected:
                if d in library_names:
                    tech["libraries"].append(d)
                else:
                    tech["frameworks"].append(d)

            # CMS detection from body
            for cms, sigs in CMS_SIGS.items():
                if any(sig in body for sig in sigs):
                    tech["cms"] = cms
                    break

            # Security headers presence/absence
            for h in SECURITY_HEADERS:
                val = resp.headers.get(h)
                tech["security_headers"][h] = val  # None = missing

        except Exception as e:
            self.log(f"Tech fingerprint error: {e}", "warning")

        return tech

    # ── WhatWeb via Kali SSH ──────────────────────────────────────────────────

    def _get_ssh(self):
        """Lazy-init KaliSSHClient from tool_config."""
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

    def _run_whatweb(self, base_url: str) -> tuple:
        """Run WhatWeb via Kali SSH. Returns (plugins_dict, source_string)."""
        ssh = self._get_ssh()
        if not ssh:
            return {}, "not_available"

        ww_bin = ssh.which("whatweb")
        if not ww_bin:
            self.log("whatweb not found on Kali", "info")
            return {}, "not_available"

        uid   = uuid.uuid4().hex[:8]
        out_f = f"/tmp/_ww_{uid}.json"
        cmd   = (
            f"{ww_bin} -q --log-json={out_f} {shlex.quote(base_url)} "
            f"2>/dev/null; cat {out_f} 2>/dev/null; rm -f {out_f}"
        )
        self.log(f"Kali whatweb: {base_url}", "info")
        out, err, rc = ssh.run(cmd, timeout=35)

        if not out.strip():
            return {}, "not_available"

        try:
            import json as _json
            data = _json.loads(out.strip())
            if isinstance(data, list) and data:
                return data[0].get("plugins", {}), "kali_whatweb"
        except Exception as exc:
            self.log(f"WhatWeb JSON parse error: {exc}", "warning")

        return {}, "not_available"

    def _merge_whatweb(self, tech: dict, plugins: dict) -> None:
        """Merge WhatWeb plugin dict into technology dict (dedup-safe)."""
        # Update server from HTTPServer plugin if currently empty
        http_server = plugins.get("HTTPServer", {})
        if http_server.get("string") and not tech.get("server"):
            tech["server"] = http_server["string"][0]

        # CMS detection
        if not tech.get("cms"):
            for cms_name in WHATWEB_CMS:
                if cms_name in plugins:
                    tech["cms"] = cms_name
                    break

        # Frameworks (deduplicated)
        existing_fw = set(tech.get("frameworks", []))
        for fw_name in WHATWEB_FRAMEWORK:
            if fw_name in plugins and fw_name not in existing_fw:
                tech["frameworks"].append(fw_name)
                existing_fw.add(fw_name)

        # Libraries (deduplicated)
        existing_lib = set(tech.get("libraries", []))
        for lib_name in WHATWEB_LIBRARY:
            if lib_name in plugins and lib_name not in existing_lib:
                tech["libraries"].append(lib_name)
                existing_lib.add(lib_name)

        # Raw whatweb plugin list
        ww_list = tech.get("whatweb", [])
        seen_names = {e["name"] for e in ww_list}
        for name, data in plugins.items():
            if name in WHATWEB_SKIP_PLUGINS or name in seen_names:
                continue
            version = ""
            if isinstance(data, dict):
                v = data.get("version") or data.get("string")
                if isinstance(v, list) and v:
                    version = v[0]
                elif isinstance(v, str):
                    version = v
            ww_list.append({"name": name, "version": version})
            seen_names.add(name)
        tech["whatweb"] = ww_list

    # ── theHarvester via Kali SSH ─────────────────────────────────────────────

    def _run_theharvester(self, domain: str) -> dict:
        """Run theHarvester via Kali SSH for email & subdomain harvesting.

        Returns: {"emails": [...], "hosts": [...], "source": "kali_theharvester"|"not_available"}
        """
        result = {"emails": [], "hosts": [], "ips": [], "source": "not_available"}

        ssh = self._get_ssh()
        if not ssh:
            return result

        harvester_bin = ssh.which("theHarvester")
        if not harvester_bin:
            self.log("theHarvester not found on Kali", "info")
            return result

        # Run theHarvester with text output (more reliable than JSON)
        # -b: data sources - using fast and reliable ones
        cmd = (
            f"{harvester_bin} -d {shlex.quote(domain)} "
            f"-b crtsh,hackertarget,rapiddns,dnsdumpster -l 50 2>&1"
        )

        self.log(f"Kali theHarvester: {domain}", "info")
        out, err, rc = ssh.run(cmd, timeout=120)  # theHarvester can be slow

        if out.strip():
            result = self._parse_theharvester_text(out)
            result["source"] = "kali_theharvester"

        return result

    def _parse_theharvester_text(self, text: str) -> dict:
        """Parse theHarvester text output when JSON is not available."""
        result = {"emails": [], "hosts": [], "ips": []}

        # Strip ANSI color codes
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        text = ansi_escape.sub('', text)

        lines = text.splitlines()
        section = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            line_lower = line.lower()

            # Detect section headers
            if "emails found" in line_lower or line_lower.startswith("[*] emails"):
                section = "emails"
                continue
            elif "hosts found" in line_lower or line_lower.startswith("[*] hosts"):
                section = "hosts"
                continue
            elif "ips found" in line_lower or line_lower.startswith("[*] ips"):
                section = "ips"
                continue
            elif line.startswith("[*]") or line.startswith("*"):
                # New section or info line, reset
                if "target" not in line_lower:
                    section = None
                continue
            elif line.startswith("-") and len(line) > 5 and line.count("-") > 3:
                # Separator line
                continue

            # Extract data based on current section
            if section == "emails" and "@" in line:
                # Email line
                email = line.split()[0] if line.split() else line
                if "@" in email and "." in email:
                    result["emails"].append(email.lower())
            elif section == "hosts" and "." in line:
                # Host line - might have IP after colon
                parts = line.split(":")
                host = parts[0].strip()
                if host and "." in host and not host.startswith("-"):
                    result["hosts"].append(host.lower())
                # Also extract IP if present
                if len(parts) > 1:
                    ip_part = parts[1].strip()
                    ip_match = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip_part)
                    result["ips"].extend(ip_match)
            elif section == "ips":
                # IP line
                ip_match = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
                result["ips"].extend(ip_match)

        # Deduplicate and limit
        result["emails"] = list(set(result["emails"]))[:50]
        result["hosts"] = list(set(result["hosts"]))[:100]
        result["ips"] = list(set(result["ips"]))[:50]

        return result

    # ── Sublist3r via Kali SSH ────────────────────────────────────────────────

    def _run_sublist3r(self, domain: str) -> dict:
        """Run Sublist3r via Kali SSH for subdomain enumeration.

        Returns: {"subdomains": [...], "source": "kali_sublist3r"|"not_available"}
        """
        result = {"subdomains": [], "source": "not_available"}

        ssh = self._get_ssh()
        if not ssh:
            return result

        # Sublist3r can be installed as 'sublist3r' or 'Sublist3r'
        sublist3r_bin = ssh.which("sublist3r") or ssh.which("Sublist3r")
        if not sublist3r_bin:
            # Try python module
            check_cmd = "python3 -c 'import sublist3r' 2>/dev/null && echo 'ok'"
            out, _, _ = ssh.run(check_cmd, timeout=10)
            if "ok" in out:
                sublist3r_bin = "python3 -m sublist3r"
            else:
                self.log("Sublist3r not found on Kali", "info")
                return result

        uid = uuid.uuid4().hex[:8]
        out_f = f"/tmp/_sublist3r_{uid}.txt"

        # Run Sublist3r
        cmd = (
            f"{sublist3r_bin} -d {shlex.quote(domain)} -o {out_f} 2>/dev/null; "
            f"cat {out_f} 2>/dev/null; rm -f {out_f}"
        )

        self.log(f"Kali Sublist3r: {domain}", "info")
        out, err, rc = ssh.run(cmd, timeout=180)  # Sublist3r can be slow

        if out.strip():
            # Strip ANSI color codes
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            out = ansi_escape.sub('', out)

            # Parse output - one subdomain per line
            subdomains = []
            for line in out.strip().splitlines():
                line = line.strip()
                if line and "." in line and not line.startswith("[") and not line.startswith("-"):
                    # Clean up the subdomain
                    sub = line.split()[0] if line.split() else line
                    if sub.endswith(domain) or domain in sub:
                        subdomains.append(sub)

            result["subdomains"] = list(set(subdomains))[:200]
            result["source"] = "kali_sublist3r"

        return result

    # ── Amass via Kali SSH ────────────────────────────────────────────────────

    def _run_amass(self, domain: str) -> dict:
        """Run Amass via Kali SSH for advanced subdomain enumeration.

        Amass is one of the most comprehensive subdomain enumeration tools,
        using multiple data sources including DNS brute-force, web archives,
        certificate transparency, and many APIs.

        Returns: {"subdomains": [...], "source": "kali_amass"|"not_available"}
        """
        result = {"subdomains": [], "source": "not_available"}

        ssh = self._get_ssh()
        if not ssh:
            return result

        # Check if amass is installed
        amass_bin = ssh.which("amass")
        if not amass_bin:
            self.log("Amass not found on Kali", "info")
            return result

        uid = uuid.uuid4().hex[:8]
        out_f = f"/tmp/_amass_{uid}.txt"

        # Run Amass in passive mode (enum -passive) to avoid active DNS queries
        # This uses only passive data sources like CT logs, web archives, etc.
        cmd = (
            f"{amass_bin} enum -passive -d {shlex.quote(domain)} -o {out_f} "
            f"-timeout 3 2>/dev/null; "
            f"cat {out_f} 2>/dev/null; rm -f {out_f}"
        )

        self.log(f"Kali Amass (passive): {domain}", "info")
        out, err, rc = ssh.run(cmd, timeout=240)  # Amass can take time

        if out.strip():
            # Strip ANSI color codes
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            out = ansi_escape.sub('', out)

            # Parse output - one subdomain per line
            subdomains = []
            for line in out.strip().splitlines():
                line = line.strip()
                # Skip info/banner lines
                if not line or line.startswith("[") or line.startswith("*") or ":" in line:
                    continue
                if "." in line and (line.endswith(domain) or domain in line):
                    # Extract just the subdomain (first word if multiple)
                    sub = line.split()[0] if line.split() else line
                    subdomains.append(sub.lower())

            result["subdomains"] = list(set(subdomains))[:300]
            result["source"] = "kali_amass"
            self.log(f"Amass found {len(result['subdomains'])} subdomains", "info")

        return result

    # ── subfinder via Kali SSH ────────────────────────────────────────────────

    def _run_subfinder(self, domain: str) -> dict:
        """Run subfinder via Kali SSH for fast subdomain discovery.

        subfinder is a fast passive subdomain enumeration tool by ProjectDiscovery.
        It uses multiple passive sources like Shodan, VirusTotal, Censys, etc.

        Returns: {"subdomains": [...], "source": "kali_subfinder"|"not_available"}
        """
        result = {"subdomains": [], "source": "not_available"}

        ssh = self._get_ssh()
        if not ssh:
            return result

        # Check if subfinder is installed
        subfinder_bin = ssh.which("subfinder")
        if not subfinder_bin:
            self.log("subfinder not found on Kali", "info")
            return result

        # Run subfinder with silent mode for clean output
        cmd = f"{subfinder_bin} -d {shlex.quote(domain)} -silent -timeout 60 2>/dev/null"

        self.log(f"Kali subfinder: {domain}", "info")
        out, err, rc = ssh.run(cmd, timeout=120)

        if out.strip():
            # Strip ANSI color codes
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            out = ansi_escape.sub('', out)

            # Parse output - one subdomain per line
            subdomains = []
            for line in out.strip().splitlines():
                line = line.strip()
                if line and "." in line and (line.endswith(domain) or domain in line):
                    subdomains.append(line.lower())

            result["subdomains"] = list(set(subdomains))[:300]
            result["source"] = "kali_subfinder"
            self.log(f"subfinder found {len(result['subdomains'])} subdomains", "info")

        return result

    # ── crt.sh Certificate Transparency (Python requests) ─────────────────────

    def _run_crtsh(self, domain: str) -> dict:
        """Query crt.sh Certificate Transparency logs for subdomain discovery.

        Returns: {"subdomains": [...], "source": "crtsh"|"not_available"}
        
        Improvements:
        - Retry mechanism with exponential backoff (crt.sh often rate-limits)
        - Longer timeout (crt.sh can be slow)
        - Fallback to alternative CT log APIs
        """
        result = {"subdomains": [], "source": "not_available"}

        # ═══════════════════════════════════════════════════════════════════════
        # Method 1: crt.sh API with retry + longer timeout
        # ═══════════════════════════════════════════════════════════════════════
        max_retries = 3
        for attempt in range(max_retries):
            try:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                self.log(f"crt.sh query (attempt {attempt + 1}/{max_retries}): {domain}", "info")

                session = make_session(url)
                # Longer timeout: crt.sh can be very slow
                resp = session.get(url, timeout=(10, 60))

                if resp.status_code == 200 and resp.text.strip():
                    import json
                    try:
                        data = json.loads(resp.text)
                        subdomains = set()

                        for entry in data:
                            name_value = entry.get("name_value", "")
                            for name in name_value.split("\n"):
                                name = name.strip().lower()
                                if name.startswith("*."):
                                    name = name[2:]
                                if name.endswith(domain) and name != domain:
                                    subdomains.add(name)

                        result["subdomains"] = list(subdomains)[:200]
                        result["source"] = "crtsh"
                        return result  # Success, return early

                    except json.JSONDecodeError as e:
                        self.log(f"crt.sh JSON parse error: {e}", "warning")
                        
                elif resp.status_code == 503:
                    # Service unavailable - retry with backoff
                    wait_time = 2 ** attempt
                    self.log(f"crt.sh 503, retrying in {wait_time}s...", "info")
                    time.sleep(wait_time)
                    continue
                else:
                    self.log(f"crt.sh returned status {resp.status_code}", "info")

            except requests.exceptions.Timeout:
                self.log(f"crt.sh timeout (attempt {attempt + 1})", "warning")
                time.sleep(2 ** attempt)  # Exponential backoff
                continue
            except Exception as e:
                self.log(f"crt.sh error: {e}", "warning")
                break

        # ═══════════════════════════════════════════════════════════════════════
        # Method 2: Fallback to certspotter.com API (alternative CT log)
        # ═══════════════════════════════════════════════════════════════════════
        if not result["subdomains"]:
            try:
                self.log(f"Trying certspotter.com fallback for {domain}", "info")
                url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
                session = make_session(url)
                resp = session.get(url, timeout=30)
                
                if resp.status_code == 200:
                    import json
                    data = json.loads(resp.text)
                    subdomains = set()
                    
                    for entry in data:
                        for dns_name in entry.get("dns_names", []):
                            name = dns_name.strip().lower()
                            if name.startswith("*."):
                                name = name[2:]
                            if name.endswith(domain) and name != domain:
                                subdomains.add(name)
                    
                    if subdomains:
                        result["subdomains"] = list(subdomains)[:200]
                        result["source"] = "certspotter"
                        self.log(f"certspotter.com: {len(result['subdomains'])} subdomains", "success")
                        return result
                        
            except Exception as e:
                self.log(f"certspotter.com error: {e}", "warning")

        return result

    # ── Wayback Machine Historical URLs (Python requests) ─────────────────────

    def _run_wayback(self, domain: str) -> dict:
        """Query Wayback Machine CDX API for historical URLs.

        Returns: {"urls": [...], "source": "wayback"|"not_available"}
        """
        result = {"urls": [], "source": "not_available"}

        try:
            # Wayback Machine CDX API
            url = (
                f"http://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=500"
            )
            self.log(f"Wayback Machine query: {domain}", "info")

            session = make_session(url)
            resp = session.get(url, timeout=45)

            if resp.status_code == 200 and resp.text.strip():
                import json
                try:
                    data = json.loads(resp.text)
                    # First row is header ["original"], skip it
                    urls = []
                    for row in data[1:]:  # Skip header
                        if row and len(row) > 0:
                            url_str = row[0]
                            # Filter out common junk
                            if not any(ext in url_str.lower() for ext in ['.css', '.js', '.png', '.jpg', '.gif', '.ico', '.woff', '.svg']):
                                urls.append(url_str)

                    # Deduplicate and limit
                    result["urls"] = list(dict.fromkeys(urls))[:300]
                    result["source"] = "wayback"

                except json.JSONDecodeError as e:
                    self.log(f"Wayback JSON parse error: {e}", "warning")
            else:
                self.log(f"Wayback returned status {resp.status_code}", "info")

        except Exception as e:
            self.log(f"Wayback error: {e}", "warning")

        return result

    def _run_shodan(self, ip: str) -> dict:
        """Query Shodan API for host intelligence.

        Requires SHODAN_API_KEY environment variable.
        Returns: {"ports": [...], "vulns": [...], "hostnames": [...], "source": "..."}
        """
        import os
        result = {"ports": [], "vulns": [], "hostnames": [], "source": "not_available"}

        api_key = os.environ.get("SHODAN_API_KEY", "").strip()
        if not api_key:
            self.log("Shodan skipped — SHODAN_API_KEY not set", "info")
            result["source"] = "no_api_key"
            return result

        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            self.log(f"Shodan query: {ip}", "info")

            session = make_session(url)
            resp = session.get(url, timeout=30)

            if resp.status_code == 200:
                import json
                data = resp.json()

                # Extract ports
                ports_data = data.get("data", [])
                ports = []
                for item in ports_data:
                    port_info = {
                        "port": item.get("port"),
                        "protocol": item.get("transport", "tcp"),
                        "service": item.get("product", "") or item.get("_shodan", {}).get("module", ""),
                        "version": item.get("version", ""),
                        "banner": (item.get("data", "") or "")[:200],  # Limit banner size
                    }
                    ports.append(port_info)
                result["ports"] = ports

                # Extract vulnerabilities
                vulns = data.get("vulns", [])
                result["vulns"] = vulns[:50]  # Limit to 50 CVEs

                # Extract hostnames
                hostnames = data.get("hostnames", [])
                result["hostnames"] = hostnames[:20]

                # Additional info
                result["os"] = data.get("os", "")
                result["org"] = data.get("org", "")
                result["isp"] = data.get("isp", "")
                result["country"] = data.get("country_name", "")
                result["city"] = data.get("city", "")
                result["last_update"] = data.get("last_update", "")
                result["source"] = "shodan_api"

                self.log(f"Shodan found {len(ports)} ports, {len(vulns)} vulns for {ip}", "success")

            elif resp.status_code == 404:
                self.log(f"Shodan: No data found for {ip}", "info")
                result["source"] = "no_data"
            elif resp.status_code == 401:
                self.log("Shodan: Invalid API key", "warning")
                result["source"] = "invalid_api_key"
            else:
                self.log(f"Shodan returned status {resp.status_code}", "warning")
                result["source"] = f"error_{resp.status_code}"

        except Exception as e:
            self.log(f"Shodan error: {e}", "warning")
            result["source"] = "error"

        return result

    # ══════════════════════════════════════════════════════════════════════════
    # recon-ng — OSINT Framework via Kali SSH
    # ══════════════════════════════════════════════════════════════════════════

    def _run_recon_ng(self, domain: str) -> dict:
        """Run recon-ng modules via Kali SSH for OSINT reconnaissance.

        Modules used:
        - recon/domains-hosts/hackertarget: Subdomain enumeration
        - recon/domains-contacts/whois_pocs: Contact extraction
        - recon/profiles-profiles/namechk: Social profile search
        - recon/hosts-hosts/resolve: Host resolution

        Returns: {"emails": [...], "hosts": [...], "profiles": [...], "credentials": [], "source": "..."}
        """
        result = {"emails": [], "hosts": [], "profiles": [], "credentials": [], "source": "not_available"}

        ssh = self._get_ssh()
        if not ssh:
            self.log("recon-ng skipped — Kali SSH not available", "info")
            result["source"] = "ssh_unavailable"
            return result

        try:
            # Check if recon-ng is installed
            check_cmd = "which recon-ng"
            output, stderr, exit_code = ssh.run(check_cmd)
            if exit_code != 0:
                self.log("recon-ng not found on Kali", "warning")
                result["source"] = "not_installed"
                return result

            recon_ng_bin = output.strip()
            self.log(f"recon-ng found at: {recon_ng_bin}", "info")

            # Create a temporary workspace and run modules
            workspace = f"scan_{domain.replace('.', '_')}_{uuid.uuid4().hex[:8]}"

            # Build recon-ng script
            # Using the most reliable passive modules
            script = f"""
workspaces create {workspace}
db insert domains domain={domain}
marketplace install recon/domains-hosts/hackertarget
marketplace install recon/domains-contacts/whois_pocs
modules load recon/domains-hosts/hackertarget
run
modules load recon/domains-contacts/whois_pocs
run
show hosts
show contacts
workspaces delete {workspace}
exit
"""
            # Execute recon-ng with script via stdin
            cmd = f"echo '{script}' | {recon_ng_bin} --no-version --no-check --no-analytics 2>/dev/null"
            output, stderr, exit_code = ssh.run(cmd, timeout=120)

            if exit_code != 0 and not output:
                self.log(f"recon-ng execution error: {stderr}", "warning")
                result["source"] = "exec_error"
                return result

            # Parse output
            result = self._parse_recon_ng_output(output, domain)
            result["source"] = "recon_ng_kali"

        except Exception as e:
            self.log(f"recon-ng error: {e}", "warning")
            result["source"] = "error"

        return result

    def _parse_recon_ng_output(self, output: str, domain: str) -> dict:
        """Parse recon-ng output to extract hosts, emails, and profiles."""
        result = {"emails": [], "hosts": [], "profiles": [], "credentials": []}

        lines = output.split('\n')
        current_section = None

        for line in lines:
            line = line.strip()

            # Detect sections
            if 'show hosts' in line.lower() or '| host |' in line.lower():
                current_section = 'hosts'
                continue
            elif 'show contacts' in line.lower() or '| email |' in line.lower():
                current_section = 'contacts'
                continue

            # Skip headers and separators
            if not line or line.startswith('+') or line.startswith('|--'):
                continue

            # Parse table rows
            if line.startswith('|') and current_section:
                parts = [p.strip() for p in line.strip('|').split('|')]

                if current_section == 'hosts' and len(parts) >= 1:
                    host = parts[0].strip()
                    if host and domain in host and host not in result["hosts"]:
                        result["hosts"].append(host)

                elif current_section == 'contacts' and len(parts) >= 1:
                    # Try to find email in parts
                    for part in parts:
                        if '@' in part and part not in result["emails"]:
                            result["emails"].append(part.strip())

            # Also look for emails in freeform text
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            emails_found = re.findall(email_pattern, line)
            for email in emails_found:
                if domain in email.lower() and email not in result["emails"]:
                    result["emails"].append(email)

        return result

    # ══════════════════════════════════════════════════════════════════════════
    # Google Dorks — Search Engine Dorking
    # ══════════════════════════════════════════════════════════════════════════

    def _run_google_dorks(self, domain: str) -> dict:
        """Run Google Dorks queries to find exposed files and sensitive pages.

        Uses multiple search engines with fallback chain:
        1. Bing (primary)
        2. DuckDuckGo (fallback)
        3. Kali googler tool (via SSH, if available)

        Returns: {"files": [...], "pages": [...], "exposed": [...], "source": "..."}
        """
        import os
        import urllib.parse

        result = {"files": [], "pages": [], "exposed": [], "source": "not_available"}

        # Dork patterns categorized by type
        dorks = {
            "files": [
                f"site:{domain} filetype:pdf",
                f"site:{domain} filetype:doc OR filetype:docx",
                f"site:{domain} filetype:xls OR filetype:xlsx",
                f"site:{domain} filetype:sql",
                f"site:{domain} filetype:log",
                f"site:{domain} filetype:bak OR filetype:backup",
                f"site:{domain} filetype:env",
                f"site:{domain} filetype:config OR filetype:conf OR filetype:cfg",
            ],
            "pages": [
                f"site:{domain} inurl:admin",
                f"site:{domain} inurl:login",
                f"site:{domain} inurl:dashboard",
                f"site:{domain} inurl:cpanel",
                f"site:{domain} inurl:phpmyadmin",
                f"site:{domain} intitle:\"index of\"",
            ],
            "exposed": [
                f"site:{domain} \"mysql error\"",
                f"site:{domain} \"sql syntax\"",
                f"site:{domain} \"password\" filetype:txt",
                f"site:{domain} \"api_key\" OR \"apikey\"",
                f"site:{domain} \"secret\" OR \"token\"",
                f"site:{domain} inurl:.git",
                f"site:{domain} inurl:.svn",
                f"site:{domain} \"phpinfo()\"",
            ],
        }

        found_results = {"files": set(), "pages": set(), "exposed": set()}
        sources_used = []

        # ═══════════════════════════════════════════════════════════════════════
        # Method 1: Bing Search (primary)
        # ═══════════════════════════════════════════════════════════════════════
        session = make_session("https://www.bing.com")
        bing_worked = False

        for category, queries in dorks.items():
            for query in queries:
                try:
                    bing_results = self._search_bing(session, query)
                    for url in bing_results:
                        if domain in url:
                            found_results[category].add(url)
                            bing_worked = True
                    time.sleep(0.8)  # Slightly longer delay
                except Exception as e:
                    self.log(f"Bing dork error ({query[:25]}...): {e}", "warning")
                    continue

        if bing_worked:
            sources_used.append("bing")

        # ═══════════════════════════════════════════════════════════════════════
        # Method 2: DuckDuckGo fallback if Bing returned nothing
        # ═══════════════════════════════════════════════════════════════════════
        total_bing = sum(len(found_results[k]) for k in found_results)
        if total_bing == 0:
            self.log("Bing returned no results, trying DuckDuckGo...", "info")
            ddg_session = make_session("https://html.duckduckgo.com")

            for category, queries in dorks.items():
                for query in queries:
                    try:
                        ddg_results = self._search_duckduckgo(ddg_session, query)
                        for url in ddg_results:
                            if domain in url:
                                found_results[category].add(url)
                        time.sleep(1.0)
                    except Exception as e:
                        continue

            if sum(len(found_results[k]) for k in found_results) > 0:
                sources_used.append("duckduckgo")

        # ═══════════════════════════════════════════════════════════════════════
        # Method 3: Kali googler tool (via SSH) - best for bypassing rate limits
        # ═══════════════════════════════════════════════════════════════════════
        total_so_far = sum(len(found_results[k]) for k in found_results)
        if total_so_far == 0:
            ssh = self._get_ssh()
            if ssh:
                googler_bin = ssh.which("googler")
                if googler_bin:
                    self.log("Trying Kali googler for dorking...", "info")
                    try:
                        # Use a subset of dorks (most important ones)
                        priority_dorks = [
                            (f"site:{domain} inurl:admin", "pages"),
                            (f"site:{domain} inurl:login", "pages"),
                            (f"site:{domain} filetype:pdf", "files"),
                            (f"site:{domain} filetype:sql", "files"),
                            (f"site:{domain} \"mysql error\"", "exposed"),
                            (f"site:{domain} inurl:.git", "exposed"),
                        ]
                        
                        for query, category in priority_dorks:
                            import shlex
                            cmd = f"{googler_bin} -n 10 --np -C {shlex.quote(query)} 2>/dev/null | grep -E '^https?://'"
                            output, _, _ = ssh.run(cmd, timeout=20)
                            
                            if output:
                                for line in output.strip().split('\n'):
                                    url = line.strip()
                                    if url.startswith('http') and domain in url:
                                        found_results[category].add(url)
                            time.sleep(2)  # Longer delay for Google
                        
                        if sum(len(found_results[k]) for k in found_results) > 0:
                            sources_used.append("kali_googler")
                            
                    except Exception as e:
                        self.log(f"Kali googler error: {e}", "warning")

        # Convert sets to lists
        result["files"] = list(found_results["files"])[:50]
        result["pages"] = list(found_results["pages"])[:50]
        result["exposed"] = list(found_results["exposed"])[:50]

        # Determine source
        total = len(result["files"]) + len(result["pages"]) + len(result["exposed"])
        if total > 0:
            result["source"] = "+".join(sources_used) if sources_used else "mixed_dorks"
        else:
            result["source"] = "no_results"

        result["queries_used"] = sum(len(v) for v in dorks.values())

        return result

    def _search_bing(self, session, query: str, max_results: int = 10) -> list:
        """Search Bing and extract result URLs.

        Args:
            session: requests session
            query: search query (dork)
            max_results: maximum number of results to return

        Returns: List of URLs found
        """
        import urllib.parse

        results = []
        encoded_query = urllib.parse.quote_plus(query)
        url = f"https://www.bing.com/search?q={encoded_query}&count={max_results}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        try:
            resp = session.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                # Parse Bing search results
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")

                # Bing result links are in <li class="b_algo"> -> <h2> -> <a href>
                for item in soup.select("li.b_algo h2 a"):
                    href = item.get("href", "")
                    if href and href.startswith("http"):
                        results.append(href)
                        if len(results) >= max_results:
                            break

                # Also check for cite elements (displayed URLs)
                for cite in soup.select("li.b_algo cite"):
                    text = cite.get_text(strip=True)
                    if text and text.startswith("http"):
                        if text not in results:
                            results.append(text)

        except Exception as e:
            self.log(f"Bing search error: {e}", "warning")

        return results[:max_results]

    def _search_duckduckgo(self, session, query: str, max_results: int = 10) -> list:
        """Search DuckDuckGo HTML version (fallback).

        Note: DuckDuckGo HTML is harder to parse and has anti-scraping measures.

        Args:
            session: requests session
            query: search query (dork)
            max_results: maximum number of results to return

        Returns: List of URLs found
        """
        import urllib.parse

        results = []
        encoded_query = urllib.parse.quote_plus(query)
        url = f"https://html.duckduckgo.com/html/?q={encoded_query}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        }

        try:
            resp = session.get(url, headers=headers, timeout=15)
            if resp.status_code == 200:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(resp.text, "html.parser")

                # DuckDuckGo HTML results are in <a class="result__a">
                for link in soup.select("a.result__a"):
                    href = link.get("href", "")
                    if href and "duckduckgo.com" not in href:
                        # DuckDuckGo wraps URLs in redirect links
                        if "uddg=" in href:
                            # Extract actual URL from redirect
                            import urllib.parse as urlparse
                            parsed = urlparse.parse_qs(urlparse.urlparse(href).query)
                            actual_url = parsed.get("uddg", [""])[0]
                            if actual_url:
                                results.append(actual_url)
                        else:
                            results.append(href)

                        if len(results) >= max_results:
                            break

        except Exception as e:
            self.log(f"DuckDuckGo search error: {e}", "warning")

        return results[:max_results]
