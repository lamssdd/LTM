"""
tools/katana_runner.py — Katana wrapper for advanced web crawling.

Katana is a next-generation crawling framework from ProjectDiscovery that:
- Crawls websites for URLs, endpoints, forms
- Extracts JavaScript endpoints (very powerful JS parsing)
- Handles SPAs and dynamic content
- Outputs JSON for easy parsing

Role in Phase 1: ACTIVE recon - deep crawling for attack surface discovery
Should run: After httpx (confirmed live hosts)
            Complements existing crawler with better JS endpoint discovery

Key advantage over basic crawlers:
- Headless browser support for JS-rendered content
- Automatic JS file parsing for API endpoints
- Form extraction with hidden fields
- Configurable crawl depth and scope

Installation on Kali:
    sudo apt install katana
    # or
    go install github.com/projectdiscovery/katana/cmd/katana@latest

Usage:
    from tools.katana_runner import KatanaRunner
    runner = KatanaRunner(ssh_client=ssh, log_callback=log)
    result = runner.run("https://example.com")
"""
import json
import os
import re
import shlex
import shutil
import subprocess
from typing import Callable, List, Optional, Union
from urllib.parse import urlparse, parse_qs

LogCallback = Optional[Callable[[str, str], None]]


class KatanaRunner:
    """
    Katana wrapper for advanced web crawling.
    
    Output schema:
    {
        "discovered_urls": [
            {
                "url": "https://example.com/api/users",
                "method": "GET",
                "source": "crawl",
                "tag": "a",
                "attribute": "href"
            }
        ],
        "js_files": ["https://example.com/static/app.js"],
        "js_endpoints": [
            {
                "endpoint": "/api/v1/users",
                "source_file": "app.js",
                "method": "GET"
            }
        ],
        "forms": [
            {
                "action": "/login",
                "method": "POST",
                "inputs": ["username", "password"],
                "hidden_fields": [{"name": "csrf", "value": "xxx"}]
            }
        ],
        "query_params": {
            "id": ["1", "2"],
            "page": ["1"]
        },
        "endpoints_by_category": {
            "api": [...],
            "auth": [...],
            "admin": [...],
            "static": [...]
        },
        "total_urls": 150,
        "source": "katana_kali" | "katana_local" | "not_available"
    }
    """
    
    # Katana flags for comprehensive crawling
    KATANA_FLAGS = [
        "-silent",              # Suppress banner
        "-jsonl",               # JSON Lines output
        "-depth", "3",          # Crawl depth
        "-js-crawl",            # Enable JavaScript parsing
        "-known-files", "all",  # Check for common files
        "-form-extraction",     # Extract forms
        "-timeout", "15",       # Request timeout
        "-crawl-duration", "180", # Max crawl time (3 min)
        "-rate-limit", "50",    # Requests per second
        "-concurrency", "10",   # Concurrent requests
        "-no-color",            # Disable color output
    ]
    
    # Patterns for categorizing endpoints
    ENDPOINT_PATTERNS = {
        "api": re.compile(r"/(api|rest|graphql|v\d+)/", re.I),
        "auth": re.compile(r"/(login|logout|signin|signout|register|auth|oauth|sso|session|token)", re.I),
        "admin": re.compile(r"/(admin|administrator|dashboard|panel|manage|backend|console|cp)", re.I),
        "upload": re.compile(r"/(upload|file|attachment|media|asset|image)", re.I),
        "search": re.compile(r"/(search|find|query|lookup)", re.I),
    }
    
    def __init__(
        self,
        ssh_client=None,
        log_callback: LogCallback = None,
        timeout: int = 300,
    ):
        """
        Initialize Katana runner.
        
        Args:
            ssh_client: KaliSSHClient instance for remote execution
            log_callback: Function(message, level) for logging
            timeout: Command timeout in seconds
        """
        self._ssh = ssh_client
        self._log = log_callback or (lambda msg, level="info": None)
        self._timeout = timeout
    
    def _log_msg(self, msg: str, level: str = "info"):
        self._log(msg, level)
    
    def run(
        self,
        target: Union[str, List[str]],
        depth: int = 3,
        js_crawl: bool = True,
        form_extract: bool = True,
        extra_flags: List[str] = None,
    ) -> dict:
        """
        Run Katana crawl on target URL(s).
        
        Args:
            target: URL or list of URLs to crawl
            depth: Crawl depth (default: 3)
            js_crawl: Enable JavaScript endpoint extraction
            form_extract: Enable form extraction
            extra_flags: Additional Katana flags
            
        Returns:
            dict with crawl results and metadata
        """
        result = {
            "discovered_urls": [],
            "js_files": [],
            "js_endpoints": [],
            "forms": [],
            "query_params": {},
            "endpoints_by_category": {
                "api": [], "auth": [], "admin": [], "upload": [], "search": [], "other": []
            },
            "total_urls": 0,
            "source": "not_available",
        }
        
        # Normalize target to list
        if isinstance(target, str):
            targets = [target]
        else:
            targets = list(target)
        
        if not targets:
            self._log_msg("katana: No target provided", "warning")
            return result
        
        self._log_msg(f"katana: Crawling {len(targets)} target(s)", "info")
        
        # Build flags
        flags = self._build_flags(depth, js_crawl, form_extract, extra_flags)
        
        # Try Kali SSH first, then local
        output = None
        source = "not_available"
        
        if self._ssh:
            output, source = self._run_via_ssh(targets, flags)
        
        if output is None:
            output, source = self._run_local(targets, flags)
        
        if output:
            parsed = self._parse_output(output)
            result.update(parsed)
            result["source"] = source
            result["total_urls"] = len(result["discovered_urls"])
            
            self._log_msg(
                f"katana: {result['total_urls']} URLs, {len(result['js_files'])} JS files, "
                f"{len(result['js_endpoints'])} JS endpoints, {len(result['forms'])} forms (source={source})",
                "success" if result["total_urls"] > 0 else "info"
            )
        else:
            self._log_msg("katana: No output received", "warning")
        
        return result
    
    def _build_flags(
        self,
        depth: int,
        js_crawl: bool,
        form_extract: bool,
        extra_flags: List[str] = None,
    ) -> List[str]:
        """Build Katana flags based on options."""
        flags = [
            "-silent",
            "-jsonl",
            "-depth", str(depth),
            "-timeout", "15",
            "-crawl-duration", "180",
            "-rate-limit", "50",
            "-concurrency", "10",
            "-no-color",
            "-known-files", "all",
        ]
        
        if js_crawl:
            flags.append("-js-crawl")
        
        if form_extract:
            flags.append("-form-extraction")
        
        return flags + (extra_flags or [])
    
    def _run_via_ssh(
        self,
        targets: List[str],
        flags: List[str],
    ) -> tuple:
        """Execute Katana via Kali SSH."""
        if not self._ssh:
            return None, "no_ssh"
        
        try:
            if not self._ssh._client:
                if not self._ssh.connect():
                    return None, "ssh_connect_failed"
            
            # Check if katana is available
            katana_bin = self._ssh.which("katana")
            if not katana_bin:
                self._log_msg("katana not found on Kali", "info")
                return None, "not_installed"
            
            # Use setsid so katana runs in a new session (avoids SIGINT from
            # paramiko's non-TTY SSH channel) and timeout prevents hanging.
            crawl_secs = self._timeout - 10 if self._timeout > 15 else self._timeout
            wrap = f"setsid timeout {crawl_secs}"

            # Build command
            if len(targets) == 1:
                cmd = f"{wrap} {katana_bin} -u {shlex.quote(targets[0])} {' '.join(flags)}"
            else:
                targets_input = "\n".join(targets)
                cmd = f"echo {shlex.quote(targets_input)} | {wrap} {katana_bin} {' '.join(flags)}"

            self._log_msg(f"Kali katana: {targets[0][:50]}...", "info")
            
            out, err, rc = self._ssh.run(cmd, timeout=self._timeout)
            
            if rc == 0 and out.strip():
                return out, "katana_kali"
            elif rc == 0:
                return "", "katana_kali_empty"
            else:
                self._log_msg(f"katana SSH error: {err[:200] if err else 'no output'}", "warning")
                return None, "ssh_error"
                
        except Exception as e:
            self._log_msg(f"katana SSH exception: {e}", "warning")
            return None, "ssh_exception"
    
    def _run_local(
        self,
        targets: List[str],
        flags: List[str],
    ) -> tuple:
        """Execute Katana locally."""
        katana_bin = shutil.which("katana")
        if not katana_bin:
            self._log_msg("katana not installed locally", "info")
            return None, "not_installed"
        
        try:
            if len(targets) == 1:
                cmd = [katana_bin, "-u", targets[0]] + flags
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                )
            else:
                targets_input = "\n".join(targets)
                proc = subprocess.run(
                    [katana_bin] + flags,
                    input=targets_input,
                    capture_output=True,
                    text=True,
                    timeout=self._timeout,
                )
            
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout, "katana_local"
            elif proc.returncode == 0:
                return "", "katana_local_empty"
            else:
                self._log_msg(f"katana local error: {proc.stderr[:200] if proc.stderr else 'no output'}", "warning")
                return None, "local_error"
                
        except subprocess.TimeoutExpired:
            self._log_msg("katana local timeout", "warning")
            return None, "timeout"
        except Exception as e:
            self._log_msg(f"katana local exception: {e}", "warning")
            return None, "local_exception"
    
    def _parse_output(self, output: str) -> dict:
        """
        Parse Katana JSONL output.
        
        Returns dict with all crawl data.
        """
        discovered_urls = []
        js_files = set()
        js_endpoints = []
        forms = []
        query_params = {}
        endpoints_by_category = {
            "api": [], "auth": [], "admin": [], "upload": [], "search": [], "other": []
        }
        
        seen_urls = set()
        
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                url = data.get("request", {}).get("endpoint") or data.get("endpoint") or ""
                
                if not url:
                    continue
                
                # Deduplicate
                if url in seen_urls:
                    continue
                seen_urls.add(url)
                
                # Basic URL record
                record = {
                    "url": url,
                    "method": data.get("request", {}).get("method", "GET"),
                    "source": data.get("source", "crawl"),
                    "tag": data.get("tag", ""),
                    "attribute": data.get("attribute", ""),
                }
                discovered_urls.append(record)
                
                # Categorize endpoint
                self._categorize_endpoint(url, endpoints_by_category)
                
                # Extract JS files
                if url.endswith(".js") or ".js?" in url:
                    js_files.add(url)
                
                # Extract query params
                self._extract_params(url, query_params)
                
                # Extract forms (if present in data)
                if data.get("form"):
                    form_data = data["form"]
                    forms.append({
                        "action": form_data.get("action", ""),
                        "method": form_data.get("method", "GET"),
                        "inputs": form_data.get("inputs", []),
                        "hidden_fields": form_data.get("hidden", []),
                    })
                
                # Extract JS endpoints (from js-crawl)
                if data.get("source") == "js" or "js" in str(data.get("tag", "")).lower():
                    parsed = urlparse(url)
                    js_endpoints.append({
                        "endpoint": parsed.path,
                        "full_url": url,
                        "method": record["method"],
                        "source_tag": data.get("tag", ""),
                    })
                    
            except json.JSONDecodeError:
                # Plain URL output
                if line.startswith("http"):
                    if line not in seen_urls:
                        seen_urls.add(line)
                        discovered_urls.append({
                            "url": line,
                            "method": "GET",
                            "source": "crawl",
                            "tag": "",
                            "attribute": "",
                        })
                        self._categorize_endpoint(line, endpoints_by_category)
                        self._extract_params(line, query_params)
                        
                        if line.endswith(".js") or ".js?" in line:
                            js_files.add(line)
        
        return {
            "discovered_urls": discovered_urls,
            "js_files": list(js_files),
            "js_endpoints": js_endpoints,
            "forms": forms,
            "query_params": query_params,
            "endpoints_by_category": endpoints_by_category,
        }
    
    def _categorize_endpoint(self, url: str, categories: dict):
        """Categorize URL into endpoint categories."""
        categorized = False
        for category, pattern in self.ENDPOINT_PATTERNS.items():
            if pattern.search(url):
                if url not in categories[category]:
                    categories[category].append(url)
                categorized = True
                break
        
        if not categorized:
            if url not in categories["other"]:
                categories["other"].append(url)
    
    def _extract_params(self, url: str, params: dict):
        """Extract query parameters from URL."""
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            for param, values in query.items():
                if param not in params:
                    params[param] = []
                for v in values:
                    if v not in params[param]:
                        params[param].append(v)
        except Exception:
            pass
    
    def get_attack_surface(self, result: dict) -> dict:
        """
        Extract attack surface summary from crawl results.
        Useful for ReportAgent.
        """
        return {
            "total_endpoints": result.get("total_urls", 0),
            "api_endpoints": len(result.get("endpoints_by_category", {}).get("api", [])),
            "auth_endpoints": len(result.get("endpoints_by_category", {}).get("auth", [])),
            "admin_endpoints": len(result.get("endpoints_by_category", {}).get("admin", [])),
            "js_files": len(result.get("js_files", [])),
            "js_endpoints": len(result.get("js_endpoints", [])),
            "forms": len(result.get("forms", [])),
            "unique_params": len(result.get("query_params", {})),
        }


# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    
    from dotenv import load_dotenv
    load_dotenv()
    
    from tools.kali_ssh_client import KaliSSHClient
    
    def log(msg, level="info"):
        print(f"[{level.upper()}] {msg}")
    
    ssh = KaliSSHClient(log_callback=log)
    if ssh.connect():
        runner = KatanaRunner(ssh_client=ssh, log_callback=log, timeout=120)
        
        result = runner.run(
            target="http://testfire.net",
            depth=2,
            js_crawl=True,
            form_extract=True,
        )
        
        print("\n=== KATANA Results Summary ===")
        print(f"Total URLs: {result['total_urls']}")
        print(f"JS Files: {len(result['js_files'])}")
        print(f"JS Endpoints: {len(result['js_endpoints'])}")
        print(f"Forms: {len(result['forms'])}")
        print(f"Query Params: {list(result['query_params'].keys())}")
        
        print("\n=== Endpoints by Category ===")
        for cat, urls in result['endpoints_by_category'].items():
            if urls:
                print(f"  {cat}: {len(urls)}")
        
        print("\n=== Attack Surface ===")
        print(json.dumps(runner.get_attack_surface(result), indent=2))
        
        ssh.close()
    else:
        print("SSH connection failed")
