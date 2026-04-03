"""
tools/projectdiscovery_tools.py — Unified interface for ProjectDiscovery tools.

This module provides a high-level interface for orchestrating:
- httpx  → HTTP probing, host validation
- dnsx   → DNS resolution, subdomain validation
- naabu  → Fast port scanning
- katana → Advanced web crawling

Flow Integration:
    [Subdomain Enum] → dnsx → httpx → naabu → katana
         │                │       │       │       │
    sublist3r/crt.sh  resolve  probe   scan   crawl

Usage:
    from tools.projectdiscovery_tools import ProjectDiscoveryToolkit
    
    toolkit = ProjectDiscoveryToolkit(ssh_client=ssh, log_callback=log)
    
    # Full pipeline
    result = toolkit.run_full_pipeline("example.com", subdomains=["sub1", "sub2"])
    
    # Individual tools
    dns_result = toolkit.run_dnsx(["sub1.example.com"])
    http_result = toolkit.run_httpx(["sub1.example.com"])
    port_result = toolkit.run_naabu(["192.168.1.1"])
    crawl_result = toolkit.run_katana("https://example.com")
"""
import os
from typing import Callable, List, Optional

from tools.httpx_runner import HttpxRunner
from tools.dnsx_runner import DnsxRunner
from tools.naabu_runner import NaabuRunner
from tools.katana_runner import KatanaRunner

LogCallback = Optional[Callable[[str, str], None]]


class ProjectDiscoveryToolkit:
    """
    Unified interface for ProjectDiscovery tools.
    
    Orchestrates the tools in optimal order:
    1. dnsx  - Resolve subdomains to IPs, validate alive
    2. httpx - Probe alive hosts for HTTP services
    3. naabu - Fast port scan on resolved IPs
    4. katana - Deep crawl on live HTTP endpoints
    
    Output schema:
    {
        "dnsx": {...},       # DNS resolution results
        "httpx": {...},      # HTTP probing results
        "naabu": {...},      # Port scan results
        "katana": {...},     # Crawl results
        "summary": {
            "total_subdomains_input": 10,
            "resolved_hosts": 8,
            "alive_http_hosts": 6,
            "total_open_ports": 15,
            "total_urls_crawled": 250,
            "total_forms": 5,
            "total_js_endpoints": 30
        }
    }
    """
    
    def __init__(
        self,
        ssh_client=None,
        log_callback: LogCallback = None,
        timeout: int = 300,
    ):
        """
        Initialize ProjectDiscovery toolkit.
        
        Args:
            ssh_client: KaliSSHClient for remote execution
            log_callback: Logging function
            timeout: Default timeout for tools
        """
        self._ssh = ssh_client
        self._log = log_callback or (lambda msg, level="info": None)
        self._timeout = timeout
        
        # Initialize individual runners
        self._dnsx = DnsxRunner(ssh_client=ssh_client, log_callback=log_callback, timeout=timeout)
        self._httpx = HttpxRunner(ssh_client=ssh_client, log_callback=log_callback, timeout=timeout)
        self._naabu = NaabuRunner(ssh_client=ssh_client, log_callback=log_callback, timeout=timeout)
        self._katana = KatanaRunner(ssh_client=ssh_client, log_callback=log_callback, timeout=timeout)
    
    def _log_msg(self, msg: str, level: str = "info"):
        self._log(msg, level)
    
    # ── Individual Tool Methods ───────────────────────────────────────────────
    
    def run_dnsx(self, hosts: List[str], **kwargs) -> dict:
        """Run dnsx DNS resolution."""
        return self._dnsx.run(hosts, **kwargs)
    
    def run_httpx(self, hosts: List[str], **kwargs) -> dict:
        """Run httpx HTTP probing."""
        return self._httpx.run(hosts, **kwargs)
    
    def run_naabu(self, hosts: List[str], **kwargs) -> dict:
        """Run naabu port scanning."""
        return self._naabu.run(hosts, **kwargs)
    
    def run_katana(self, target, **kwargs) -> dict:
        """Run katana web crawling."""
        return self._katana.run(target, **kwargs)
    
    # ── Pipeline Methods ──────────────────────────────────────────────────────
    
    def run_subdomain_validation(self, subdomains: List[str]) -> dict:
        """
        Stage 1: Validate subdomains via DNS + HTTP probing.
        
        Flow: subdomains → dnsx → httpx
        
        Returns dict with resolved and alive hosts.
        """
        self._log_msg(f"[Stage 1] Subdomain validation: {len(subdomains)} domains", "info")
        
        result = {
            "input_count": len(subdomains),
            "dnsx": {},
            "httpx": {},
            "alive_hosts": [],
            "resolved_ips": [],
        }
        
        # Step 1: DNS resolution
        self._log_msg("[1.1] Running dnsx for DNS resolution...", "info")
        dns_result = self._dnsx.run(subdomains)
        result["dnsx"] = dns_result
        
        alive_domains = self._dnsx.get_alive_hosts(dns_result)
        result["resolved_ips"] = self._dnsx.get_all_ips(dns_result)
        
        if not alive_domains:
            self._log_msg("No domains resolved, skipping httpx", "warning")
            return result
        
        # Step 2: HTTP probing
        self._log_msg(f"[1.2] Running httpx on {len(alive_domains)} resolved hosts...", "info")
        http_result = self._httpx.run(alive_domains)
        result["httpx"] = http_result
        
        # Extract alive HTTP hosts
        result["alive_hosts"] = [
            h["url"] for h in http_result.get("probed_hosts", [])
            if h.get("status_code") and h["status_code"] < 500
        ]
        
        self._log_msg(
            f"[Stage 1] Complete: {len(result['alive_hosts'])} alive HTTP hosts",
            "success"
        )
        
        return result
    
    def run_port_discovery(self, hosts: List[str], top_ports: int = 1000) -> dict:
        """
        Stage 2: Fast port discovery.
        
        Flow: hosts/IPs → naabu
        
        Returns dict with open ports.
        """
        self._log_msg(f"[Stage 2] Port discovery: {len(hosts)} hosts", "info")
        
        result = self._naabu.run(hosts, top_ports=top_ports)
        
        self._log_msg(
            f"[Stage 2] Complete: {result.get('total_open', 0)} open ports",
            "success"
        )
        
        return result
    
    def run_deep_crawl(self, urls: List[str], depth: int = 3) -> dict:
        """
        Stage 3: Deep web crawling.
        
        Flow: live URLs → katana
        
        Returns dict with crawl results.
        """
        self._log_msg(f"[Stage 3] Deep crawl: {len(urls)} URLs", "info")
        
        # Crawl each URL
        combined_result = {
            "discovered_urls": [],
            "js_files": [],
            "js_endpoints": [],
            "forms": [],
            "query_params": {},
            "endpoints_by_category": {
                "api": [], "auth": [], "admin": [], "upload": [], "search": [], "other": []
            },
            "total_urls": 0,
            "sources": [],
        }
        
        for url in urls[:5]:  # Limit to 5 URLs to avoid timeout
            self._log_msg(f"Crawling: {url[:50]}...", "info")
            crawl = self._katana.run(url, depth=depth)
            
            # Merge results
            combined_result["discovered_urls"].extend(crawl.get("discovered_urls", []))
            combined_result["js_files"].extend(crawl.get("js_files", []))
            combined_result["js_endpoints"].extend(crawl.get("js_endpoints", []))
            combined_result["forms"].extend(crawl.get("forms", []))
            combined_result["sources"].append(crawl.get("source", "unknown"))
            
            # Merge query params
            for param, values in crawl.get("query_params", {}).items():
                if param not in combined_result["query_params"]:
                    combined_result["query_params"][param] = []
                combined_result["query_params"][param].extend(values)
            
            # Merge categories
            for cat, urls_list in crawl.get("endpoints_by_category", {}).items():
                if cat in combined_result["endpoints_by_category"]:
                    combined_result["endpoints_by_category"][cat].extend(urls_list)
        
        # Deduplicate
        combined_result["discovered_urls"] = self._dedupe_urls(combined_result["discovered_urls"])
        combined_result["js_files"] = list(set(combined_result["js_files"]))
        combined_result["total_urls"] = len(combined_result["discovered_urls"])
        
        self._log_msg(
            f"[Stage 3] Complete: {combined_result['total_urls']} URLs, "
            f"{len(combined_result['forms'])} forms",
            "success"
        )
        
        return combined_result
    
    def run_full_pipeline(
        self,
        domain: str,
        subdomains: List[str] = None,
        port_scan: bool = True,
        deep_crawl: bool = True,
        crawl_depth: int = 3,
    ) -> dict:
        """
        Run full ProjectDiscovery pipeline.
        
        Flow:
            subdomains → dnsx → httpx → naabu → katana
        
        Args:
            domain: Main domain (e.g., "example.com")
            subdomains: List of subdomains to validate (optional)
            port_scan: Run naabu port scan
            deep_crawl: Run katana deep crawl
            crawl_depth: Katana crawl depth
            
        Returns:
            Comprehensive dict with all results
        """
        self._log_msg(f"=== ProjectDiscovery Pipeline: {domain} ===", "info")
        
        result = {
            "domain": domain,
            "dnsx": {},
            "httpx": {},
            "naabu": {},
            "katana": {},
            "summary": {
                "total_subdomains_input": 0,
                "resolved_hosts": 0,
                "alive_http_hosts": 0,
                "total_open_ports": 0,
                "total_urls_crawled": 0,
                "total_forms": 0,
                "total_js_endpoints": 0,
            },
        }
        
        # Prepare subdomain list
        if subdomains:
            all_subs = list(set(subdomains))
        else:
            all_subs = [domain, f"www.{domain}"]
        
        result["summary"]["total_subdomains_input"] = len(all_subs)
        
        # Stage 1: Subdomain validation (dnsx + httpx)
        validation = self.run_subdomain_validation(all_subs)
        result["dnsx"] = validation["dnsx"]
        result["httpx"] = validation["httpx"]
        result["summary"]["resolved_hosts"] = validation["dnsx"].get("resolved_count", 0)
        result["summary"]["alive_http_hosts"] = len(validation.get("alive_hosts", []))
        
        # Stage 2: Port scan (optional)
        if port_scan and validation.get("resolved_ips"):
            result["naabu"] = self.run_port_discovery(validation["resolved_ips"])
            result["summary"]["total_open_ports"] = result["naabu"].get("total_open", 0)
        
        # Stage 3: Deep crawl (optional)
        if deep_crawl and validation.get("alive_hosts"):
            result["katana"] = self.run_deep_crawl(
                validation["alive_hosts"],
                depth=crawl_depth
            )
            result["summary"]["total_urls_crawled"] = result["katana"].get("total_urls", 0)
            result["summary"]["total_forms"] = len(result["katana"].get("forms", []))
            result["summary"]["total_js_endpoints"] = len(result["katana"].get("js_endpoints", []))
        
        self._log_msg(f"=== Pipeline Complete ===", "success")
        self._log_msg(
            f"Summary: {result['summary']['resolved_hosts']} resolved, "
            f"{result['summary']['alive_http_hosts']} alive, "
            f"{result['summary']['total_open_ports']} ports, "
            f"{result['summary']['total_urls_crawled']} URLs",
            "info"
        )
        
        return result
    
    def _dedupe_urls(self, urls: List[dict]) -> List[dict]:
        """Deduplicate URL records by URL."""
        seen = set()
        unique = []
        for u in urls:
            url = u.get("url", "")
            if url and url not in seen:
                seen.add(url)
                unique.append(u)
        return unique
    
    # ── Check Tools Availability ──────────────────────────────────────────────
    
    def check_tools(self) -> dict:
        """Check which tools are available on Kali."""
        result = {
            "dnsx": False,
            "httpx": False,
            "naabu": False,
            "katana": False,
        }
        
        if not self._ssh:
            return result
        
        try:
            if not self._ssh._client:
                if not self._ssh.connect():
                    return result
            
            for tool in result.keys():
                result[tool] = bool(self._ssh.which(tool))
            
        except Exception as e:
            self._log_msg(f"Error checking tools: {e}", "warning")
        
        return result


# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    import json
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    
    from dotenv import load_dotenv
    load_dotenv()
    
    from tools.kali_ssh_client import KaliSSHClient
    
    def log(msg, level="info"):
        print(f"[{level.upper()}] {msg}")
    
    ssh = KaliSSHClient(log_callback=log)
    if ssh.connect():
        toolkit = ProjectDiscoveryToolkit(ssh_client=ssh, log_callback=log)
        
        # Check tools
        print("\n=== Tool Availability ===")
        tools = toolkit.check_tools()
        for tool, available in tools.items():
            status = "OK" if available else "NOT FOUND"
            print(f"  {tool}: {status}")
        
        # Run pipeline
        print("\n=== Running Pipeline ===")
        result = toolkit.run_full_pipeline(
            domain="testfire.net",
            subdomains=[
                "testfire.net",
                "www.testfire.net",
                "demo.testfire.net",
            ],
            port_scan=True,
            deep_crawl=True,
            crawl_depth=2,
        )
        
        print("\n=== Summary ===")
        print(json.dumps(result["summary"], indent=2))
        
        ssh.close()
    else:
        print("SSH connection failed")
