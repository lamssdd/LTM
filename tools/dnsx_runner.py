"""
tools/dnsx_runner.py — dnsx wrapper for bulk DNS resolution.

dnsx is a fast DNS toolkit from ProjectDiscovery that:
- Resolves hostnames to IPs in bulk
- Extracts multiple record types (A, AAAA, CNAME, MX, NS, TXT)
- Validates which domains are alive
- Outputs JSON for easy parsing

Role in Phase 1: PASSIVE recon - validates subdomains after enumeration
Should run: After subdomain enumeration (sublist3r, crt.sh, theHarvester)
            Before httpx (to get resolved hosts for HTTP probing)

Installation on Kali:
    sudo apt install dnsx
    # or
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

Usage:
    from tools.dnsx_runner import DnsxRunner
    runner = DnsxRunner(ssh_client=ssh, log_callback=log)
    result = runner.run(["sub1.example.com", "sub2.example.com"])
"""
import json
import os
import shlex
import shutil
import subprocess
from typing import Callable, List, Optional

LogCallback = Optional[Callable[[str, str], None]]


class DnsxRunner:
    """
    dnsx wrapper for bulk DNS resolution.
    
    Output schema:
    {
        "resolved_hosts": [
            {
                "hostname": "sub.example.com",
                "a_records": ["1.2.3.4", "5.6.7.8"],
                "aaaa_records": ["2001:db8::1"],
                "cname": ["alias.example.com"],
                "mx": ["mail.example.com"],
                "ns": ["ns1.example.com"],
                "txt": ["v=spf1 include:..."]
            }
        ],
        "resolved_count": 1,
        "failed_hosts": ["dead.example.com"],
        "source": "dnsx_kali" | "dnsx_local" | "not_available"
    }
    """
    
    # dnsx flags for comprehensive DNS resolution
    DNSX_FLAGS = [
        "-silent",      # Suppress banner
        "-json",        # JSON output
        "-a",           # A records
        "-aaaa",        # AAAA records
        "-cname",       # CNAME records
        "-mx",          # MX records
        "-ns",          # NS records
        "-txt",         # TXT records
        "-resp",        # Include response data
        "-retry", "2",  # Retry attempts
        "-t", "10",     # Threads
    ]
    
    def __init__(
        self,
        ssh_client=None,
        log_callback: LogCallback = None,
        timeout: int = 120,
    ):
        """
        Initialize dnsx runner.
        
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
        hosts: List[str],
        record_types: List[str] = None,
        extra_flags: List[str] = None,
    ) -> dict:
        """
        Run dnsx on a list of hostnames.
        
        Args:
            hosts: List of hostnames to resolve
            record_types: Optional specific record types (default: all)
            extra_flags: Additional dnsx flags
            
        Returns:
            dict with resolved_hosts list and metadata
        """
        result = {
            "resolved_hosts": [],
            "resolved_count": 0,
            "failed_hosts": [],
            "source": "not_available",
        }
        
        if not hosts:
            self._log_msg("dnsx: No hosts provided", "warning")
            return result
        
        # Deduplicate and clean hosts
        clean_hosts = list(set(h.strip().lower() for h in hosts if h.strip()))
        self._log_msg(f"dnsx: Resolving {len(clean_hosts)} hosts", "info")
        
        # Build custom flags based on record_types
        flags = self._build_flags(record_types, extra_flags)
        
        # Try Kali SSH first, then local
        output = None
        source = "not_available"
        
        if self._ssh:
            output, source = self._run_via_ssh(clean_hosts, flags)
        
        if output is None:
            output, source = self._run_local(clean_hosts, flags)
        
        if output:
            result["resolved_hosts"] = self._parse_output(output)
            result["resolved_count"] = len(result["resolved_hosts"])
            result["source"] = source
            
            # Calculate failed hosts
            resolved_names = {h["hostname"].lower() for h in result["resolved_hosts"]}
            result["failed_hosts"] = [h for h in clean_hosts if h.lower() not in resolved_names]
            
            self._log_msg(
                f"dnsx: {result['resolved_count']} resolved, {len(result['failed_hosts'])} failed (source={source})",
                "success" if result["resolved_count"] > 0 else "info"
            )
        else:
            self._log_msg("dnsx: No output received", "warning")
        
        return result
    
    def _build_flags(
        self,
        record_types: List[str] = None,
        extra_flags: List[str] = None,
    ) -> List[str]:
        """Build dnsx flags based on options."""
        if record_types:
            # Use specific record types
            flags = ["-silent", "-json", "-resp", "-retry", "2", "-t", "10"]
            type_map = {
                "a": "-a", "aaaa": "-aaaa", "cname": "-cname",
                "mx": "-mx", "ns": "-ns", "txt": "-txt",
            }
            for rt in record_types:
                if rt.lower() in type_map:
                    flags.append(type_map[rt.lower()])
            return flags + (extra_flags or [])
        else:
            return self.DNSX_FLAGS + (extra_flags or [])
    
    def _run_via_ssh(
        self,
        hosts: List[str],
        flags: List[str],
    ) -> tuple:
        """Execute dnsx via Kali SSH."""
        if not self._ssh:
            return None, "no_ssh"
        
        try:
            if not self._ssh._client:
                if not self._ssh.connect():
                    return None, "ssh_connect_failed"
            
            # Check if dnsx is available
            dnsx_bin = self._ssh.which("dnsx")
            if not dnsx_bin:
                self._log_msg("dnsx not found on Kali", "info")
                return None, "not_installed"
            
            # Build command with stdin input
            hosts_input = "\n".join(hosts)
            cmd = f"echo {shlex.quote(hosts_input)} | {dnsx_bin} {' '.join(flags)}"
            self._log_msg(f"Kali dnsx: {len(hosts)} hosts", "info")
            
            out, err, rc = self._ssh.run(cmd, timeout=self._timeout)
            
            if rc == 0 and out.strip():
                return out, "dnsx_kali"
            else:
                self._log_msg(f"dnsx SSH error: {err[:200] if err else 'no output'}", "warning")
                return None, "ssh_error"
                
        except Exception as e:
            self._log_msg(f"dnsx SSH exception: {e}", "warning")
            return None, "ssh_exception"
    
    def _run_local(
        self,
        hosts: List[str],
        flags: List[str],
    ) -> tuple:
        """Execute dnsx locally."""
        dnsx_bin = shutil.which("dnsx")
        if not dnsx_bin:
            self._log_msg("dnsx not installed locally", "info")
            return None, "not_installed"
        
        try:
            hosts_input = "\n".join(hosts)
            
            proc = subprocess.run(
                [dnsx_bin] + flags,
                input=hosts_input,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout, "dnsx_local"
            else:
                self._log_msg(f"dnsx local error: {proc.stderr[:200] if proc.stderr else 'no output'}", "warning")
                return None, "local_error"
                
        except subprocess.TimeoutExpired:
            self._log_msg("dnsx local timeout", "warning")
            return None, "timeout"
        except Exception as e:
            self._log_msg(f"dnsx local exception: {e}", "warning")
            return None, "local_exception"
    
    def _parse_output(self, output: str) -> List[dict]:
        """
        Parse dnsx JSON output (one JSON object per line).
        
        Returns list of normalized DNS records.
        """
        results = []
        
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                # Normalize to our schema
                record = {
                    "hostname": data.get("host", ""),
                    "a_records": data.get("a", []) or [],
                    "aaaa_records": data.get("aaaa", []) or [],
                    "cname": data.get("cname", []) or [],
                    "mx": data.get("mx", []) or [],
                    "ns": data.get("ns", []) or [],
                    "txt": data.get("txt", []) or [],
                    "resolver": data.get("resolver", ""),
                    "status_code": data.get("status_code", ""),
                }
                
                # Only include if we got a hostname
                if record["hostname"]:
                    results.append(record)
                    
            except json.JSONDecodeError:
                # Try to parse plain text: "hostname [ip1,ip2]"
                parts = line.split()
                if parts:
                    hostname = parts[0]
                    ips = []
                    if len(parts) > 1:
                        # Extract IPs from brackets
                        ip_part = " ".join(parts[1:])
                        ip_part = ip_part.strip("[]")
                        ips = [ip.strip() for ip in ip_part.split(",")]
                    
                    results.append({
                        "hostname": hostname,
                        "a_records": ips,
                        "aaaa_records": [],
                        "cname": [],
                        "mx": [],
                        "ns": [],
                        "txt": [],
                        "resolver": "",
                        "status_code": "",
                    })
        
        return results
    
    def get_alive_hosts(self, resolved_result: dict) -> List[str]:
        """
        Extract list of alive hostnames from resolved result.
        Useful for piping to httpx.
        """
        return [h["hostname"] for h in resolved_result.get("resolved_hosts", [])]
    
    def get_all_ips(self, resolved_result: dict) -> List[str]:
        """
        Extract all unique IPs from resolved result.
        Useful for port scanning with naabu.
        """
        ips = set()
        for host in resolved_result.get("resolved_hosts", []):
            ips.update(host.get("a_records", []))
            ips.update(host.get("aaaa_records", []))
        return list(ips)


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
        runner = DnsxRunner(ssh_client=ssh, log_callback=log)
        result = runner.run([
            "testfire.net",
            "demo.testfire.net",
            "www.testfire.net",
            "nonexistent.testfire.net",
        ])
        
        print("\n=== DNSX Results ===")
        print(json.dumps(result, indent=2, default=str))
        
        print("\n=== Alive Hosts ===")
        print(runner.get_alive_hosts(result))
        
        print("\n=== All IPs ===")
        print(runner.get_all_ips(result))
        
        ssh.close()
    else:
        print("SSH connection failed")
