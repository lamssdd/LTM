"""
tools/naabu_runner.py — naabu wrapper for fast port scanning.

naabu is a fast port scanner from ProjectDiscovery that:
- Scans ports quickly using SYN/CONNECT techniques
- Supports host discovery
- Can scan specific ports or top ports
- Outputs JSON for easy parsing

Role in Phase 1: ACTIVE recon - fast port discovery before detailed nmap scan
Should run: After dnsx (resolved IPs) or on target hosts
            Before nmap (naabu for speed, nmap for service detection)

Strategy:
    naabu → Fast scan top 1000 ports → Get open port list
    nmap  → Targeted scan only open ports → Get service/version info

Installation on Kali:
    sudo apt install naabu
    # or
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

Usage:
    from tools.naabu_runner import NaabuRunner
    runner = NaabuRunner(ssh_client=ssh, log_callback=log)
    result = runner.run(["192.168.1.1", "example.com"])
"""
import json
import os
import shlex
import shutil
import subprocess
from typing import Callable, List, Optional, Union

LogCallback = Optional[Callable[[str, str], None]]


class NaabuRunner:
    """
    naabu wrapper for fast port scanning.
    
    Output schema:
    {
        "scan_results": [
            {
                "host": "192.168.1.1",
                "ip": "192.168.1.1",
                "port": 80,
                "protocol": "tcp"
            }
        ],
        "hosts_with_ports": {
            "192.168.1.1": [80, 443, 8080],
            "10.0.0.1": [22, 80]
        },
        "all_open_ports": [22, 80, 443, 8080],
        "total_open": 5,
        "source": "naabu_kali" | "naabu_local" | "not_available"
    }
    """
    
    # naabu flags for fast comprehensive scan
    NAABU_FLAGS = [
        "-silent",          # Suppress banner
        "-json",            # JSON output
        "-top-ports", "1000", # Scan top 1000 ports
        "-rate", "1000",    # Packets per second
        "-retries", "2",    # Retry attempts
        "-timeout", "5000", # Timeout in ms
        "-c", "25",         # Concurrent hosts
    ]
    
    def __init__(
        self,
        ssh_client=None,
        log_callback: LogCallback = None,
        timeout: int = 300,
    ):
        """
        Initialize naabu runner.
        
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
        ports: Union[str, List[int]] = None,
        top_ports: int = None,
        extra_flags: List[str] = None,
    ) -> dict:
        """
        Run naabu port scan on hosts.
        
        Args:
            hosts: List of hostnames or IPs to scan
            ports: Specific ports to scan (e.g., "80,443" or [80, 443])
            top_ports: Number of top ports to scan (default: 1000)
            extra_flags: Additional naabu flags
            
        Returns:
            dict with scan results and metadata
        """
        result = {
            "scan_results": [],
            "hosts_with_ports": {},
            "all_open_ports": [],
            "total_open": 0,
            "source": "not_available",
        }
        
        if not hosts:
            self._log_msg("naabu: No hosts provided", "warning")
            return result
        
        # Deduplicate and clean hosts
        clean_hosts = list(set(h.strip() for h in hosts if h.strip()))
        self._log_msg(f"naabu: Scanning {len(clean_hosts)} hosts", "info")
        
        # Build flags
        flags = self._build_flags(ports, top_ports, extra_flags)
        
        # Try Kali SSH first, then local
        output = None
        source = "not_available"
        
        if self._ssh:
            output, source = self._run_via_ssh(clean_hosts, flags)
        
        if output is None:
            output, source = self._run_local(clean_hosts, flags)
        
        if output:
            result["scan_results"] = self._parse_output(output)
            result["source"] = source
            
            # Aggregate results
            result["hosts_with_ports"] = self._aggregate_by_host(result["scan_results"])
            result["all_open_ports"] = self._get_unique_ports(result["scan_results"])
            result["total_open"] = len(result["scan_results"])
            
            self._log_msg(
                f"naabu: {result['total_open']} open ports across {len(result['hosts_with_ports'])} hosts (source={source})",
                "success" if result["total_open"] > 0 else "info"
            )
        else:
            self._log_msg("naabu: No output received", "warning")
        
        return result
    
    def _build_flags(
        self,
        ports: Union[str, List[int]] = None,
        top_ports: int = None,
        extra_flags: List[str] = None,
    ) -> List[str]:
        """Build naabu flags based on options."""
        flags = ["-silent", "-json", "-rate", "1000", "-retries", "2", "-timeout", "5000", "-c", "25"]
        
        if ports:
            # Specific ports
            if isinstance(ports, list):
                ports = ",".join(str(p) for p in ports)
            flags.extend(["-p", ports])
        elif top_ports:
            flags.extend(["-top-ports", str(top_ports)])
        else:
            # Default: top 1000
            flags.extend(["-top-ports", "1000"])
        
        return flags + (extra_flags or [])
    
    def _run_via_ssh(
        self,
        hosts: List[str],
        flags: List[str],
    ) -> tuple:
        """Execute naabu via Kali SSH."""
        if not self._ssh:
            return None, "no_ssh"
        
        try:
            if not self._ssh._client:
                if not self._ssh.connect():
                    return None, "ssh_connect_failed"
            
            # Check if naabu is available
            naabu_bin = self._ssh.which("naabu")
            if not naabu_bin:
                self._log_msg("naabu not found on Kali", "info")
                return None, "not_installed"
            
            # Build command with stdin input
            hosts_input = "\n".join(hosts)
            cmd = f"echo {shlex.quote(hosts_input)} | {naabu_bin} {' '.join(flags)}"
            self._log_msg(f"Kali naabu: {len(hosts)} hosts", "info")
            
            out, err, rc = self._ssh.run(cmd, timeout=self._timeout)
            
            if rc == 0 and out.strip():
                return out, "naabu_kali"
            elif rc == 0:
                # naabu may return 0 with no output if no ports open
                return "", "naabu_kali_empty"
            else:
                self._log_msg(f"naabu SSH error: {err[:200] if err else 'no output'}", "warning")
                return None, "ssh_error"
                
        except Exception as e:
            self._log_msg(f"naabu SSH exception: {e}", "warning")
            return None, "ssh_exception"
    
    def _run_local(
        self,
        hosts: List[str],
        flags: List[str],
    ) -> tuple:
        """Execute naabu locally."""
        naabu_bin = shutil.which("naabu")
        if not naabu_bin:
            self._log_msg("naabu not installed locally", "info")
            return None, "not_installed"
        
        try:
            hosts_input = "\n".join(hosts)
            
            proc = subprocess.run(
                [naabu_bin] + flags,
                input=hosts_input,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout, "naabu_local"
            elif proc.returncode == 0:
                return "", "naabu_local_empty"
            else:
                self._log_msg(f"naabu local error: {proc.stderr[:200] if proc.stderr else 'no output'}", "warning")
                return None, "local_error"
                
        except subprocess.TimeoutExpired:
            self._log_msg("naabu local timeout", "warning")
            return None, "timeout"
        except Exception as e:
            self._log_msg(f"naabu local exception: {e}", "warning")
            return None, "local_exception"
    
    def _parse_output(self, output: str) -> List[dict]:
        """
        Parse naabu JSON output (one JSON object per line).
        
        Returns list of port scan results.
        """
        results = []
        
        for line in output.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            
            try:
                data = json.loads(line)
                
                # naabu output format: {"host": "x", "ip": "x", "port": 80}
                record = {
                    "host": data.get("host", ""),
                    "ip": data.get("ip", data.get("host", "")),
                    "port": data.get("port"),
                    "protocol": data.get("protocol", "tcp"),
                }
                
                if record["port"]:
                    results.append(record)
                    
            except json.JSONDecodeError:
                # Try to parse plain text: "host:port"
                if ":" in line:
                    parts = line.rsplit(":", 1)
                    if len(parts) == 2:
                        host, port = parts
                        try:
                            results.append({
                                "host": host.strip(),
                                "ip": host.strip(),
                                "port": int(port.strip()),
                                "protocol": "tcp",
                            })
                        except ValueError:
                            pass
        
        return results
    
    def _aggregate_by_host(self, scan_results: List[dict]) -> dict:
        """Group ports by host."""
        hosts = {}
        for r in scan_results:
            host = r.get("host") or r.get("ip")
            if host:
                if host not in hosts:
                    hosts[host] = []
                if r.get("port") and r["port"] not in hosts[host]:
                    hosts[host].append(r["port"])
        
        # Sort ports for each host
        for host in hosts:
            hosts[host].sort()
        
        return hosts
    
    def _get_unique_ports(self, scan_results: List[dict]) -> List[int]:
        """Get sorted list of unique open ports."""
        ports = set()
        for r in scan_results:
            if r.get("port"):
                ports.add(r["port"])
        return sorted(ports)
    
    def get_nmap_targets(self, scan_result: dict) -> str:
        """
        Generate nmap target string from naabu results.
        Format: "-p 80,443,8080 host1 host2"
        """
        ports = scan_result.get("all_open_ports", [])
        hosts = list(scan_result.get("hosts_with_ports", {}).keys())
        
        if not ports or not hosts:
            return ""
        
        port_str = ",".join(str(p) for p in ports)
        host_str = " ".join(hosts)
        
        return f"-p {port_str} {host_str}"


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
        runner = NaabuRunner(ssh_client=ssh, log_callback=log)
        
        # Scan common web ports
        result = runner.run(
            hosts=["testfire.net"],
            ports="21,22,80,443,8080,8443",  # Specific ports for faster test
        )
        
        print("\n=== NAABU Results ===")
        print(json.dumps(result, indent=2, default=str))
        
        print("\n=== Nmap Target String ===")
        print(runner.get_nmap_targets(result))
        
        ssh.close()
    else:
        print("SSH connection failed")
