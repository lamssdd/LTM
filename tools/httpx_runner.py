"""
tools/httpx_runner.py — httpx wrapper for HTTP probing and host validation.

httpx is a fast HTTP toolkit from ProjectDiscovery that:
- Probes hosts for HTTP/HTTPS availability
- Extracts status codes, titles, technologies
- Detects web servers, content length, redirects
- Outputs JSON for easy parsing

Role in Phase 1: ACTIVE recon - validates live hosts after subdomain enumeration
Should run: After dnsx (resolved hosts) or sublist3r (raw subdomains)

Installation on Kali:
    sudo apt install httpx-toolkit
    # or
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

Usage:
    from tools.httpx_runner import HttpxRunner
    runner = HttpxRunner(ssh_client=ssh, log_callback=log)
    result = runner.run(["sub1.example.com", "sub2.example.com"])
"""
import json
import os
import shlex
import shutil
import subprocess
import tempfile
from typing import Callable, List, Optional

# Type alias
LogCallback = Optional[Callable[[str, str], None]]


class HttpxRunner:
    """
    httpx wrapper for HTTP probing.
    
    Output schema:
    {
        "probed_hosts": [
            {
                "url": "https://example.com",
                "status_code": 200,
                "title": "Example Domain",
                "webserver": "nginx",
                "tech": ["Nginx", "PHP"],
                "content_length": 1234,
                "scheme": "https",
                "host": "example.com",
                "port": 443,
                "final_url": "https://example.com/",
                "response_time": "123ms",
                "method": "GET"
            }
        ],
        "alive_count": 1,
        "source": "httpx_kali" | "httpx_local" | "not_available"
    }
    """
    
    # Common httpx flags for comprehensive output
    HTTPX_FLAGS = [
        "-silent",           # Suppress banner
        "-json",             # JSON output
        "-status-code",      # Include status code
        "-title",            # Include page title
        "-tech-detect",      # Technology detection
        "-web-server",       # Web server header
        "-content-length",   # Content length
        "-follow-redirects", # Follow redirects
        "-timeout", "10",    # Connection timeout
        "-retries", "2",     # Retry attempts
        "-threads", "10",    # Parallel threads
    ]
    
    def __init__(
        self,
        ssh_client=None,
        log_callback: LogCallback = None,
        timeout: int = 120,
    ):
        """
        Initialize httpx runner.
        
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
        extra_flags: List[str] = None,
    ) -> dict:
        """
        Run httpx on a list of hosts/URLs.
        
        Args:
            hosts: List of hostnames or URLs to probe
            extra_flags: Additional httpx flags
            
        Returns:
            dict with probed_hosts list and metadata
        """
        result = {
            "probed_hosts": [],
            "alive_count": 0,
            "source": "not_available",
        }
        
        if not hosts:
            self._log_msg("httpx: No hosts provided", "warning")
            return result
        
        # Deduplicate and clean hosts
        clean_hosts = list(set(h.strip() for h in hosts if h.strip()))
        self._log_msg(f"httpx: Probing {len(clean_hosts)} hosts", "info")
        
        # Try Kali SSH first, then local
        output = None
        source = "not_available"
        
        if self._ssh:
            output, source = self._run_via_ssh(clean_hosts, extra_flags)
        
        if output is None:
            output, source = self._run_local(clean_hosts, extra_flags)
        
        if output:
            result["probed_hosts"] = self._parse_output(output)
            result["alive_count"] = len(result["probed_hosts"])
            result["source"] = source
            self._log_msg(
                f"httpx: {result['alive_count']} alive hosts (source={source})",
                "success" if result["alive_count"] > 0 else "info"
            )
        else:
            self._log_msg("httpx: No output received", "warning")
        
        return result
    
    def _run_via_ssh(
        self,
        hosts: List[str],
        extra_flags: List[str] = None,
    ) -> tuple:
        """Execute httpx via Kali SSH."""
        if not self._ssh:
            return None, "no_ssh"
        
        try:
            if not self._ssh._client:
                if not self._ssh.connect():
                    return None, "ssh_connect_failed"
            
            # Prefer ProjectDiscovery httpx (go/bin) over the Python httpx in /usr/bin
            httpx_bin = self._ssh.which("httpx")
            # If which returned a non-Go httpx (e.g. Python /usr/bin/httpx), verify it
            # accepts the -silent flag; fall back to the go/bin path if not.
            if httpx_bin:
                chk, _, chk_rc = self._ssh.run(
                    f"{httpx_bin} -silent -version 2>&1 | head -1", timeout=5
                )
                if chk_rc != 0 or "projectdiscovery" not in chk.lower():
                    # Try go/bin explicitly
                    for go_path in [
                        f"/home/{self._ssh.user}/go/bin/httpx",
                        "/root/go/bin/httpx",
                        "/usr/local/go/bin/httpx",
                    ]:
                        out_chk, _, rc_chk = self._ssh.run(
                            f"test -x {go_path} && echo ok", timeout=5
                        )
                        if rc_chk == 0 and "ok" in out_chk:
                            httpx_bin = go_path
                            self._ssh._tool_cache["httpx"] = go_path
                            break
                    else:
                        self._log_msg("ProjectDiscovery httpx not found on Kali", "info")
                        return None, "not_installed"
            else:
                self._log_msg("httpx not found on Kali", "info")
                return None, "not_installed"

            # Build command with stdin input
            flags = self.HTTPX_FLAGS + (extra_flags or [])
            hosts_input = "\n".join(hosts)

            cmd = f"echo {shlex.quote(hosts_input)} | {httpx_bin} {' '.join(flags)}"
            self._log_msg(f"Kali httpx: {len(hosts)} hosts", "info")
            
            out, err, rc = self._ssh.run(cmd, timeout=self._timeout)
            
            if rc == 0 and out.strip():
                return out, "httpx_kali"
            else:
                self._log_msg(f"httpx SSH error: {err[:200] if err else 'no output'}", "warning")
                return None, "ssh_error"
                
        except Exception as e:
            self._log_msg(f"httpx SSH exception: {e}", "warning")
            return None, "ssh_exception"
    
    def _run_local(
        self,
        hosts: List[str],
        extra_flags: List[str] = None,
    ) -> tuple:
        """Execute httpx locally."""
        httpx_bin = shutil.which("httpx")
        if not httpx_bin:
            self._log_msg("httpx not installed locally", "info")
            return None, "not_installed"
        
        try:
            flags = self.HTTPX_FLAGS + (extra_flags or [])
            hosts_input = "\n".join(hosts)
            
            proc = subprocess.run(
                [httpx_bin] + flags,
                input=hosts_input,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            
            if proc.returncode == 0 and proc.stdout.strip():
                return proc.stdout, "httpx_local"
            else:
                self._log_msg(f"httpx local error: {proc.stderr[:200] if proc.stderr else 'no output'}", "warning")
                return None, "local_error"
                
        except subprocess.TimeoutExpired:
            self._log_msg("httpx local timeout", "warning")
            return None, "timeout"
        except Exception as e:
            self._log_msg(f"httpx local exception: {e}", "warning")
            return None, "local_exception"
    
    def _parse_output(self, output: str) -> List[dict]:
        """
        Parse httpx JSON output (one JSON object per line).
        
        Returns list of normalized host records.
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
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code") or data.get("status-code"),
                    "title": data.get("title", ""),
                    "webserver": data.get("webserver", ""),
                    "tech": data.get("tech", []) or [],
                    "content_length": data.get("content_length") or data.get("content-length"),
                    "scheme": data.get("scheme", ""),
                    "host": data.get("host", ""),
                    "port": data.get("port"),
                    "final_url": data.get("final_url") or data.get("url", ""),
                    "response_time": data.get("response_time", ""),
                    "method": data.get("method", "GET"),
                }
                
                # Only include if we got meaningful data
                if record["url"] or record["host"]:
                    results.append(record)
                    
            except json.JSONDecodeError:
                # Not JSON, try to extract URL from plain text output
                if line.startswith("http"):
                    results.append({
                        "url": line,
                        "status_code": None,
                        "title": "",
                        "webserver": "",
                        "tech": [],
                        "content_length": None,
                        "scheme": "https" if line.startswith("https") else "http",
                        "host": "",
                        "port": None,
                        "final_url": line,
                        "response_time": "",
                        "method": "GET",
                    })
        
        return results


# ── Standalone test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    
    from dotenv import load_dotenv
    load_dotenv()
    
    from tools.kali_ssh_client import KaliSSHClient
    
    def log(msg, level="info"):
        print(f"[{level.upper()}] {msg}")
    
    # Test with Kali SSH
    ssh = KaliSSHClient(log_callback=log)
    if ssh.connect():
        runner = HttpxRunner(ssh_client=ssh, log_callback=log)
        result = runner.run([
            "testfire.net",
            "demo.testfire.net",
            "www.testfire.net",
        ])
        
        print("\n=== HTTPX Results ===")
        print(json.dumps(result, indent=2, default=str))
        
        ssh.close()
    else:
        print("SSH connection failed")
