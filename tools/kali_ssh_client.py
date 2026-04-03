"""
tools/kali_ssh_client.py — SSH helper for running recon tools on Kali Linux.

Config via environment variables or explicit constructor args:
  KALI_HOST             Kali IP / hostname  (required)
  KALI_PORT             SSH port, default 22
  KALI_USER             SSH username        (required)
  KALI_PASS             SSH password        (optional — prefer key)
  KALI_KEY_PATH         Path to private key (optional)
  KALI_CONNECT_TIMEOUT  Seconds, default 10

Usage:
  from tools.kali_ssh_client import KaliSSHClient
  ssh = KaliSSHClient(log_callback=self.log)
  if ssh.connect():
      out, err, rc = ssh.run("nmap -Pn -T4 --open -p80,443 example.com")
      ssh.close()
"""
import os
import shlex

try:
    import paramiko
    _PARAMIKO_OK = True
except ImportError:
    _PARAMIKO_OK = False


class KaliSSHClient:
    """Thin paramiko wrapper for running Kali tools over SSH."""

    def __init__(
        self,
        host: str = None,
        port: int = None,
        user: str = None,
        password: str = None,
        key_path: str = None,
        connect_timeout: int = None,
        log_callback=None,
    ):
        self.host    = host    or os.environ.get("KALI_HOST", "")
        self.port    = int(port or os.environ.get("KALI_PORT", "22"))
        self.user    = user    or os.environ.get("KALI_USER", "")
        # Password is passed explicitly or read from env — never printed in logs
        self.password    = password if password is not None else os.environ.get("KALI_PASS", "")
        self.key_path    = key_path or os.environ.get("KALI_KEY_PATH", "")
        self.connect_timeout = int(connect_timeout or os.environ.get("KALI_CONNECT_TIMEOUT", "10"))
        self._client     = None
        self._log        = log_callback or (lambda msg, level="info": None)
        self._tool_cache: dict = {}

    # ── Config ────────────────────────────────────────────────────────────────

    def is_configured(self) -> bool:
        """True if minimum required config (host + user + some auth) is present."""
        return bool(self.host and self.user and (self.password or self.key_path))

    # ── Connection ────────────────────────────────────────────────────────────

    def connect(self) -> bool:
        """Open SSH connection. Returns True on success."""
        if not _PARAMIKO_OK:
            self._log("paramiko not installed — Kali SSH unavailable (pip install paramiko)", "warning")
            return False
        if not self.is_configured():
            missing = []
            if not self.host:     missing.append("KALI_HOST")
            if not self.user:     missing.append("KALI_USER")
            if not (self.password or self.key_path): missing.append("KALI_PASS or KALI_KEY_PATH")
            self._log(f"Kali SSH not configured — missing: {', '.join(missing)}", "info")
            return False
        if self._client:
            return True  # already connected

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kwargs: dict = dict(
                hostname=self.host,
                port=self.port,
                username=self.user,
                timeout=self.connect_timeout,
            )
            if self.key_path and os.path.exists(self.key_path):
                kwargs["key_filename"] = self.key_path
                self._log(f"Kali SSH auth: key ({self.key_path})", "info")
            else:
                kwargs["password"] = self.password
                self._log("Kali SSH auth: password", "info")

            client.connect(**kwargs)
            self._client = client
            self._log(f"Kali SSH connected: {self.user}@{self.host}:{self.port}", "success")
            return True
        except Exception as exc:
            self._log(f"Kali SSH connect failed ({self.host}:{self.port}): {exc}", "warning")
            return False

    # ── Command execution ─────────────────────────────────────────────────────

    def run(self, command: str, timeout: int = 60) -> tuple:
        """
        Execute a shell command on Kali.
        Returns: (stdout: str, stderr: str, exit_code: int)
        Returns ("", error_msg, -1) on failure.
        """
        if not self._client:
            return "", "SSH not connected", -1
        try:
            _, stdout, stderr = self._client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            rc  = stdout.channel.recv_exit_status()
            return out, err, rc
        except Exception as exc:
            self._log(f"SSH command error: {exc}", "warning")
            return "", str(exc), -1

    # ── Tool checks ───────────────────────────────────────────────────────────

    # Extra directories to search when `which` fails (e.g. Go binaries not in SSH PATH)
    _EXTRA_SEARCH_DIRS = [
        "/home/{user}/go/bin",
        "/root/go/bin",
        "/usr/local/go/bin",
    ]

    def which(self, binary: str) -> str | None:
        """Return full path of binary on Kali, or None. Result is cached.

        Falls back to checking common Go binary directories when the binary is
        not found via the standard PATH (non-interactive SSH sessions often
        omit ~/go/bin).
        """
        if binary in self._tool_cache:
            return self._tool_cache[binary]

        out, _, rc = self.run(f"which {shlex.quote(binary)}", timeout=5)
        path = out.strip() if rc == 0 and out.strip() else None

        if not path:
            # Fallback: search extra dirs (ProjectDiscovery Go tools live here)
            for dir_tpl in self._EXTRA_SEARCH_DIRS:
                candidate = dir_tpl.format(user=self.user) + "/" + binary
                out2, _, rc2 = self.run(
                    f"test -x {shlex.quote(candidate)} && echo {shlex.quote(candidate)}",
                    timeout=5,
                )
                if rc2 == 0 and out2.strip():
                    path = out2.strip()
                    break

        self._tool_cache[binary] = path
        return path

    def check_tools(self, *binaries: str) -> dict:
        """Returns {binary: path_or_None} for each binary."""
        return {b: self.which(b) for b in binaries}

    # ── Context manager ───────────────────────────────────────────────────────

    def close(self):
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
            self._log("Kali SSH connection closed.", "info")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()
