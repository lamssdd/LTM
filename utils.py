"""
utils.py — Tien ich dung chung cho toan bo he thong.

Cac hang so va ham nay duoc dung o nhieu module:
  - normalize_url / normalize_hostname
  - make_session
  - TIMEOUT / FAST_TIMEOUT
  - SEVERITY_LEVELS / SEVERITY_ORDER
  - make_log_entry
"""
import ipaddress
import time
from urllib.parse import urlparse
import requests
import requests.packages.urllib3

# Tat canh bao SSL mot lan duy nhat tai day
requests.packages.urllib3.disable_warnings()

# ── Timeout (connect, read) ──────────────────────────────────────────
TIMEOUT      = (5, 10)
FAST_TIMEOUT = (3, 6)

# ── Thu tu muc do nghiem trong (CRITICAL → INFO) ─────────────────────
SEVERITY_ORDER:  dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
}
SEVERITY_LEVELS: list[str] = list(SEVERITY_ORDER.keys())

# ── User-Agent chung ─────────────────────────────────────────────────
USER_AGENT = "Mozilla/5.0 (SecurityScanner/2.0)"


def normalize_url(target: str) -> str:
    """Chuan hoa URL: dam bao co scheme http(s)://."""
    t = target.strip().rstrip("/")
    if t.startswith(("http://", "https://")):
        return t
    return "https://" + t


def normalize_hostname(target: str) -> str:
    """Lay phan hostname tu URL hoac domain."""
    t = target.strip().rstrip("/")
    for prefix in ("https://", "http://"):
        if t.startswith(prefix):
            t = t[len(prefix):]
    return t.split("/")[0].split("?")[0]


def should_bypass_env_proxy(target: str | None) -> bool:
    """
    Bo qua proxy moi truong cho localhost va dia chi private/internal.

    Scanner can ket noi truc tiep den muc tieu noi bo; neu requests doc
    HTTP_PROXY/HTTPS_PROXY tu env thi qua trinh recon/scan se bi hu khi
    proxy do khong phuc vu private IP.
    """
    if not target:
        return False

    host = normalize_hostname(target)
    if not host:
        return False

    parsed = urlparse("http://" + host if "://" not in host else host)
    host = (parsed.hostname or host).strip().lower()
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True

    if host.endswith(".local") or host.endswith(".lan") or host.endswith(".internal"):
        return True

    try:
        ip = ipaddress.ip_address(host)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
        )
    except ValueError:
        return False


def make_session(target: str | None = None) -> requests.Session:
    """Tao Session voi User-Agent san co va tu dong bypass env proxy neu can."""
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    if should_bypass_env_proxy(target):
        session.trust_env = False
    return session


def emit_log(
    message:  str,
    level:    str = "info",
    phase:    str = "phase1",
    agent:    str = "system",
    extra:    dict = None,
    log_queue=None,
) -> dict:
    """
    Helper thong nhat de ghi log:
      - In ra console
      - Day vao queue de Flask SSE stream (neu co)
      - Tra ve dict cho caller luu truoc khi push vao queue

    Usage:
      from utils import emit_log
      emit_log("Starting scan...", level="info", agent="PassiveReconAgent", log_queue=queue)
    """
    entry = {
        "time":    time.strftime("%H:%M:%S"),
        "agent":   agent,
        "level":   level,
        "message": message,
        "phase":   phase,
    }
    if extra:
        entry.update(extra)
    # Console output
    print(f"[{entry['time']}] [{level.upper():8}] [{agent}] {message}")
    # Queue for Flask SSE
    if log_queue is not None:
        try:
            log_queue.put_nowait(entry)
        except Exception:
            pass
    return entry


def load_dotenv(path: str = None) -> None:
    """
    Load key=value pairs from a .env file into os.environ.
    Shell env vars always take priority (setdefault behaviour).
    Skips blank lines and lines starting with #.
    """
    import os as _os
    env_path = path or _os.path.join(_os.path.dirname(__file__), ".env")
    if not _os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            _os.environ.setdefault(key.strip(), val.strip())


def build_tool_config(
    mode: str = None,
    kali_host: str = None,
    kali_port: int = None,
    kali_user: str = None,
    kali_pass: str = None,
    kali_key_path: str = None,
    kali_timeout: int = None,
) -> dict:
    """
    Build tool config dict for Phase 1 agents.

    Priority: explicit args > environment variables > defaults.

    Keys:
      mode            — "auto" | "local" | "kali_ssh"  (default: "auto")
      kali_host       — Kali IP/hostname
      kali_port       — SSH port (default 22)
      kali_user       — SSH username
      kali_pass       — SSH password (never log this)
      kali_key_path   — Path to SSH private key
      kali_timeout    — Connection timeout seconds (default 10)
    """
    import os
    return {
        "mode":         mode         or os.environ.get("PHASE1_TOOL_MODE", "auto"),
        "kali_host":    kali_host    or os.environ.get("KALI_HOST", ""),
        "kali_port":    int(kali_port or os.environ.get("KALI_PORT", "22")),
        "kali_user":    kali_user    or os.environ.get("KALI_USER", ""),
        "kali_pass":    kali_pass    or os.environ.get("KALI_PASS", ""),
        "kali_key_path":kali_key_path or os.environ.get("KALI_KEY_PATH", ""),
        "kali_timeout": int(kali_timeout or os.environ.get("KALI_CONNECT_TIMEOUT", "10")),
    }


def make_log_entry(agent: str, level: str, message: str,
                   progress: int | None = None) -> dict:
    """Tao log entry chuan dung chung cho tat ca agent va orchestrator."""
    entry = {
        "time":    time.strftime("%H:%M:%S"),
        "agent":   agent,
        "level":   level,
        "message": message,
    }
    if progress is not None:
        entry["progress"] = progress
    return entry


def is_localhost_target(hostname: str) -> bool:
    """
    Check if hostname is localhost/loopback address.
    
    Returns True for:
    - localhost
    - 127.0.0.1 (or any 127.x.x.x)
    - ::1 (IPv6 loopback)
    - *.local / *.localhost domains
    """
    if not hostname:
        return False
    
    hostname = hostname.strip().lower()
    
    # Exact matches
    if hostname in {"localhost", "127.0.0.1", "::1"}:
        return True
    
    # localhost domains
    if hostname.endswith((".localhost", ".local")):
        return True
    
    # 127.x.x.x range
    if hostname.startswith("127."):
        parts = hostname.split(".")
        if len(parts) == 4:
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                pass
    
    # IPv6 loopback variations
    if hostname.startswith("::1") or hostname == "::":
        return True
    
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_loopback
    except ValueError:
        return False
