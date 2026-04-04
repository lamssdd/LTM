#!/usr/bin/env python3
"""
main.py — Sentinel v3: Enterprise Pentest Multi-Agent Dashboard

A professional terminal-based dashboard for the multi-agent penetration testing system.
Features real-time logging, progress tracking, and cybersecurity-themed UI.

Usage:
    python main.py                          # Interactive mode
    python main.py --target http://example.com  # Direct scan mode
    python main.py --demo                   # Demo mode (simulated scan)

Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    SentinelDashboard                        │
    │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
    │  │   Header    │  │  Controls   │  │    Progress Bar     │  │
    │  └─────────────┘  └─────────────┘  └─────────────────────┘  │
    │  ┌─────────────────────────────────────────────────────────┐│
    │  │                    Console Log                          ││
    │  │  [Passive][DNS] Resolving domain...                     ││
    │  │  [Active][PortScan] Found 80, 443                       ││
    │  └─────────────────────────────────────────────────────────┘│
    │  ┌─────────────────────────────────────────────────────────┐│
    │  │                    Status Panel                         ││
    │  └─────────────────────────────────────────────────────────┘│
    └─────────────────────────────────────────────────────────────┘
"""

import argparse
import os
import sys
import time
import threading
import queue
import random
import msvcrt  # Windows keyboard input
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Callable
from enum import Enum

# ══════════════════════════════════════════════════════════════════════════════
# Rich Library Setup
# ══════════════════════════════════════════════════════════════════════════════

try:
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text
    from rich.style import Style
    from rich.align import Align
    from rich import box
    from rich.columns import Columns
    from rich.rule import Rule
except ImportError:
    print("Error: 'rich' library not installed. Install with: pip install rich")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
# Theme & Styles (Cybersecurity Blue Theme)
# ══════════════════════════════════════════════════════════════════════════════

class Theme:
    """Cybersecurity Blue Theme - NOT green!"""
    # Primary colors
    PRIMARY = "bright_blue"
    SECONDARY = "cyan"
    ACCENT = "dodger_blue2"
    
    # Status colors
    SUCCESS = "green"
    WARNING = "yellow"
    ERROR = "red"
    INFO = "bright_blue"
    
    # Log type colors
    PASSIVE = "bright_blue"
    ACTIVE = "cyan"
    AGENT = "magenta"
    EXTERNAL = "yellow"
    STRATEGY = "bright_magenta"
    SYSTEM = "dim white"
    
    # UI colors
    BORDER = "blue"
    HEADER_BG = "on blue"
    TITLE = "bold bright_white on blue"
    BUTTON = "black on bright_blue"
    BUTTON_ACTIVE = "black on cyan"
    TAB = "bright_blue"
    TAB_ACTIVE = "bold bright_white on blue"
    TIMESTAMP = "dim cyan"
    
    # Styles
    HEADER_STYLE = Style(color="bright_white", bgcolor="blue", bold=True)
    PANEL_STYLE = Style(color="bright_blue")


# ══════════════════════════════════════════════════════════════════════════════
# Data Classes
# ══════════════════════════════════════════════════════════════════════════════

class LogLevel(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    AGENT = "agent"
    EXTERNAL = "external"
    STRATEGY = "strategy"
    SYSTEM = "system"
    ERROR = "error"
    SUCCESS = "success"
    WARNING = "warning"


@dataclass
class LogEntry:
    timestamp: str
    level: LogLevel
    category: str
    message: str
    tool: str = ""


@dataclass
class AgentStatus:
    name: str
    status: str = "idle"  # idle, running, done, error
    current_task: str = ""
    progress: int = 0
    items_found: int = 0


@dataclass
class ScanState:
    target: str = ""
    phase: str = "Idle"
    status: str = "idle"  # idle, running, paused, done, error
    progress: int = 0
    start_time: Optional[float] = None
    logs: List[LogEntry] = field(default_factory=list)
    agents: dict = field(default_factory=dict)
    stats: dict = field(default_factory=lambda: {
        "urls": 0, "forms": 0, "params": 0, "ports": 0,
        "subdomains": 0, "vulns": 0, "emails": 0
    })


# ══════════════════════════════════════════════════════════════════════════════
# Console Log Manager
# ══════════════════════════════════════════════════════════════════════════════

class LogManager:
    """Thread-safe log manager with queue-based updates."""
    
    MAX_LOGS = 500  # Keep last N logs for display (increased for history)
    
    def __init__(self):
        self._queue: queue.Queue = queue.Queue()
        self._logs: List[LogEntry] = []
        self._lock = threading.Lock()
    
    def log(self, level: LogLevel, category: str, message: str, tool: str = ""):
        """Add a log entry (thread-safe)."""
        entry = LogEntry(
            timestamp=datetime.now().strftime("%H:%M:%S"),
            level=level,
            category=category,
            message=message,
            tool=tool
        )
        self._queue.put(entry)
    
    def process_queue(self) -> List[LogEntry]:
        """Process queued logs and return new entries."""
        new_entries = []
        while not self._queue.empty():
            try:
                entry = self._queue.get_nowait()
                with self._lock:
                    self._logs.append(entry)
                    if len(self._logs) > self.MAX_LOGS:
                        self._logs = self._logs[-self.MAX_LOGS:]
                new_entries.append(entry)
            except queue.Empty:
                break
        return new_entries
    
    def get_logs(self, limit: int = 50) -> List[LogEntry]:
        """Get recent logs."""
        with self._lock:
            return self._logs[-limit:]
    
    def clear(self):
        """Clear all logs including pending queue items."""
        with self._lock:
            self._logs.clear()
        # Drain the queue so old entries don't bleed into the new scan
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break


# ══════════════════════════════════════════════════════════════════════════════
# Real Scan Bridge  (connects agents → ScanState + LogManager)
# ══════════════════════════════════════════════════════════════════════════════

class ScanBridge:
    """
    Bridge agent events to ScanState and LogManager for real scans.

    Responsibilities:
    - Real progress %  (passive 45% + active 45% + aggregate 10%)
    - Phase-aware log separation (passive vs active never mixed)
    - Error sanitization (no raw Python tracebacks shown)
    - Phase state labels: [QUEUED] [RUNNING] [COMPLETE] [FAILED]
    """

    _ERROR_MAP = {
        "has no attribute":          "Module not configured or unsupported for this target",
        "NoneType":                  "Component returned no data",
        "Connection refused":        "Target refused connection",
        "timed out":                 "Request timed out — target may be slow or filtered",
        "Name or service not known": "Cannot resolve hostname — check target",
        "SSLError":                  "SSL/TLS error — target may not support HTTPS",
        "ConnectionResetError":      "Connection reset by target",
        "Max retries exceeded":      "Target unreachable — max retries exceeded",
    }

    _PASSIVE_TOOLS = {
        "ip_resolve", "dns", "whois", "ssl", "whatweb",
        "amass", "subfinder", "crtsh", "theharvester", "wayback", "shodan", "google_dorks",
    }
    _ACTIVE_TOOLS = {
        "http_probe", "http_methods", "nmap_tcp", "syn_scan",
        "wafw00f", "banner_grab", "robots", "crawl", "ffuf",
    }

    def __init__(self, state: ScanState, log_manager: LogManager):
        self.state       = state
        self.log_manager = log_manager
        self._lock       = threading.Lock()
        self._done       = {"passive": set(), "active": set(), "aggregate": set()}

    @classmethod
    def sanitize(cls, msg: str) -> str:
        """Convert raw Python errors to human-readable messages."""
        for pattern, friendly in cls._ERROR_MAP.items():
            if pattern.lower() in msg.lower():
                return friendly
        if "Traceback" in msg or 'File "' in msg:
            return "Internal module error — check configuration"
        return msg

    def _recalc_progress(self):
        p = len(self._done["passive"])  / len(self._PASSIVE_TOOLS) * 45
        a = len(self._done["active"])   / len(self._ACTIVE_TOOLS)  * 45
        g = min(len(self._done["aggregate"]), 1)                   * 10
        self.state.progress = int(min(p + a + g, 100))

    def make_log_callback(self, phase: str, agent_name: str):
        """Return a log_callback for one phase — logs never cross phases."""
        phase_level = {
            "passive":   LogLevel.PASSIVE,
            "active":    LogLevel.ACTIVE,
            "aggregate": LogLevel.AGENT,
        }.get(phase, LogLevel.SYSTEM)

        def callback(entry: dict):
            if not isinstance(entry, dict):
                return
            message = entry.get("message", "")
            if not message:
                return
            raw = entry.get("level", "info").lower()
            if raw == "error":
                level   = LogLevel.ERROR
                message = self.sanitize(message)
            elif raw in ("warning", "warn"):
                level = LogLevel.WARNING
            elif raw in ("success", "done"):
                level = LogLevel.SUCCESS
            else:
                level = phase_level
            self.log_manager.log(level, agent_name, message)

        return callback

    def make_tool_tracker(self):
        """Return a ToolTracker-compatible adapter for agent injection."""
        return _BridgeToolTracker(self)

    def tool_done(self, phase: str, tool: str):
        with self._lock:
            self._done[phase].add(tool)
            self._recalc_progress()

    def aggregate_done(self):
        with self._lock:
            self._done["aggregate"].add("aggregate")
            self._recalc_progress()


class _BridgeToolTracker:
    """
    ToolTracker-compatible adapter injected into tool_config["tool_tracker"].
    Routes start/done/error events through ScanBridge for progress tracking.
    """

    def __init__(self, bridge: ScanBridge):
        self._bridge  = bridge
        self._current = None
        self.state    = {}  # minimal compatibility shim

    @property
    def current_tool(self):
        return self._current

    @property
    def counts(self):
        return {"done": 0, "error": 0, "running": 0, "pending": 0}

    def start(self, name: str):
        self._current = name

    def done(self, name: str, summary: str = "", result: dict = None):  # noqa: ARG002
        if self._current == name:
            self._current = None
        phase = "active" if name in ScanBridge._ACTIVE_TOOLS else "passive"
        self._bridge.tool_done(phase, name)

    def error(self, name: str, error: str = ""):  # noqa: ARG002
        if self._current == name:
            self._current = None
        phase = "active" if name in ScanBridge._ACTIVE_TOOLS else "passive"
        self._bridge.tool_done(phase, name)   # advance progress even on error

    def add_log(self, name: str, msg: str):  # noqa: ARG002
        pass   # logs are handled by the phase log_callback

    def snapshot(self) -> dict:
        return {}


# ══════════════════════════════════════════════════════════════════════════════
# Simulated Agents (for Demo Mode)
# ══════════════════════════════════════════════════════════════════════════════

class SimulatedAgent(threading.Thread):
    """Base class for simulated agents."""
    
    def __init__(self, name: str, log_manager: LogManager, state: ScanState):
        super().__init__(daemon=True)
        self.name = name
        self.log = log_manager
        self.state = state
        self._stop_event = threading.Event()
    
    def stop(self):
        self._stop_event.set()
    
    def is_stopped(self):
        return self._stop_event.is_set()
    
    def _update_stats(self, key: str, value: int):
        self.state.stats[key] = self.state.stats.get(key, 0) + value


class PassiveReconSimulator(SimulatedAgent):
    """Simulates Passive Reconnaissance Agent."""
    
    TASKS = [
        (LogLevel.PASSIVE, "DNS", "Resolving domain to IP address...", 0.3),
        (LogLevel.PASSIVE, "DNS", "Found IP: 65.61.137.117", 0.2),
        (LogLevel.PASSIVE, "DNS", "Checking A, AAAA, MX, NS, TXT records...", 0.5),
        (LogLevel.PASSIVE, "WHOIS", "Querying WHOIS database...", 0.8),
        (LogLevel.PASSIVE, "WHOIS", "Registrar: Network Solutions LLC", 0.2),
        (LogLevel.PASSIVE, "SSL", "Fetching SSL certificate...", 0.5),
        (LogLevel.PASSIVE, "SSL", "Certificate valid, expires in 245 days", 0.2),
        (LogLevel.PASSIVE, "Subdomain", "Enumerating subdomains (120+ prefixes)...", 1.0),
        (LogLevel.PASSIVE, "Subdomain", "Found: www, api, mail, admin, dev", 0.3),
        (LogLevel.PASSIVE, "Tech", "Fingerprinting web technologies...", 0.6),
        (LogLevel.PASSIVE, "Tech", "Detected: Apache/2.4.7, PHP/5.4.2, jQuery", 0.2),
        (LogLevel.EXTERNAL, "WhatWeb", "Running: whatweb -a 3 target...", 1.2),
        (LogLevel.PASSIVE, "WhatWeb", "Found: WordPress 5.9, Bootstrap 4.6", 0.3),
        (LogLevel.EXTERNAL, "theHarvester", "Running: theHarvester -d domain -b all", 2.0),
        (LogLevel.PASSIVE, "theHarvester", "Found 12 emails, 8 hosts", 0.3),
        (LogLevel.EXTERNAL, "Sublist3r", "Running: sublist3r -d domain", 1.5),
        (LogLevel.PASSIVE, "Sublist3r", "Discovered 23 subdomains", 0.2),
        (LogLevel.EXTERNAL, "Amass", "Running: amass enum -passive -d domain", 2.5),
        (LogLevel.PASSIVE, "Amass", "Found 45 additional subdomains", 0.3),
        (LogLevel.PASSIVE, "crt.sh", "Querying Certificate Transparency logs...", 1.0),
        (LogLevel.PASSIVE, "crt.sh", "Found 67 certificates for domain", 0.2),
        (LogLevel.PASSIVE, "Wayback", "Checking Wayback Machine archive...", 1.2),
        (LogLevel.PASSIVE, "Wayback", "Retrieved 234 historical URLs", 0.3),
        (LogLevel.PASSIVE, "Shodan", "Querying Shodan API for host intel...", 0.8),
        (LogLevel.PASSIVE, "Shodan", "Found 5 open ports, 2 CVEs", 0.3),
        (LogLevel.PASSIVE, "GoogleDorks", "Running search engine dorking...", 1.5),
        (LogLevel.PASSIVE, "GoogleDorks", "Found 8 exposed files, 3 admin pages", 0.3),
    ]
    
    def run(self):
        self.state.agents["PassiveRecon"] = AgentStatus("PassiveRecon", "running")
        self.log.log(LogLevel.SYSTEM, "System", "PassiveReconAgent started")
        
        for i, (level, cat, msg, delay) in enumerate(self.TASKS):
            if self.is_stopped():
                break
            
            self.log.log(level, cat, msg)
            time.sleep(delay * random.uniform(0.8, 1.2))
            
            # Update progress
            progress = int((i + 1) / len(self.TASKS) * 100)
            self.state.agents["PassiveRecon"].progress = progress
            self.state.agents["PassiveRecon"].current_task = cat
            
            # Update stats
            if "subdomain" in msg.lower():
                self._update_stats("subdomains", random.randint(5, 20))
            elif "email" in msg.lower():
                self._update_stats("emails", random.randint(3, 12))
        
        self.state.agents["PassiveRecon"].status = "done"
        self.log.log(LogLevel.SUCCESS, "PassiveRecon", "Passive reconnaissance completed")


class ActiveReconSimulator(SimulatedAgent):
    """Simulates Active Reconnaissance Agent."""
    
    TASKS = [
        (LogLevel.ACTIVE, "HTTP", "Checking HTTP/HTTPS availability...", 0.5),
        (LogLevel.ACTIVE, "HTTP", "HTTP: 200 OK | HTTPS: 200 OK", 0.2),
        (LogLevel.ACTIVE, "HTTP", "Following redirect chain (2 hops)...", 0.3),
        (LogLevel.ACTIVE, "Headers", "Collecting response headers...", 0.4),
        (LogLevel.ACTIVE, "Headers", "Missing: X-Frame-Options, CSP", 0.2),
        (LogLevel.ACTIVE, "Cookies", "Analyzing cookie security flags...", 0.3),
        (LogLevel.ACTIVE, "Cookies", "Warning: JSESSIONID missing HttpOnly", 0.2),
        (LogLevel.ACTIVE, "Methods", "Probing HTTP methods (OPTIONS)...", 0.6),
        (LogLevel.ACTIVE, "Methods", "Allowed: GET, POST, HEAD, OPTIONS", 0.2),
        (LogLevel.EXTERNAL, "nmap", "Running: nmap -sT -p- target", 3.0),
        (LogLevel.ACTIVE, "PortScan", "Open ports: 22, 80, 443, 3306, 8080", 0.3),
        (LogLevel.EXTERNAL, "wafw00f", "Running: wafw00f target", 1.0),
        (LogLevel.ACTIVE, "WAF", "No WAF detected", 0.2),
        (LogLevel.ACTIVE, "Banner", "Grabbing service banners...", 1.5),
        (LogLevel.ACTIVE, "Banner", "Port 22: OpenSSH 7.9p1", 0.2),
        (LogLevel.ACTIVE, "Banner", "Port 3306: MySQL 5.7.32", 0.2),
        (LogLevel.STRATEGY, "SYN", "TCP SYN scan (Scapy stealth mode)...", 2.0),
        (LogLevel.ACTIVE, "SYN", "Stealth scan completed: 5 ports open", 0.3),
        (LogLevel.ACTIVE, "Robots", "Fetching robots.txt...", 0.4),
        (LogLevel.ACTIVE, "Robots", "Found 12 disallowed paths", 0.2),
        (LogLevel.ACTIVE, "Sitemap", "Parsing sitemap.xml...", 0.5),
        (LogLevel.ACTIVE, "Sitemap", "Extracted 156 URLs from sitemap", 0.2),
        (LogLevel.AGENT, "Crawler", "Starting web crawler (depth=3)...", 0.5),
        (LogLevel.AGENT, "Crawler", "Crawling page 1/50...", 0.8),
        (LogLevel.AGENT, "Crawler", "Crawling page 10/50...", 1.0),
        (LogLevel.AGENT, "Crawler", "Crawling page 25/50...", 1.2),
        (LogLevel.AGENT, "Crawler", "Crawling page 50/50...", 0.8),
        (LogLevel.AGENT, "Crawler", "Crawl complete: 50 pages, 23 forms", 0.3),
        (LogLevel.AGENT, "FormAnalyzer", "Analyzing form parameters...", 0.8),
        (LogLevel.AGENT, "FormAnalyzer", "Found 45 input parameters", 0.2),
        (LogLevel.AGENT, "JSParser", "Extracting JS endpoints...", 1.0),
        (LogLevel.AGENT, "JSParser", "Found 18 API endpoints in JS", 0.3),
        (LogLevel.EXTERNAL, "ffuf", "Running: ffuf -w wordlist.txt -u URL/FUZZ", 2.5),
        (LogLevel.ACTIVE, "Discovery", "Found 8 hidden endpoints", 0.3),
    ]
    
    def run(self):
        self.state.agents["ActiveRecon"] = AgentStatus("ActiveRecon", "running")
        self.log.log(LogLevel.SYSTEM, "System", "ActiveReconAgent started")
        
        for i, (level, cat, msg, delay) in enumerate(self.TASKS):
            if self.is_stopped():
                break
            
            self.log.log(level, cat, msg)
            time.sleep(delay * random.uniform(0.8, 1.2))
            
            progress = int((i + 1) / len(self.TASKS) * 100)
            self.state.agents["ActiveRecon"].progress = progress
            self.state.agents["ActiveRecon"].current_task = cat
            
            if "port" in msg.lower():
                self._update_stats("ports", random.randint(3, 8))
            elif "url" in msg.lower() or "page" in msg.lower():
                self._update_stats("urls", random.randint(10, 50))
            elif "form" in msg.lower():
                self._update_stats("forms", random.randint(5, 25))
            elif "param" in msg.lower():
                self._update_stats("params", random.randint(10, 50))
        
        self.state.agents["ActiveRecon"].status = "done"
        self.log.log(LogLevel.SUCCESS, "ActiveRecon", "Active reconnaissance completed")


class ReportSimulator(SimulatedAgent):
    """Simulates Report Generation Agent."""
    
    def run(self):
        self.state.agents["Reporter"] = AgentStatus("Reporter", "running")
        self.log.log(LogLevel.SYSTEM, "System", "ReportAgent started")
        
        tasks = [
            "Aggregating reconnaissance data...",
            "Generating canonical JSON output...",
            "Creating attack surface summary...",
            "Writing phase1_canonical.json...",
            "Report generation complete",
        ]
        
        for i, msg in enumerate(tasks):
            if self.is_stopped():
                break
            self.log.log(LogLevel.AGENT, "Reporter", msg)
            time.sleep(0.5)
            self.state.agents["Reporter"].progress = int((i + 1) / len(tasks) * 100)
        
        self.state.agents["Reporter"].status = "done"
        self.log.log(LogLevel.SUCCESS, "Reporter", "Report saved to data/phase1_canonical.json")


# ══════════════════════════════════════════════════════════════════════════════
# Dashboard UI Components
# ══════════════════════════════════════════════════════════════════════════════

class DashboardUI:
    """Renders the Sentinel v3 Dashboard using Rich."""

    _LEVEL_STYLES = {
        LogLevel.PASSIVE:  ("Passive",  Theme.PASSIVE),
        LogLevel.ACTIVE:   ("Active",   Theme.ACTIVE),
        LogLevel.AGENT:    ("Agent",    Theme.AGENT),
        LogLevel.EXTERNAL: ("External", Theme.EXTERNAL),
        LogLevel.STRATEGY: ("Strategy", Theme.STRATEGY),
        LogLevel.SYSTEM:   ("System",   Theme.SYSTEM),
        LogLevel.ERROR:    ("ERROR",    Theme.ERROR),
        LogLevel.SUCCESS:  ("SUCCESS",  Theme.SUCCESS),
        LogLevel.WARNING:  ("WARNING",  Theme.WARNING),
    }

    def __init__(self, state: ScanState, log_manager: LogManager):
        self.console    = Console()
        self.state      = state
        self.log_manager = log_manager
        self.active_tab = 0
        self.tabs = ["Nhật ký", "Trạng thái Agent", "Thống kê"]
        # Log scroll state
        self.log_scroll_offset = 0  # 0 = bottom (newest), >0 = scroll up
        self.auto_scroll = True     # Auto-scroll to newest logs

    # ── Header ────────────────────────────────────────────────────────────────

    def render_header(self) -> Panel:
        """Compact single-line header."""
        t = Text(justify="center")
        t.append("CENTINEL ", style="bright_blue bold")
        t.append("v3", style="cyan bold")
        t.append("  —  Enterprise Pentest Multi-Agent System", style="dim cyan")
        return Panel(t, border_style="bright_blue", box=box.DOUBLE, padding=(0, 2))

    # ── Runtime info (LEFT) ───────────────────────────────────────────────────

    def _progress_bar(self, pct: int, width: int = 24) -> Text:
        filled = int(width * pct / 100)
        bar = Text()
        bar.append("█" * filled,            style="cyan")
        bar.append("░" * (width - filled),  style="dim blue")
        bar.append(f"  {pct:3d}%",          style="bold bright_blue")
        return bar

    def _status_text(self) -> Text:
        mp = {
            "idle":    ("●  Chờ",       "dim"),
            "running": ("●  Đang chạy", "green bold"),
            "done":    ("✓  Hoàn tất",  "bright_green bold"),
            "error":   ("✗  Lỗi",       "red bold"),
        }
        label, style = mp.get(self.state.status, (self.state.status, "white"))
        return Text(label, style=style)

    def _current_task(self) -> str:
        for agent in self.state.agents.values():
            if agent.status == "running" and agent.current_task:
                return agent.current_task
        return "—"

    def render_runtime_panel(self) -> Panel:
        """
        Compact left panel — all runtime info in one box:
        Target  |  Phase  |  Status  |  Elapsed  |  Task  |  Progress
        """
        elapsed = (
            f"{time.time() - self.state.start_time:.1f}s"
            if self.state.start_time else "—"
        )

        tbl = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        tbl.add_column("k", style="bright_blue bold", no_wrap=True, width=13)
        tbl.add_column("v", overflow="fold")

        tbl.add_row("🎯 Mục tiêu",   Text(self.state.target or "—", style="bright_white"))
        tbl.add_row("📊 Giai đoạn",  Text(self.state.phase,         style="cyan"))
        tbl.add_row("⚡ Trạng thái", self._status_text())
        tbl.add_row("⌛ Thời gian",  Text(elapsed,                  style="white"))
        tbl.add_row("🔧 Tác vụ",     Text(self._current_task(),     style="dim cyan"))
        tbl.add_row("📈 Tiến trình", self._progress_bar(self.state.progress))

        return Panel(
            tbl,
            title="[bright_blue bold]Thông tin quét[/bright_blue bold]",
            border_style="blue",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    # ── Actions (RIGHT) ───────────────────────────────────────────────────────

    def render_actions(self) -> Panel:
        """Compact right panel — action buttons stacked vertically."""
        if self.state.status == "running":
            primary = Text("  ⏹  Dừng quét  ", style="black on red bold")
        else:
            primary = Text("  ▶  Chạy quét  ", style="black on bright_green bold")

        lines = Text(justify="center")
        lines.append_text(primary)
        lines.append("\n\n")
        lines.append("  ⚙  Cài đặt  ", style="black on bright_blue")
        lines.append("   ")
        lines.append("  📄  Xuất  ",   style="black on cyan")
        lines.append("\n\n")
        lines.append("  ❓  Trợ giúp  ", style="black on magenta")

        return Panel(
            Align.center(lines, vertical="middle"),
            title="[bright_blue bold]Thao tác[/bright_blue bold]",
            border_style="blue",
            box=box.ROUNDED,
        )

    # ── Tabs ──────────────────────────────────────────────────────────────────

    def render_tabs(self) -> Text:
        tabs = Text()
        for i, name in enumerate(self.tabs):
            style = "bold bright_white on blue" if i == self.active_tab else "bright_blue"
            tabs.append(f"  {name}  ", style=style)
            tabs.append(" ")
        return tabs

    # ── Log panel ─────────────────────────────────────────────────────────────

    def render_log_panel(self) -> Panel:
        """
        Log panel — fills all remaining vertical space.
        Supports scrolling with Page Up/Down keys.
        """
        self.log_manager.process_queue()
        all_logs = self.log_manager.get_logs(limit=500)
        total = len(all_logs)
        
        # Display window size
        display_limit = 25  # Number of lines visible at once
        
        # Calculate scroll position
        if self.auto_scroll:
            # Auto-scroll: show newest logs
            start_idx = max(0, total - display_limit)
        else:
            # Manual scroll: respect scroll offset
            start_idx = max(0, total - display_limit - self.log_scroll_offset)
        
        end_idx = start_idx + display_limit
        logs = all_logs[start_idx:end_idx]

        log_text = Text()
        for i, entry in enumerate(logs):
            line_num = start_idx + i + 1
            log_text.append(f"[{line_num:03d}] ", style="dim")
            log_text.append(f"{entry.timestamp} ", style=Theme.TIMESTAMP)
            label, style = self._LEVEL_STYLES.get(entry.level, ("Info", "white"))
            log_text.append(f"[{label}]", style=f"bold {style}")
            if entry.category:
                log_text.append(f"[{entry.category}]", style="dim cyan")
            log_text.append(f" {entry.message}\n", style="white")

        if not logs:
            log_text.append("\n  [dim]Đang chờ quét bắt đầu...[/dim]")

        # Scroll indicator
        scroll_info = ""
        if not self.auto_scroll:
            scroll_info = f" | [yellow]PAUSED[/yellow] (nhấn END để tiếp tục)"
        elif self.log_scroll_offset > 0:
            scroll_info = f" | Scroll: +{self.log_scroll_offset}"
        
        subtitle = f"[dim]{total} dòng | PgUp/PgDn: cuộn | HOME/END: đầu/cuối{scroll_info}[/dim]"

        return Panel(
            log_text,
            title=f"[bright_blue bold]{self.tabs[self.active_tab]}[/bright_blue bold]",
            subtitle=subtitle,
            border_style="blue",
            box=box.ROUNDED,
        )
    
    def scroll_log_up(self, lines: int = 10):
        """Scroll log up (view older entries)."""
        self.auto_scroll = False
        total = len(self.log_manager.get_logs(limit=500))
        max_offset = max(0, total - 25)  # 25 is display_limit
        self.log_scroll_offset = min(self.log_scroll_offset + lines, max_offset)
    
    def scroll_log_down(self, lines: int = 10):
        """Scroll log down (view newer entries)."""
        self.log_scroll_offset = max(0, self.log_scroll_offset - lines)
        if self.log_scroll_offset == 0:
            self.auto_scroll = True
    
    def scroll_to_top(self):
        """Scroll to oldest log."""
        self.auto_scroll = False
        total = len(self.log_manager.get_logs(limit=500))
        self.log_scroll_offset = max(0, total - 25)
    
    def scroll_to_bottom(self):
        """Scroll to newest log and resume auto-scroll."""
        self.log_scroll_offset = 0
        self.auto_scroll = True

    # ── Bottom panels ─────────────────────────────────────────────────────────

    def _mini_bar(self, pct: int, width: int = 12) -> Text:
        filled = int(width * pct / 100)
        t = Text()
        t.append("█" * filled,           style="cyan")
        t.append("░" * (width - filled), style="dim blue")
        t.append(f" {pct}%",             style="bright_blue")
        return t

    def render_agent_status(self) -> Panel:
        tbl = Table(
            show_header=True, header_style="bold bright_blue",
            border_style="blue", box=box.SIMPLE, expand=True,
        )
        tbl.add_column("Agent",      style="cyan",    width=14)
        tbl.add_column("ST",         justify="center", width=3)
        tbl.add_column("Tác vụ",     style="dim",     ratio=1)
        tbl.add_column("Tiến trình", justify="right", width=18)

        icons = {"idle": "[dim]○[/dim]", "running": "[green]●[/green]",
                 "done": "[bright_green]✓[/bright_green]", "error": "[red]✗[/red]"}

        for name in ("PassiveRecon", "ActiveRecon", "Reporter"):
            ag = self.state.agents.get(name, AgentStatus(name))
            tbl.add_row(name, icons.get(ag.status, "○"),
                        ag.current_task or "—", self._mini_bar(ag.progress))

        return Panel(tbl,
                     title="[bright_blue bold]Agent[/bright_blue bold]",
                     border_style="blue", box=box.ROUNDED)

    def render_stats(self) -> Panel:
        stats = self.state.stats
        tbl = Table(show_header=False, box=None, expand=True, padding=(0, 1))
        tbl.add_column("Stat",  style="bright_blue")
        tbl.add_column("Value", justify="right", style="cyan bold")
        for label, key in [
            ("🌐 URLs",      "urls"),
            ("📝 Forms",     "forms"),
            ("🔧 Params",    "params"),
            ("🔌 Ports",     "ports"),
            ("🌍 Subdomains","subdomains"),
            ("📧 Emails",    "emails"),
            ("⚠️  Vulns",    "vulns"),
        ]:
            tbl.add_row(label, str(stats.get(key, 0)))
        return Panel(tbl,
                     title="[bright_blue bold]Thống kê[/bright_blue bold]",
                     border_style="blue", box=box.ROUNDED)

    # ── Footer ────────────────────────────────────────────────────────────────

    def render_footer(self) -> Text:
        t = Text(justify="center")
        for key, label in [("Q","Thoát"), ("R","Chạy"), ("S","Dừng"), ("5","Log đầy đủ")]:
            t.append(f" [{key}]", style="bold cyan")
            t.append(f" {label}  ", style="dim")
        return t

    # ── Master render ─────────────────────────────────────────────────────────

    def render(self) -> Group:
        """
        Compact layout:
          header   (3)   — single-line title
          top_row  (9)   — [runtime_panel | actions]  (merged info + progress)
          tabs     (1)   — tab bar
          main     (*)   — log panel fills remaining height  ← fixes scroll feel
          bottom   (6)   — [agent status | stats]
          footer   (1)   — shortcuts
        """
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="top_row", size=9),
            Layout(name="tabs",   size=1),
            Layout(name="main"),           # no size → fills remaining space
            Layout(name="bottom", size=6),
            Layout(name="footer", size=1),
        )

        layout["header"].update(self.render_header())

        layout["top_row"].split_row(
            Layout(self.render_runtime_panel(), name="runtime", ratio=3),
            Layout(self.render_actions(),       name="actions", ratio=1),
        )

        layout["tabs"].update(Align.center(self.render_tabs()))
        layout["main"].update(self.render_log_panel())

        layout["bottom"].split_row(
            Layout(self.render_agent_status(), name="agents", ratio=2),
            Layout(self.render_stats(),        name="stats",  ratio=1),
        )

        layout["footer"].update(self.render_footer())
        return Group(layout)


# ══════════════════════════════════════════════════════════════════════════════
# Main Application
# ══════════════════════════════════════════════════════════════════════════════

class SentinelApp:
    """Main Sentinel v3 Application."""
    
    def __init__(self, target: str = "", demo_mode: bool = False):
        self.state = ScanState(target=target)
        self.log_manager = LogManager()
        self.ui = DashboardUI(self.state, self.log_manager)
        self.demo_mode = demo_mode
        self.running = False
        self.agents: List[SimulatedAgent] = []
    
    def start_demo_scan(self):
        """Start a demo scan with simulated agents."""
        if self.running:
            return
        
        self.running = True
        self.state.status = "running"
        self.state.phase = "Reconnaissance"
        self.state.start_time = time.time()
        self.state.progress = 0
        
        self.log_manager.log(LogLevel.SYSTEM, "System", 
            f"Starting Sentinel v3 scan on: {self.state.target}")
        self.log_manager.log(LogLevel.STRATEGY, "Strategy", 
            "Adaptive reconnaissance mode enabled")
        
        # Start Phase 1a: Passive Recon
        self.state.phase = "Phase 1a: Passive Recon"
        passive_agent = PassiveReconSimulator("PassiveRecon", self.log_manager, self.state)
        passive_agent.start()
        self.agents.append(passive_agent)
        
        # Wait for passive to complete, then start active
        def run_active_after_passive():
            passive_agent.join()
            if not self.running:
                return
            
            self.state.phase = "Phase 1b: Active Recon"
            self.state.progress = 30
            
            active_agent = ActiveReconSimulator("ActiveRecon", self.log_manager, self.state)
            active_agent.start()
            self.agents.append(active_agent)
            active_agent.join()
            
            if not self.running:
                return
            
            self.state.phase = "Phase 1c: Reporting"
            self.state.progress = 70
            
            report_agent = ReportSimulator("Reporter", self.log_manager, self.state)
            report_agent.start()
            self.agents.append(report_agent)
            report_agent.join()
            
            if self.running:
                self.state.status = "done"
                self.state.phase = "Complete"
                self.state.progress = 100
                self.log_manager.log(LogLevel.SUCCESS, "System", 
                    "Sentinel v3 scan completed successfully!")
        
        threading.Thread(target=run_active_after_passive, daemon=True).start()
    
    def stop_scan(self):
        """Stop the current scan."""
        self.running = False
        self.state.status = "idle"
        
        for agent in self.agents:
            agent.stop()
        
        self.log_manager.log(LogLevel.WARNING, "System", "Scan stopped by user")
    
    def run_real_scan(self):
        """Run a real scan using the actual agents."""
        if self.running:
            return

        self.running = True
        self.state.status   = "running"
        self.state.progress = 0
        self.state.start_time = time.time()
        self.state.agents   = {}

        def execute_scan():
            try:
                from utils import load_dotenv, build_tool_config
                from memory import ScanMemory
                from agents.passive_recon_agent    import PassiveReconAgent
                from agents.active_recon_agent     import ActiveReconAgent
                from agents.recon_aggregator_agent import ReconAggregatorAgent
                from phase3.analysis_agent import AnalysisAgent
                from phase3.report_agent import ReportAgent
                import os as _os

                load_dotenv()

                bridge      = ScanBridge(self.state, self.log_manager)
                memory      = ScanMemory(self.state.target)
                tool_config = build_tool_config()
                tool_config["tool_tracker"] = bridge.make_tool_tracker()

                # ── Phase 1: Reconnaissance ───────────────────────────────────
                self.log_manager.log(LogLevel.SYSTEM, "System", "Phase 1 started")

                # ── Phase 1a: Passive Recon ───────────────────────────────────
                self.state.phase = "Phase 1a: Passive Recon  [RUNNING]"
                self.state.agents["PassiveRecon"] = AgentStatus("PassiveRecon", "running")
                self.log_manager.log(LogLevel.SYSTEM, "System",
                                     "Starting Passive Reconnaissance...")

                PassiveReconAgent(
                    log_callback=bridge.make_log_callback("passive", "PassiveRecon"),
                    memory=memory,
                    tool_config=tool_config,
                ).run(self.state.target)

                self.state.agents["PassiveRecon"].status   = "done"
                self.state.agents["PassiveRecon"].progress = 100
                self.state.phase = "Phase 1a: Passive Recon  [COMPLETE]"
                self.log_manager.log(LogLevel.SUCCESS, "System",
                                     "Passive Recon complete")

                if not self.running:
                    return

                # ── Phase 1b: Active Recon ────────────────────────────────────
                self.state.phase = "Phase 1b: Active Recon  [RUNNING]"
                self.state.agents["ActiveRecon"] = AgentStatus("ActiveRecon", "running")
                self.log_manager.log(LogLevel.SYSTEM, "System",
                                     "Starting Active Reconnaissance...")

                ActiveReconAgent(
                    log_callback=bridge.make_log_callback("active", "ActiveRecon"),
                    memory=memory,
                    tool_config=tool_config,
                ).run(self.state.target)

                self.state.agents["ActiveRecon"].status   = "done"
                self.state.agents["ActiveRecon"].progress = 100
                self.state.phase = "Phase 1b: Active Recon  [COMPLETE]"
                self.log_manager.log(LogLevel.SUCCESS, "System",
                                     "Active Recon complete")

                if not self.running:
                    return

                # ── Phase 1c: Aggregation (only after both phases done) ────────
                self.state.phase = "Phase 1c: Aggregation  [RUNNING]"
                self.state.agents["Reporter"] = AgentStatus("Reporter", "running")
                self.log_manager.log(LogLevel.SYSTEM, "System",
                                     "Aggregating results...")

                data_dir = _os.path.join(_os.path.dirname(__file__), "data")
                _os.makedirs(data_dir, exist_ok=True)

                ReconAggregatorAgent(
                    log_callback=bridge.make_log_callback("aggregate", "Aggregator"),
                    memory=memory,
                    output_dir=data_dir,
                ).run(self.state.target)

                bridge.aggregate_done()
                self.state.agents["Reporter"].status   = "done"
                self.state.agents["Reporter"].progress = 100

                self.log_manager.log(LogLevel.SUCCESS, "System", "Phase 1 completed")

                # ── Phase 3: Analysis & Report ────────────────────────────────
                self.log_manager.log(LogLevel.SYSTEM, "System", "Phase 3 started")

                canonical_path = _os.path.join(data_dir, "phase1_canonical.json")
                if not _os.path.isfile(canonical_path):
                    raise FileNotFoundError(
                        f"Phase 1 completed but canonical output not found: {canonical_path}"
                    )

                self.state.phase = "Phase 3a: Analysis  [RUNNING]"
                self.state.agents["AnalysisAgent"] = AgentStatus("AnalysisAgent", "running")
                self.log_manager.log(LogLevel.SYSTEM, "System", "Analysis started")

                analysis_path = AnalysisAgent().run(canonical_path, data_dir)

                self.state.agents["AnalysisAgent"].status = "done"
                self.state.agents["AnalysisAgent"].progress = 100
                self.log_manager.log(LogLevel.SUCCESS, "System", "Analysis completed")

                self.state.phase = "Phase 3b: Report  [RUNNING]"
                self.state.agents["ReportAgent"] = AgentStatus("ReportAgent", "running")
                self.log_manager.log(LogLevel.SYSTEM, "System", "Report started")

                ReportAgent().run(canonical_path, analysis_path, data_dir)

                self.state.agents["ReportAgent"].status = "done"
                self.state.agents["ReportAgent"].progress = 100
                self.log_manager.log(LogLevel.SUCCESS, "System", "Report completed")
                self.log_manager.log(LogLevel.SUCCESS, "System", "Phase 3 completed")

                # ── Complete — only set here, after ALL phases done ───────────
                self.state.progress = 100
                self.state.status   = "done"
                self.state.phase    = "Complete"
                self.log_manager.log(LogLevel.SUCCESS, "System",
                                     "Sentinel v3 scan completed successfully!")

            except Exception as exc:
                self.state.status = "error"
                self.log_manager.log(LogLevel.ERROR, "System",
                                     ScanBridge.sanitize(str(exc)))

        threading.Thread(target=execute_scan, daemon=True).start()
    
    def run(self):
        """Run the dashboard application."""
        console = Console()
        
        # Welcome message
        if not self.state.target:
            console.print("\n[bold bright_blue]Sentinel v3[/bold bright_blue] - Enterprise Pentest Multi-Agent\n")
            self.state.target = console.input("[cyan]Nhập URL mục tiêu:[/cyan] ").strip()
            if not self.state.target:
                self.state.target = "http://testfire.net"
                console.print(f"[dim]Using default target: {self.state.target}[/dim]")
        
        # Demo mode only: calculate progress from simulated agent states.
        # Real scan progress is tracked by ScanBridge per tool — no override needed.
        def update_progress_demo():
            while self.running:
                if self.state.status == "running" and self.demo_mode:
                    total = sum(a.progress for a in self.state.agents.values())
                    count = len(self.state.agents)
                    if count > 0:
                        self.state.progress = min(95, total // count)
                time.sleep(0.5)

        progress_thread = threading.Thread(target=update_progress_demo, daemon=True)
        progress_thread.start()
        
        # Start the scan
        if self.demo_mode:
            self.start_demo_scan()
        else:
            self.run_real_scan()
        
        # Setup keyboard listener for scrolling
        import msvcrt
        import sys
        
        def check_key():
            """Non-blocking key check for Windows."""
            if msvcrt.kbhit():
                key = msvcrt.getch()
                # Handle special keys (arrows, page up/down, home/end)
                if key == b'\xe0' or key == b'\x00':  # Special key prefix
                    key2 = msvcrt.getch()
                    if key2 == b'I':    # Page Up
                        self.ui.scroll_log_up(10)
                    elif key2 == b'Q':  # Page Down
                        self.ui.scroll_log_down(10)
                    elif key2 == b'H':  # Up arrow
                        self.ui.scroll_log_up(1)
                    elif key2 == b'P':  # Down arrow
                        self.ui.scroll_log_down(1)
                    elif key2 == b'G':  # Home
                        self.ui.scroll_to_top()
                    elif key2 == b'O':  # End
                        self.ui.scroll_to_bottom()
                elif key == b'q' or key == b'Q':
                    return 'quit'
            return None
        
        # Run live dashboard - auto exit when scan completes
        with Live(self.ui.render(), console=console, refresh_per_second=4, screen=True) as live:
            try:
                while True:
                    # Check for keyboard input
                    action = check_key()
                    if action == 'quit':
                        self.stop_scan()
                        break
                    
                    live.update(self.ui.render())
                    time.sleep(0.1)  # Faster refresh for keyboard responsiveness
                    
                    # Auto-exit when scan completes
                    if self.state.status in ("done", "error"):
                        # Wait for user to review, allow scrolling
                        self.log_manager.log(LogLevel.SYSTEM, "System",
                            "Scan hoàn tất! Nhấn Q để thoát hoặc PgUp/PgDn để xem log.")
                        while True:
                            action = check_key()
                            if action == 'quit':
                                break
                            live.update(self.ui.render())
                            time.sleep(0.1)
                        break
            except KeyboardInterrupt:
                self.stop_scan()
        
        # After exiting live view, show summary and interactive menu
        self._show_scan_summary(console)
    
    def _show_scan_summary(self, console: Console):
        """Show scan summary and interactive menu after scan completes."""
        import json
        import os
        
        console.print("\n")
        console.print("=" * 70)
        console.print(Align.center(Text("SCAN COMPLETE", style="bold bright_green")))
        console.print("=" * 70)
        
        # Load results from canonical JSON if available
        canonical_path = os.path.join(os.path.dirname(__file__), "data", "phase1_canonical.json")
        results = {}
        
        if os.path.exists(canonical_path):
            try:
                with open(canonical_path, "r", encoding="utf-8") as f:
                    results = json.load(f)
            except Exception as e:
                console.print(f"[red]Error loading results: {e}[/red]")
        
        # Summary table
        if results:
            summary = results.get("summary", {})
            passive = results.get("passive_recon", {})
            active = results.get("active_recon", {})
            
            # Target info panel
            target_info = Table(show_header=False, box=None, padding=(0, 2))
            target_info.add_column("Label", style="cyan bold")
            target_info.add_column("Value", style="white")
            target_info.add_row("🎯 Target:", results.get('target', self.state.target))
            target_info.add_row("🕐 Timestamp:", results.get('timestamp', 'N/A'))
            target_info.add_row("⏱️  Duration:", f"{self.state.start_time and (time.time() - self.state.start_time):.1f}s" if self.state.start_time else "N/A")
            console.print(Panel(target_info, title="[bold cyan]Scan Information[/bold cyan]", border_style="cyan"))
            
            # Main results table
            table = Table(
                title="[bold bright_blue]📊 Reconnaissance Results[/bold bright_blue]",
                border_style="blue",
                box=box.ROUNDED,
                show_header=True,
                header_style="bold cyan",
                expand=True,
            )
            table.add_column("Category", style="bright_blue", width=20)
            table.add_column("Count", justify="center", style="cyan bold", width=8)
            table.add_column("Details", style="white")
            
            # === PASSIVE RECON ===
            table.add_row("[bold magenta]── PASSIVE RECON ──[/bold magenta]", "", "", style="dim")
            
            # IP Addresses
            ip_addrs = passive.get("ip_addresses", [])
            table.add_row("🌐 IP Addresses", str(len(ip_addrs)), ", ".join(ip_addrs[:5]))
            
            # Subdomains
            subdomains = passive.get("subdomains", [])
            sub_names = [s.get("subdomain", "") for s in subdomains[:5]]
            sub_detail = ", ".join(sub_names)
            if len(subdomains) > 5:
                sub_detail += f" (+{len(subdomains)-5} more)"
            table.add_row("🔍 Subdomains", str(len(subdomains)), sub_detail)
            
            # theHarvester
            harvester = passive.get("theharvester", {})
            h_emails = harvester.get("emails", [])
            h_hosts = harvester.get("hosts", [])
            table.add_row("📧 Emails (Harvester)", str(len(h_emails)), ", ".join(h_emails[:3]) if h_emails else "[dim]none[/dim]")
            table.add_row("🖥️  Hosts (Harvester)", str(len(h_hosts)), ", ".join(h_hosts[:3]) if h_hosts else "[dim]none[/dim]")
            
            # Wayback
            wayback = passive.get("wayback", {})
            wayback_urls = wayback.get("urls", [])
            table.add_row("📜 Wayback URLs", str(len(wayback_urls)), f"[dim]Historical URLs from archive.org[/dim]")
            
            # crt.sh
            crtsh = passive.get("crtsh", {})
            crtsh_subs = crtsh.get("subdomains", [])
            table.add_row("🔐 crt.sh Certs", str(len(crtsh_subs)), ", ".join(crtsh_subs[:3]) if crtsh_subs else "[dim]none[/dim]")
            
            # Shodan
            shodan = passive.get("shodan", {})
            if shodan.get("source") not in ("no_api_key", "not_available", "skipped_localhost"):
                shodan_ports = shodan.get("ports", [])
                shodan_vulns = shodan.get("vulns", [])
                table.add_row("🔎 Shodan Ports", str(len(shodan_ports)), ", ".join(str(p.get("port","")) for p in shodan_ports[:5]))
                table.add_row("⚠️  Shodan Vulns", str(len(shodan_vulns)), ", ".join(shodan_vulns[:3]) if shodan_vulns else "[green]none[/green]")
            
            # === ACTIVE RECON ===
            table.add_row("[bold magenta]── ACTIVE RECON ──[/bold magenta]", "", "", style="dim")
            
            # Ports
            ports = active.get("ports", [])
            port_details = [f"{p.get('port')}/{p.get('service','?')}" for p in ports[:5]]
            table.add_row("🔌 Open Ports", str(len(ports)), ", ".join(port_details))
            
            # Crawl results
            crawl = active.get("crawl", {})
            table.add_row("🌍 Crawled URLs", str(len(crawl.get("urls", []))), "")
            table.add_row("📝 Forms Found", str(len(crawl.get("forms", []))), "")
            table.add_row("🔧 Parameters", str(len(crawl.get("params", []))), "")
            table.add_row("⭐ Notable Endpoints", str(len(crawl.get("notable_endpoints", []))), "")
            table.add_row("📜 JS Endpoints", str(len(crawl.get("js_endpoints", []))), "")
            table.add_row("🙈 Hidden Fields", str(len(crawl.get("hidden_fields", []))), "")
            
            # Hidden endpoints (ffuf)
            hidden = active.get("hidden_endpoints", [])
            hidden_paths = [h.get("path", "") for h in hidden[:5]]
            table.add_row("🔐 Hidden Endpoints", str(len(hidden)), ", ".join(hidden_paths) if hidden_paths else "[dim]none[/dim]")
            
            # WAF
            waf = active.get("waf", {})
            if waf.get("detected"):
                waf_status = f"[red]⚠️ {waf.get('name', 'Unknown')} ({waf.get('manufacturer', '')})[/red]"
            else:
                waf_status = "[green]✓ Not detected[/green]"
            table.add_row("🛡️  WAF Detection", "", waf_status)
            
            # Banners
            banners = active.get("banners", [])
            table.add_row("📡 Service Banners", str(len(banners)), "")
            
            console.print(table)
            
            # Technology Stack Panel
            tech = passive.get("technology", {})
            if tech.get("server") or tech.get("frameworks") or tech.get("whatweb"):
                tech_table = Table(show_header=False, box=None, padding=(0, 1))
                tech_table.add_column("Type", style="cyan")
                tech_table.add_column("Value", style="white")
                
                if tech.get("server"):
                    tech_table.add_row("Server:", tech["server"])
                if tech.get("frameworks"):
                    tech_table.add_row("Frameworks:", ", ".join(tech["frameworks"]))
                if tech.get("libraries"):
                    tech_table.add_row("Libraries:", ", ".join(tech["libraries"]))
                if tech.get("cms"):
                    tech_table.add_row("CMS:", tech["cms"])
                
                # WhatWeb plugins
                whatweb = tech.get("whatweb", [])
                if whatweb:
                    ww_names = [w.get("name", "") for w in whatweb if w.get("name")]
                    tech_table.add_row("WhatWeb:", ", ".join(ww_names[:10]))
                
                console.print(Panel(tech_table, title="[bold cyan]🔧 Technology Stack[/bold cyan]", border_style="cyan"))
            
            # SSL Info
            ssl_info = passive.get("ssl", {})
            if ssl_info.get("subject"):
                ssl_table = Table(show_header=False, box=None, padding=(0, 1))
                ssl_table.add_column("Field", style="cyan")
                ssl_table.add_column("Value", style="white")
                ssl_table.add_row("Subject:", ssl_info.get("subject", ""))
                ssl_table.add_row("Issuer:", ssl_info.get("issuer", ""))
                ssl_table.add_row("Valid Until:", ssl_info.get("not_after", ""))
                ssl_table.add_row("Days Remaining:", str(ssl_info.get("days_remaining", "?")))
                console.print(Panel(ssl_table, title="[bold green]🔒 SSL Certificate[/bold green]", border_style="green"))
            elif ssl_info.get("error"):
                console.print(Panel(f"[yellow]{ssl_info['error']}[/yellow]", title="[bold yellow]🔒 SSL Certificate[/bold yellow]", border_style="yellow"))
            
            # Security Headers
            sec_headers = tech.get("security_headers", {})
            missing_headers = [h for h, v in sec_headers.items() if v is None]
            if missing_headers:
                console.print(Panel(
                    "[yellow]Missing: [/yellow]" + ", ".join(missing_headers),
                    title="[bold yellow]⚠️ Security Headers[/bold yellow]",
                    border_style="yellow"
                ))
            
            # Limitations/Warnings
            limitations = summary.get("limitations", [])
            if limitations:
                lim_text = "\n".join([f"• {lim}" for lim in limitations])
                console.print(Panel(lim_text, title="[bold yellow]⚠️ Limitations[/bold yellow]", border_style="yellow"))
            
            # Tool Sources
            tool_sources = active.get("tool_sources", {})
            sources_text = " | ".join([f"{k}: [cyan]{v}[/cyan]" for k, v in tool_sources.items() if v != "none"])
            if sources_text:
                console.print(f"\n[dim]Tool Sources: {sources_text}[/dim]")
            
            # File location
            console.print(f"\n[green]✓ Full results saved to:[/green] [bold white]{canonical_path}[/bold white]")
        
        else:
            console.print("[yellow]No scan results available yet.[/yellow]")
        
        console.print("\n" + "=" * 70)
        
        # Interactive menu
        self._interactive_menu(console)
    
    def _show_full_execution_log(self, console: Console):
        """Show full execution log in scrollable format."""
        console.print("\n" + "=" * 70)
        console.print("[bold bright_blue]📋 NHẬT KÝ THỰC THI ĐẦY ĐỦ[/bold bright_blue]")
        console.print("[dim]Cuộn lên/xuống để xem tất cả[/dim]")
        console.print("=" * 70 + "\n")
        
        logs = self.log_manager.get_logs(limit=500)  # Get all logs
        
        if not logs:
            console.print("[yellow]Chưa có log nào.[/yellow]")
            return
        
        # Color mappings
        level_colors = {
            LogLevel.PASSIVE: "blue",
            LogLevel.ACTIVE: "cyan",
            LogLevel.AGENT: "magenta",
            LogLevel.EXTERNAL: "yellow",
            LogLevel.STRATEGY: "bright_blue",
            LogLevel.SYSTEM: "dim white",
            LogLevel.ERROR: "red",
            LogLevel.SUCCESS: "green",
            LogLevel.WARNING: "yellow",
        }
        
        level_labels = {
            LogLevel.PASSIVE: "Passive",
            LogLevel.ACTIVE: "Active",
            LogLevel.AGENT: "Agent",
            LogLevel.EXTERNAL: "External",
            LogLevel.STRATEGY: "Strategy",
            LogLevel.SYSTEM: "System",
            LogLevel.ERROR: "ERROR",
            LogLevel.SUCCESS: "SUCCESS",
            LogLevel.WARNING: "WARNING",
        }
        
        for i, entry in enumerate(logs, 1):
            color = level_colors.get(entry.level, "white")
            label = level_labels.get(entry.level, "Info")
            
            # Format: [001] [timestamp] [LEVEL][Category] message
            line = f"[dim][{i:03d}][/dim] "
            line += f"[dim]{entry.timestamp}[/dim] "
            line += f"[bold {color}][{label}][/bold {color}]"
            
            if entry.category:
                line += f"[dim cyan][{entry.category}][/dim cyan]"
            
            line += f" {entry.message}"
            
            console.print(line)
        
        console.print("\n" + "─" * 50)
        console.print(f"[dim]Tổng cộng: {len(logs)} dòng log[/dim]")
        console.print("[dim]Gợi ý: Dùng chuột/Page Up/Down để cuộn xem toàn bộ[/dim]")
    
    def _interactive_menu(self, console: Console):
        """Show interactive menu after scan."""
        while True:
            console.print("\n" + "─" * 50)
            console.print("[bold bright_blue]Tùy chọn:[/bold bright_blue]")
            console.print("  [cyan]1[/cyan] - Quét mục tiêu mới")
            console.print("  [cyan]2[/cyan] - Xem kết quả chi tiết (JSON)")
            console.print("  [cyan]3[/cyan] - Xuất báo cáo")
            console.print("  [cyan]4[/cyan] - Xem lịch sử quét")
            console.print("  [cyan]5[/cyan] - Xem toàn bộ nhật ký thực thi")
            console.print("  [cyan]q[/cyan] - Thoát")
            console.print("")

            choice = console.input("[cyan]Chọn:[/cyan] ").strip().lower()
            
            if choice == "1":
                # Run new scan
                new_target = console.input("[cyan]Nhập mục tiêu mới (Enter để giữ nguyên):[/cyan] ").strip()
                if new_target:
                    self.state.target = new_target
                
                # Reset state
                self.state.status = "idle"
                self.state.phase = "Idle"
                self.state.progress = 0
                self.state.start_time = None
                self.state.agents.clear()
                self.log_manager.clear()
                self.running = False
                
                # Restart scan
                self.run_real_scan()
                
                # Re-enter live view with auto-exit on complete
                with Live(self.ui.render(), console=console, refresh_per_second=4, screen=True) as live:
                    try:
                        while True:
                            live.update(self.ui.render())
                            time.sleep(0.25)
                            
                            # Auto-exit when scan completes
                            if self.state.status in ("done", "error"):
                                time.sleep(2)
                                break
                    except KeyboardInterrupt:
                        self.stop_scan()
                
                # Show summary again (recursive call will handle menu)
                self._show_scan_summary(console)
                return  # Exit this menu, new summary has its own menu
            
            elif choice == "2":
                # View JSON results
                import json
                import os
                canonical_path = os.path.join(os.path.dirname(__file__), "data", "phase1_canonical.json")
                if os.path.exists(canonical_path):
                    with open(canonical_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    from rich.syntax import Syntax
                    from rich.panel import Panel
                    
                    # Pretty print JSON
                    json_str = json.dumps(data, indent=2, ensure_ascii=False)
                    # Show only first part to avoid flooding console
                    if len(json_str) > 5000:
                        json_str = json_str[:5000] + "\n\n... [truncated - see full file]"
                    
                    syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
                    console.print(Panel(syntax, title="phase1_canonical.json", border_style="blue"))
                else:
                    console.print("[yellow]Chưa có file kết quả.[/yellow]")
            
            elif choice == "3":
                # Export report
                import json
                import os
                from datetime import datetime
                
                canonical_path = os.path.join(os.path.dirname(__file__), "data", "phase1_canonical.json")
                if os.path.exists(canonical_path):
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    export_name = f"sentinel_report_{timestamp}.json"
                    export_path = os.path.join(os.path.dirname(__file__), "reports", export_name)
                    
                    # Ensure reports dir exists
                    os.makedirs(os.path.dirname(export_path), exist_ok=True)
                    
                    # Copy file
                    import shutil
                    shutil.copy(canonical_path, export_path)
                    console.print(f"[green]✓ Đã xuất báo cáo:[/green] [white]{export_path}[/white]")
                else:
                    console.print("[yellow]Chưa có kết quả để xuất.[/yellow]")
            
            elif choice == "4":
                # View scan history
                import json
                import os
                history_path = os.path.join(os.path.dirname(__file__), "data", "scan_history.json")
                if os.path.exists(history_path):
                    with open(history_path, "r", encoding="utf-8") as f:
                        history = json.load(f)
                    
                    table = Table(title="Lịch sử quét", border_style="blue", box=box.ROUNDED)
                    table.add_column("ID", style="cyan")
                    table.add_column("Mục tiêu", style="white")
                    table.add_column("Thời gian", style="dim")
                    table.add_column("Trạng thái", style="green")
                    
                    scans = (history if isinstance(history, list) else [])[-10:]
                    for scan in reversed(scans):
                        table.add_row(
                            str(scan.get("id", "?"))[:8],
                            str(scan.get("target", "?"))[:40],
                            str(scan.get("scan_time") or scan.get("started_at", "?")),
                            str(scan.get("status", "done"))
                        )
                    
                    console.print(table)
                else:
                    console.print("[yellow]Chưa có lịch sử quét.[/yellow]")
            
            elif choice == "5":
                # View full execution log (scrollable in normal console)
                self._show_full_execution_log(console)
            
            elif choice == "q" or choice == "quit" or choice == "exit":
                console.print("[cyan]Tạm biệt![/cyan]")
                break
            
            else:
                console.print("[red]Lựa chọn không hợp lệ. Vui lòng thử lại.[/red]")


# ══════════════════════════════════════════════════════════════════════════════
# Entry Point
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="Sentinel v3 - Enterprise Pentest Multi-Agent Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --demo                    # Run demo mode with simulated scan
  python main.py --target http://example.com  # Scan a real target
  python main.py                           # Interactive mode (prompt for target)
        """
    )
    
    parser.add_argument(
        "--target", "-t",
        help="Target URL to scan"
    )
    parser.add_argument(
        "--demo", "-d",
        action="store_true",
        help="Run in demo mode with simulated agents"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["auto", "local", "kali_ssh"],
        default="auto",
        help="Tool execution mode (default: auto)"
    )
    
    args = parser.parse_args()
    
    # Print banner
    console = Console()
    console.print("""
[bright_blue bold]
   ____            __  _            __   _____
  / __/__ ___  / /_(_)__  ___ / /  |_  /
 _\\ \\/ -_) _ \\/ __/ / _ \\/ -_) /  / __/ 
/___/\\__/_//_/\\__/_/_//_/\\__/_/  /____/ 
                                    v3.0
[/bright_blue bold]
[cyan]Enterprise Pentest Multi-Agent System[/cyan]
[dim]────────────────────────────────────────[/dim]
    """)
    
    app = SentinelApp(target=args.target or "", demo_mode=args.demo)
    app.run()


if __name__ == "__main__":
    main()
