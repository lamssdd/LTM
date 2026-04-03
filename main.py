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
        """Clear all logs."""
        with self._lock:
            self._logs.clear()


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
    
    def __init__(self, state: ScanState, log_manager: LogManager):
        self.console = Console()
        self.state = state
        self.log_manager = log_manager
        self.active_tab = 0
        self.tabs = ["Execution Log", "Agent Status", "Statistics", "Timeline"]
    
    def render_header(self) -> Panel:
        """Render the header with title and status."""
        title = Text()
        title.append("█▀ █▀▀ █▄░█ ▀█▀ █ █▄░█ █▀▀ █░░   ", style="bright_blue bold")
        title.append("v3", style="cyan bold")
        title.append("\n", style="")
        title.append("█▄ ██▄ █░▀█ ░█░ █ █░▀█ ██▄ █▄▄   ", style="bright_blue bold")
        title.append("Enterprise Pentest Multi-Agent System", style="dim cyan")
        
        return Panel(
            Align.center(title),
            border_style="bright_blue",
            box=box.DOUBLE,
            padding=(0, 2),
        )
    
    def render_target_info(self) -> Panel:
        """Render target information panel."""
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Label", style="bright_blue bold")
        table.add_column("Value", style="bright_white")
        
        table.add_row("🎯 Target:", self.state.target or "[dim]Not specified[/dim]")
        table.add_row("📊 Phase:", f"[cyan]{self.state.phase}[/cyan]")
        table.add_row("⏱️  Status:", self._get_status_text())
        
        if self.state.start_time:
            elapsed = time.time() - self.state.start_time
            table.add_row("⌛ Elapsed:", f"{elapsed:.1f}s")
        
        return Panel(
            table,
            title="[bright_blue bold]Target Information[/bright_blue bold]",
            border_style="blue",
            box=box.ROUNDED,
        )
    
    def _get_status_text(self) -> str:
        """Get formatted status text."""
        status_map = {
            "idle": "[dim]● Idle[/dim]",
            "running": "[green]● Running[/green]",
            "paused": "[yellow]● Paused[/yellow]",
            "done": "[bright_green]✓ Complete[/bright_green]",
            "error": "[red]✗ Error[/red]",
        }
        return status_map.get(self.state.status, self.state.status)
    
    def render_controls(self) -> Panel:
        """Render control buttons."""
        buttons = []
        
        if self.state.status == "idle":
            buttons.append(Text(" ▶ Run Sentinel ", style="black on bright_green bold"))
        elif self.state.status == "running":
            buttons.append(Text(" ⏹ Stop Scan ", style="black on red bold"))
        else:
            buttons.append(Text(" ▶ Run Sentinel ", style="black on bright_green bold"))
        
        buttons.append(Text("   ", style=""))
        buttons.append(Text(" ⚙ Settings ", style="black on bright_blue"))
        buttons.append(Text("   ", style=""))
        buttons.append(Text(" 📄 Export ", style="black on cyan"))
        buttons.append(Text("   ", style=""))
        buttons.append(Text(" ❓ Help ", style="black on magenta"))
        
        return Panel(
            Align.center(Text.assemble(*buttons)),
            border_style="blue",
            box=box.ROUNDED,
            padding=(0, 1),
        )
    
    def render_progress(self) -> Panel:
        """Render progress bar."""
        progress = Progress(
            SpinnerColumn(spinner_name="dots", style="cyan"),
            TextColumn("[bright_blue]{task.description}[/bright_blue]"),
            BarColumn(bar_width=40, style="blue", complete_style="cyan"),
            TextColumn("[cyan]{task.percentage:>3.0f}%[/cyan]"),
            TimeElapsedColumn(),
            expand=True,
        )
        
        task = progress.add_task(
            f"Phase: {self.state.phase}",
            total=100,
            completed=self.state.progress
        )
        
        return Panel(
            progress,
            title="[bright_blue bold]Progress[/bright_blue bold]",
            border_style="blue",
            box=box.ROUNDED,
        )
    
    def render_tabs(self) -> Text:
        """Render tab navigation."""
        tabs = Text()
        for i, tab_name in enumerate(self.tabs):
            if i == self.active_tab:
                tabs.append(f" {tab_name} ", style="bold bright_white on blue")
            else:
                tabs.append(f" {tab_name} ", style="bright_blue")
            tabs.append("  ", style="")
        return tabs
    
    def render_log_panel(self) -> Panel:
        """Render the main console log panel."""
        # Process any new logs
        self.log_manager.process_queue()
        
        logs = self.log_manager.get_logs(limit=35)  # Show more logs (was 20)
        
        log_text = Text()
        for entry in logs:
            # Timestamp
            log_text.append(f"[{entry.timestamp}] ", style=Theme.TIMESTAMP)
            
            # Level/Category badge
            level_styles = {
                LogLevel.PASSIVE: ("Passive", Theme.PASSIVE),
                LogLevel.ACTIVE: ("Active", Theme.ACTIVE),
                LogLevel.AGENT: ("Agent", Theme.AGENT),
                LogLevel.EXTERNAL: ("External", Theme.EXTERNAL),
                LogLevel.STRATEGY: ("Strategy", Theme.STRATEGY),
                LogLevel.SYSTEM: ("System", Theme.SYSTEM),
                LogLevel.ERROR: ("ERROR", Theme.ERROR),
                LogLevel.SUCCESS: ("SUCCESS", Theme.SUCCESS),
                LogLevel.WARNING: ("WARNING", Theme.WARNING),
            }
            
            label, style = level_styles.get(entry.level, ("Info", "white"))
            log_text.append(f"[{label}]", style=f"bold {style}")
            
            # Category
            if entry.category:
                log_text.append(f"[{entry.category}]", style="dim cyan")
            
            # Message
            log_text.append(f" {entry.message}\n", style="white")
        
        if not logs:
            log_text.append("[dim]Waiting for scan to start...[/dim]")
        
        return Panel(
            log_text,
            title=f"[bright_blue bold]{self.tabs[self.active_tab]}[/bright_blue bold]",
            subtitle="[dim]View full log after scan (Option 5)[/dim]",
            border_style="blue",
            box=box.ROUNDED,
            height=28,  # Taller panel for more logs
        )
    
    def render_agent_status(self) -> Panel:
        """Render agent status panel."""
        table = Table(
            show_header=True,
            header_style="bold bright_blue",
            border_style="blue",
            box=box.SIMPLE,
            expand=True,
        )
        
        table.add_column("Agent", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Task", style="dim")
        table.add_column("Progress", justify="right")
        
        default_agents = ["PassiveRecon", "ActiveRecon", "Reporter"]
        
        for agent_name in default_agents:
            agent = self.state.agents.get(agent_name, AgentStatus(agent_name))
            
            status_icons = {
                "idle": "[dim]○[/dim]",
                "running": "[green]●[/green]",
                "done": "[bright_green]✓[/bright_green]",
                "error": "[red]✗[/red]",
            }
            status = status_icons.get(agent.status, "○")
            
            progress_bar = self._mini_progress_bar(agent.progress)
            
            table.add_row(
                agent_name,
                status,
                agent.current_task or "-",
                progress_bar,
            )
        
        return Panel(
            table,
            title="[bright_blue bold]Agent Status[/bright_blue bold]",
            border_style="blue",
            box=box.ROUNDED,
        )
    
    def _mini_progress_bar(self, progress: int, width: int = 15) -> Text:
        """Create a mini progress bar."""
        filled = int(width * progress / 100)
        empty = width - filled
        
        bar = Text()
        bar.append("█" * filled, style="cyan")
        bar.append("░" * empty, style="dim blue")
        bar.append(f" {progress}%", style="bright_blue")
        return bar
    
    def render_stats(self) -> Panel:
        """Render statistics panel."""
        stats = self.state.stats
        
        table = Table(show_header=False, box=None, expand=True, padding=(0, 2))
        table.add_column("Stat", style="bright_blue")
        table.add_column("Value", justify="right", style="cyan bold")
        
        stat_items = [
            ("🌐 URLs", stats.get("urls", 0)),
            ("📝 Forms", stats.get("forms", 0)),
            ("🔧 Params", stats.get("params", 0)),
            ("🔌 Ports", stats.get("ports", 0)),
            ("🌍 Subdomains", stats.get("subdomains", 0)),
            ("📧 Emails", stats.get("emails", 0)),
            ("⚠️  Vulns", stats.get("vulns", 0)),
        ]
        
        for label, value in stat_items:
            table.add_row(label, str(value))
        
        return Panel(
            table,
            title="[bright_blue bold]Statistics[/bright_blue bold]",
            border_style="blue",
            box=box.ROUNDED,
        )
    
    def render_footer(self) -> Text:
        """Render footer with keyboard shortcuts."""
        footer = Text()
        footer.append(" [Q]", style="bold cyan")
        footer.append(" Quit  ", style="dim")
        footer.append("[R]", style="bold cyan")
        footer.append(" Run  ", style="dim")
        footer.append("[S]", style="bold cyan")
        footer.append(" Stop  ", style="dim")
        footer.append("[Tab]", style="bold cyan")
        footer.append(" Switch Tab  ", style="dim")
        footer.append("[E]", style="bold cyan")
        footer.append(" Export  ", style="dim")
        return Align.center(footer)
    
    def render(self) -> Group:
        """Render the complete dashboard."""
        # Create layout
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=5),
            Layout(name="info_row", size=7),
            Layout(name="progress", size=5),
            Layout(name="tabs", size=1),
            Layout(name="main", size=24),
            Layout(name="bottom", size=7),
            Layout(name="footer", size=1),
        )
        
        layout["header"].update(self.render_header())
        
        # Info row: target + controls
        layout["info_row"].split_row(
            Layout(self.render_target_info(), name="target"),
            Layout(self.render_controls(), name="controls"),
        )
        
        layout["progress"].update(self.render_progress())
        layout["tabs"].update(Align.center(self.render_tabs()))
        layout["main"].update(self.render_log_panel())
        
        # Bottom row: agent status + stats
        layout["bottom"].split_row(
            Layout(self.render_agent_status(), name="agents", ratio=2),
            Layout(self.render_stats(), name="stats", ratio=1),
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
        self.state.status = "running"
        self.state.start_time = time.time()
        
        def execute_scan():
            try:
                from utils import load_dotenv, build_tool_config
                from memory import ScanMemory
                from agents.passive_recon_agent import PassiveReconAgent
                from agents.active_recon_agent import ActiveReconAgent
                from agents.recon_aggregator_agent import ReconAggregatorAgent
                
                load_dotenv()
                
                memory = ScanMemory(self.state.target)
                tool_config = build_tool_config()
                
                # Passive Recon
                self.state.phase = "Phase 1a: Passive Recon"
                self.log_manager.log(LogLevel.SYSTEM, "System", "Starting Passive Reconnaissance...")
                
                def log_cb(entry):
                    level = LogLevel.PASSIVE
                    if "active" in entry.get("agent", "").lower():
                        level = LogLevel.ACTIVE
                    self.log_manager.log(level, entry.get("agent", ""), entry.get("message", ""))
                
                passive = PassiveReconAgent(log_callback=log_cb, memory=memory, tool_config=tool_config)
                passive.run(self.state.target)
                
                self.state.progress = 30
                
                # Active Recon
                self.state.phase = "Phase 1b: Active Recon"
                self.log_manager.log(LogLevel.SYSTEM, "System", "Starting Active Reconnaissance...")
                
                active = ActiveReconAgent(log_callback=log_cb, memory=memory, tool_config=tool_config)
                active.run(self.state.target)
                
                self.state.progress = 70
                
                # Aggregation
                self.state.phase = "Phase 1c: Reporting"
                self.log_manager.log(LogLevel.SYSTEM, "System", "Generating report...")
                
                aggregator = ReconAggregatorAgent(log_callback=log_cb, memory=memory, output_dir="data")
                aggregator.run(self.state.target)
                
                self.state.progress = 100
                self.state.status = "done"
                self.state.phase = "Complete"
                self.log_manager.log(LogLevel.SUCCESS, "System", "Scan completed successfully!")
                
            except Exception as e:
                self.state.status = "error"
                self.log_manager.log(LogLevel.ERROR, "System", f"Error: {e}")
        
        threading.Thread(target=execute_scan, daemon=True).start()
    
    def run(self):
        """Run the dashboard application."""
        console = Console()
        
        # Welcome message
        if not self.state.target:
            console.print("\n[bold bright_blue]Sentinel v3[/bold bright_blue] - Enterprise Pentest Multi-Agent\n")
            self.state.target = console.input("[cyan]Enter target URL:[/cyan] ").strip()
            if not self.state.target:
                self.state.target = "http://testfire.net"
                console.print(f"[dim]Using default target: {self.state.target}[/dim]")
        
        # Update progress during scan
        def update_progress():
            while self.running:
                if self.state.status == "running":
                    # Calculate progress from agent states
                    total = 0
                    count = 0
                    for agent in self.state.agents.values():
                        total += agent.progress
                        count += 1
                    if count > 0:
                        self.state.progress = min(95, total // count)
                time.sleep(0.5)
        
        progress_thread = threading.Thread(target=update_progress, daemon=True)
        progress_thread.start()
        
        # Start the scan
        if self.demo_mode:
            self.start_demo_scan()
        else:
            self.run_real_scan()
        
        # Run live dashboard - auto exit when scan completes
        with Live(self.ui.render(), console=console, refresh_per_second=4, screen=True) as live:
            try:
                while True:
                    live.update(self.ui.render())
                    time.sleep(0.25)
                    
                    # Auto-exit when scan completes
                    if self.state.status in ("done", "error"):
                        time.sleep(2)  # Brief pause to show final state
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
        console.print("[bold bright_blue]📋 FULL EXECUTION LOG[/bold bright_blue]")
        console.print("[dim]Scroll up/down with your terminal to view all entries[/dim]")
        console.print("=" * 70 + "\n")
        
        logs = self.log_manager.get_logs(limit=500)  # Get all logs
        
        if not logs:
            console.print("[yellow]No logs available.[/yellow]")
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
        console.print(f"[dim]Total: {len(logs)} log entries[/dim]")
        console.print("[dim]Tip: Use terminal scroll (Page Up/Down or mouse wheel) to browse[/dim]")
    
    def _interactive_menu(self, console: Console):
        """Show interactive menu after scan."""
        while True:
            console.print("\n" + "─" * 50)
            console.print("[bold bright_blue]Options:[/bold bright_blue]")
            console.print("  [cyan]1[/cyan] - Run new scan")
            console.print("  [cyan]2[/cyan] - View detailed results (JSON)")
            console.print("  [cyan]3[/cyan] - Export report")
            console.print("  [cyan]4[/cyan] - View scan history")
            console.print("  [cyan]5[/cyan] - View full execution log (scrollable)")
            console.print("  [cyan]q[/cyan] - Quit")
            console.print("")
            
            choice = console.input("[cyan]Select option:[/cyan] ").strip().lower()
            
            if choice == "1":
                # Run new scan
                new_target = console.input("[cyan]Enter target URL (or press Enter for same target):[/cyan] ").strip()
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
                    console.print("[yellow]No results file found.[/yellow]")
            
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
                    console.print(f"[green]✓ Report exported to:[/green] [white]{export_path}[/white]")
                else:
                    console.print("[yellow]No results to export.[/yellow]")
            
            elif choice == "4":
                # View scan history
                import json
                import os
                history_path = os.path.join(os.path.dirname(__file__), "data", "scan_history.json")
                if os.path.exists(history_path):
                    with open(history_path, "r", encoding="utf-8") as f:
                        history = json.load(f)
                    
                    table = Table(title="Scan History", border_style="blue", box=box.ROUNDED)
                    table.add_column("ID", style="cyan")
                    table.add_column("Target", style="white")
                    table.add_column("Timestamp", style="dim")
                    table.add_column("Status", style="green")
                    
                    scans = history.get("scans", [])[-10:]  # Last 10 scans
                    for scan in reversed(scans):
                        table.add_row(
                            scan.get("id", "?")[:8],
                            scan.get("target", "?")[:40],
                            scan.get("started_at", "?"),
                            scan.get("status", "?")
                        )
                    
                    console.print(table)
                else:
                    console.print("[yellow]No scan history found.[/yellow]")
            
            elif choice == "5":
                # View full execution log (scrollable in normal console)
                self._show_full_execution_log(console)
            
            elif choice == "q" or choice == "quit" or choice == "exit":
                console.print("[cyan]Goodbye! 👋[/cyan]")
                break
            
            else:
                console.print("[red]Invalid option. Please try again.[/red]")


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
