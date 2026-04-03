#!/usr/bin/env python3
"""
phase1_console.py — Phase 1 Reconnaissance Scanner (Console Mode)

Usage:
  python phase1_console.py --target http://testfire.net
  python phase1_console.py --target example.com --mode kali_ssh --output-json results.json
  python phase1_console.py --target 192.168.1.1 --mode local --timeout 300

Arguments:
  --target       Target URL or hostname (required)
  --mode         Tool mode: auto, local, kali_ssh (default: auto)
  --timeout      Overall scan timeout in seconds (default: 600)
  --output-json  Save results to JSON file (optional)
"""
import argparse
import json
import os
import sys
import time
import threading
from datetime import datetime

# Fix Windows console encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    os.system("")  # Enable ANSI colors on Windows


def safe_print(*args, **kwargs):
    """Print with encoding error handling for Windows."""
    try:
        print(*args, **kwargs)
    except UnicodeEncodeError:
        text = " ".join(str(a) for a in args)
        print(text.encode('ascii', errors='replace').decode('ascii'), **kwargs)


# Load environment variables
from utils import load_dotenv, build_tool_config, normalize_url
load_dotenv()

from memory import ScanMemory
from agents.passive_recon_agent import PassiveReconAgent
from agents.active_recon_agent import ActiveReconAgent
from agents.recon_aggregator_agent import ReconAggregatorAgent


# ── ANSI Colors ───────────────────────────────────────────────────────────────
# Disable colors if not TTY (e.g., piped output)
_USE_COLORS = sys.stdout.isatty()

class Colors:
    RESET   = "\033[0m" if _USE_COLORS else ""
    BOLD    = "\033[1m" if _USE_COLORS else ""
    RED     = "\033[91m" if _USE_COLORS else ""
    GREEN   = "\033[92m" if _USE_COLORS else ""
    YELLOW  = "\033[93m" if _USE_COLORS else ""
    BLUE    = "\033[94m" if _USE_COLORS else ""
    MAGENTA = "\033[95m" if _USE_COLORS else ""
    CYAN    = "\033[96m" if _USE_COLORS else ""
    GRAY    = "\033[90m" if _USE_COLORS else ""


# ── Console ToolTracker ───────────────────────────────────────────────────────
class ConsoleToolTracker:
    """Track tool status and print realtime logs to console."""

    TOOL_META = {
        # Passive Recon
        "ip_resolve":   {"label": "IP Resolution",      "phase": "passive"},
        "dns":          {"label": "DNS Records",        "phase": "passive"},
        "whois":        {"label": "WHOIS Lookup",       "phase": "passive"},
        "subdomains":   {"label": "Subdomain Enum",     "phase": "passive"},
        "ssl":          {"label": "SSL / TLS",          "phase": "passive"},
        "tech":         {"label": "Tech Fingerprint",   "phase": "passive"},
        "whatweb":      {"label": "WhatWeb",            "phase": "passive"},
        "theharvester": {"label": "theHarvester",       "phase": "passive"},
        "sublist3r":    {"label": "Sublist3r",          "phase": "passive"},
        "crtsh":        {"label": "crt.sh",             "phase": "passive"},
        "wayback":      {"label": "Wayback Machine",    "phase": "passive"},
        "shodan":       {"label": "Shodan",             "phase": "passive"},
        # Active Recon
        "http_probe":   {"label": "HTTP Availability",  "phase": "active"},
        "headers":      {"label": "Response Headers",   "phase": "active"},
        "http_methods": {"label": "HTTP Methods",       "phase": "active"},
        "nmap":         {"label": "Port Scan (nmap)",   "phase": "active"},
        "wafw00f":      {"label": "WAF Detection",      "phase": "active"},
        "banner_grab":  {"label": "Banner Grabbing",    "phase": "active"},
        "syn_scan":     {"label": "SYN Scan",           "phase": "active"},
        "robots":       {"label": "robots.txt",         "phase": "active"},
        "crawl":        {"label": "Website Crawl",      "phase": "active"},
        "ffuf":         {"label": "Hidden Endpoints",   "phase": "active"},
    }

    def __init__(self):
        self._lock = threading.Lock()
        self._current = None
        self.state = {}
        self.stats = {"done": 0, "error": 0, "skipped": 0}

        for name, meta in self.TOOL_META.items():
            self.state[name] = {
                "status": "pending",
                "started_at": None,
                "ended_at": None,
                "elapsed": None,
                "error": None,
            }

    @property
    def current_tool(self):
        return self._current

    @property
    def counts(self):
        return self.stats

    def _timestamp(self):
        return datetime.now().strftime("%H:%M:%S")

    def _print(self, tool: str, event: str, message: str = "", color: str = Colors.RESET):
        ts = self._timestamp()
        label = self.TOOL_META.get(tool, {}).get("label", tool)
        phase = self.TOOL_META.get(tool, {}).get("phase", "")
        phase_color = Colors.CYAN if phase == "passive" else Colors.MAGENTA

        if event == "START":
            safe_print(f"{Colors.GRAY}[{ts}]{Colors.RESET} {phase_color}[{label}]{Colors.RESET} {Colors.YELLOW}START{Colors.RESET}")
        elif event == "DONE":
            safe_print(f"{Colors.GRAY}[{ts}]{Colors.RESET} {phase_color}[{label}]{Colors.RESET} {Colors.GREEN}DONE{Colors.RESET} {message}")
        elif event == "ERROR":
            safe_print(f"{Colors.GRAY}[{ts}]{Colors.RESET} {phase_color}[{label}]{Colors.RESET} {Colors.RED}ERROR{Colors.RESET} {message}")
        elif event == "SKIP":
            safe_print(f"{Colors.GRAY}[{ts}]{Colors.RESET} {phase_color}[{label}]{Colors.RESET} {Colors.GRAY}SKIP{Colors.RESET} {message}")
        elif event == "INFO":
            safe_print(f"{Colors.GRAY}[{ts}]{Colors.RESET} {phase_color}[{label}]{Colors.RESET} {message}")

    def start(self, name: str):
        if name not in self.state:
            return
        with self._lock:
            self._current = name
            self.state[name]["status"] = "running"
            self.state[name]["started_at"] = time.time()
        self._print(name, "START")

    def done(self, name: str, summary: str = "", result: dict = None):
        if name not in self.state:
            return
        with self._lock:
            t = self.state[name]
            t["status"] = "done"
            t["ended_at"] = time.time()
            t["elapsed"] = t["ended_at"] - (t["started_at"] or t["ended_at"])
            self.stats["done"] += 1
            if self._current == name:
                self._current = None
        elapsed_str = f"({t['elapsed']:.1f}s)" if t["elapsed"] else ""
        self._print(name, "DONE", f"{elapsed_str} {summary}")

    def error(self, name: str, error: str = ""):
        if name not in self.state:
            return
        with self._lock:
            t = self.state[name]
            t["status"] = "error"
            t["ended_at"] = time.time()
            t["elapsed"] = t["ended_at"] - (t["started_at"] or t["ended_at"])
            t["error"] = error
            self.stats["error"] += 1
            if self._current == name:
                self._current = None
        self._print(name, "ERROR", error)

    def skip(self, name: str, reason: str = ""):
        if name not in self.state:
            return
        with self._lock:
            self.state[name]["status"] = "skipped"
            self.stats["skipped"] += 1
        self._print(name, "SKIP", reason)

    def add_log(self, name: str, msg: str):
        """Log additional info for a tool."""
        if name in self.state:
            self._print(name, "INFO", msg)

    def snapshot(self) -> dict:
        with self._lock:
            import copy
            return copy.deepcopy(self.state)


# ── Console Logger ────────────────────────────────────────────────────────────
def make_console_logger(tracker: ConsoleToolTracker):
    """Create a log callback that prints to console with timestamps."""

    def log_callback(entry: dict):
        ts = datetime.now().strftime("%H:%M:%S")
        level = entry.get("level", "info").upper()
        agent = entry.get("agent", "")
        message = entry.get("message", "")
        tool = entry.get("tool", "")

        # Color based on level
        if level == "ERROR":
            color = Colors.RED
        elif level == "WARNING":
            color = Colors.YELLOW
        elif level == "SUCCESS":
            color = Colors.GREEN
        elif level == "PHASE":
            color = Colors.BOLD + Colors.BLUE
        else:
            color = Colors.RESET

        # Only print non-tool logs (tool logs handled by tracker)
        if not tool and message:
            if agent:
                safe_print(f"{Colors.GRAY}[{ts}]{Colors.RESET} {Colors.BLUE}[{agent}]{Colors.RESET} {color}{message}{Colors.RESET}")
            else:
                safe_print(f"{Colors.GRAY}[{ts}]{Colors.RESET} {color}{message}{Colors.RESET}")

    return log_callback


# ── Main Scanner ──────────────────────────────────────────────────────────────
def run_phase1_scan(target: str, mode: str = "auto", timeout: int = 600, output_json: str = None):
    """Run Phase 1 Recon scan in console mode."""

    safe_print(f"\n{'=' * 60}")
    safe_print(f"  Phase 1 Reconnaissance Scanner (Console Mode)")
    safe_print(f"{'=' * 60}")
    safe_print(f"  Target:  {target}")
    safe_print(f"  Mode:    {mode}")
    safe_print(f"  Timeout: {timeout}s")
    safe_print(f"{'=' * 60}\n")

    start_time = time.time()

    # Initialize tracker and logger
    tracker = ConsoleToolTracker()
    log_callback = make_console_logger(tracker)

    # Build tool config
    tool_config = build_tool_config(mode=mode)
    tool_config["tool_tracker"] = tracker

    # Initialize memory
    memory = ScanMemory(target)

    # Create data directory
    data_dir = os.path.join(os.path.dirname(__file__), "data")
    os.makedirs(data_dir, exist_ok=True)

    try:
        # ── Phase 1a: Passive Recon ───────────────────────────────────────────
        safe_print(f"\n[Phase 1a] Passive Reconnaissance")
        safe_print(f"{'-' * 50}")

        passive_agent = PassiveReconAgent(
            log_callback=log_callback,
            memory=memory,
            tool_config=tool_config
        )
        passive_result = passive_agent.run(target)

        if passive_result.get("error"):
            safe_print(f"PassiveRecon error: {passive_result['error']}")

        # ── Phase 1b: Active Recon ────────────────────────────────────────────
        safe_print(f"\n[Phase 1b] Active Reconnaissance")
        safe_print(f"{'-' * 50}")

        active_agent = ActiveReconAgent(
            log_callback=log_callback,
            memory=memory,
            tool_config=tool_config
        )
        active_result = active_agent.run(target)

        if active_result.get("error"):
            safe_print(f"ActiveRecon error: {active_result['error']}")

        # ── Phase 1c: Aggregation ─────────────────────────────────────────────
        safe_print(f"\n[Phase 1c] Aggregation")
        safe_print(f"{'-' * 50}")

        aggregator = ReconAggregatorAgent(
            log_callback=log_callback,
            memory=memory,
            output_dir=data_dir
        )
        agg_result = aggregator.run(target)

        if agg_result.get("error"):
            safe_print(f"Aggregator error: {agg_result['error']}")

        # Get canonical result
        canonical = memory.get_canonical_phase1()

    except KeyboardInterrupt:
        safe_print(f"\nScan interrupted by user")
        canonical = memory.get_canonical_phase1() if memory else {}
    except Exception as e:
        safe_print(f"\nFatal error: {e}")
        canonical = {}

    # ── Summary ───────────────────────────────────────────────────────────────
    elapsed = time.time() - start_time
    summary = canonical.get("summary", {})
    stats = tracker.counts

    safe_print(f"\n{'=' * 60}")
    safe_print(f"  SCAN COMPLETE")
    safe_print(f"{'=' * 60}")
    safe_print(f"  Target:       {target}")
    safe_print(f"  Duration:     {elapsed:.1f}s")
    safe_print(f"  Tools:        {stats['done']} done / {stats['error']} error / {stats['skipped']} skipped")
    safe_print(f"{'-' * 60}")
    safe_print(f"  URLs:         {summary.get('total_urls', 0)}")
    safe_print(f"  Forms:        {summary.get('total_forms', 0)}")
    safe_print(f"  Params:       {summary.get('total_params', 0)}")
    safe_print(f"  Subdomains:   {summary.get('total_subdomains', 0)}")
    safe_print(f"  Hidden:       {summary.get('total_hidden_endpoints', 0)}")
    safe_print(f"  Notable:      {summary.get('total_notable_endpoints', 0)}")
    safe_print(f"{'=' * 60}")

    # Save JSON if requested
    json_path = os.path.join(data_dir, "phase1_canonical.json")
    if output_json:
        try:
            with open(output_json, "w", encoding="utf-8") as f:
                json.dump(canonical, f, indent=2, ensure_ascii=False)
            safe_print(f"\nResults saved to: {output_json}")
        except Exception as e:
            safe_print(f"\nFailed to save JSON: {e}")
    else:
        safe_print(f"\nResults saved to: {json_path}")

    return canonical


# ── CLI Entry Point ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Phase 1 Reconnaissance Scanner (Console Mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python phase1_console.py                                    # Interactive mode
  python phase1_console.py --target http://testfire.net
  python phase1_console.py --target example.com --mode kali_ssh
  python phase1_console.py --target 192.168.1.1 --mode local --output-json scan.json
        """
    )
    parser.add_argument(
        "--target", "-t",
        required=False,
        help="Target URL or hostname (will prompt if not provided)"
    )
    parser.add_argument(
        "--mode", "-m",
        choices=["auto", "local", "kali_ssh"],
        default=None,
        help="Tool mode (default: auto)"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="Overall scan timeout in seconds (default: 600)"
    )
    parser.add_argument(
        "--output-json", "-o",
        help="Save results to JSON file"
    )

    args = parser.parse_args()

    # Interactive mode if no target provided
    target = args.target
    if not target:
        safe_print("\n" + "=" * 50)
        safe_print("  Phase 1 Reconnaissance Scanner")
        safe_print("=" * 50)
        try:
            target = input("\nEnter target (URL or hostname): ").strip()
        except (KeyboardInterrupt, EOFError):
            safe_print("\nCancelled.")
            sys.exit(0)
        
        if not target:
            safe_print("Error: Target is required")
            sys.exit(1)

    # Interactive mode selection if not provided
    mode = args.mode
    if not mode:
        safe_print("\nSelect mode:")
        safe_print("  1. auto     - Auto-detect best tools")
        safe_print("  2. kali_ssh - Use Kali Linux via SSH")
        safe_print("  3. local    - Local tools only")
        try:
            choice = input("\nChoice [1/2/3] (default: 1): ").strip()
        except (KeyboardInterrupt, EOFError):
            safe_print("\nCancelled.")
            sys.exit(0)
        
        mode_map = {"1": "auto", "2": "kali_ssh", "3": "local", "": "auto"}
        mode = mode_map.get(choice, "auto")

    # Run scan
    try:
        run_phase1_scan(
            target=target,
            mode=mode,
            timeout=args.timeout,
            output_json=args.output_json
        )
    except Exception as e:
        safe_print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
