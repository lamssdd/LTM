"""
orchestrator.py — ScanOrchestrator + ToolTracker cho Phase 1 Pipeline.

Runtime path:
  PassiveReconAgent -> ActiveReconAgent -> ReconAggregatorAgent

ToolTracker inject vao agents qua tool_config['tool_tracker'] de cap nhat
trang thai tung tool theo thoi gian thuc qua SSE.
"""
import queue
import threading
import time
import uuid


# ── ToolTracker ───────────────────────────────────────────────────────────────

class ToolTracker:
    """Theo doi trang thai tung tool va phat events qua SSE."""

    TOOL_META = {
        # Passive Recon
        "ip_resolve":   {"label": "IP Resolution",           "phase": "passive"},
        "dns":          {"label": "DNS Records",             "phase": "passive"},
        "whois":        {"label": "WHOIS Lookup",            "phase": "passive"},
        "subdomains":   {"label": "Subdomain Enum",          "phase": "passive"},
        "ssl":          {"label": "SSL / TLS",               "phase": "passive"},
        "tech":         {"label": "Tech Fingerprint",        "phase": "passive"},
        "whatweb":      {"label": "WhatWeb",                 "phase": "passive"},
        "theharvester": {"label": "theHarvester",            "phase": "passive"},
        "sublist3r":    {"label": "Sublist3r",               "phase": "passive"},
        "crtsh":        {"label": "crt.sh",                  "phase": "passive"},
        "wayback":      {"label": "Wayback Machine",         "phase": "passive"},
        "shodan":       {"label": "Shodan",                  "phase": "passive"},
        # Active Recon
        "http_probe":   {"label": "HTTP Availability",       "phase": "active"},
        "headers":      {"label": "Response Headers",        "phase": "active"},
        "http_methods": {"label": "HTTP Methods",            "phase": "active"},
        "nmap":         {"label": "Port Scan (nmap)",        "phase": "active"},
        "wafw00f":      {"label": "WAF Detection",           "phase": "active"},
        "banner_grab":  {"label": "Banner Grabbing",         "phase": "active"},
        "syn_scan":     {"label": "SYN Scan (Scapy)",        "phase": "active"},
        "robots":       {"label": "robots.txt / Sitemap",    "phase": "active"},
        "crawl":        {"label": "Website Crawl",           "phase": "active"},
        "ffuf":         {"label": "Hidden Endpoints",        "phase": "active"},
    }

    def __init__(self, emit_fn):
        self._emit  = emit_fn
        self._lock  = threading.Lock()
        self._cur   = None   # ten tool dang chay
        self.state  = {}
        for name, meta in self.TOOL_META.items():
            self.state[name] = {
                "name":       name,
                "label":      meta["label"],
                "phase":      meta["phase"],
                "status":     "pending",
                "started_at": None,
                "ended_at":   None,
                "elapsed":    None,
                "summary":    "",
                "result":     {},
                "error":      None,
                "logs":       [],
            }

    @property
    def current_tool(self):
        return self._cur

    @property
    def counts(self):
        total   = len(self.state)
        done    = sum(1 for t in self.state.values() if t["status"] == "done")
        errors  = sum(1 for t in self.state.values() if t["status"] == "error")
        running = sum(1 for t in self.state.values() if t["status"] == "running")
        return {"total": total, "done": done, "errors": errors, "running": running,
                "pending": total - done - errors - running}

    def start(self, name: str):
        if name not in self.state:
            return
        with self._lock:
            self._cur = name
            t = self.state[name]
            t["status"]     = "running"
            t["started_at"] = time.strftime("%H:%M:%S")
            t["_start_ts"]  = time.time()
        self._emit({
            "type": "tool_event", "event": "start",
            "tool": name, "label": self.state[name]["label"],
            "phase": self.state[name]["phase"],
            "time": time.strftime("%H:%M:%S"),
        })

    def done(self, name: str, summary: str = "", result: dict = None):
        if name not in self.state:
            return
        with self._lock:
            t = self.state[name]
            t["status"]   = "done"
            t["ended_at"] = time.strftime("%H:%M:%S")
            elapsed = time.time() - t.pop("_start_ts", time.time())
            t["elapsed"]  = f"{elapsed:.1f}s"
            t["summary"]  = summary
            if result is not None:
                t["result"] = result
            if self._cur == name:
                self._cur = None
        self._emit({
            "type": "tool_event", "event": "done",
            "tool": name, "label": self.state[name]["label"],
            "phase": self.state[name]["phase"],
            "time": time.strftime("%H:%M:%S"),
            "elapsed": self.state[name]["elapsed"],
            "summary": summary,
        })

    def error(self, name: str, error: str = ""):
        if name not in self.state:
            return
        with self._lock:
            t = self.state[name]
            t["status"]   = "error"
            t["ended_at"] = time.strftime("%H:%M:%S")
            elapsed = time.time() - t.pop("_start_ts", time.time())
            t["elapsed"]  = f"{elapsed:.1f}s"
            t["error"]    = error
            if self._cur == name:
                self._cur = None
        self._emit({
            "type": "tool_event", "event": "error",
            "tool": name, "label": self.state[name]["label"],
            "phase": self.state[name]["phase"],
            "time": time.strftime("%H:%M:%S"),
            "error": error,
        })

    def add_log(self, name: str, msg: str):
        """Gan log entry vao tool cu the."""
        with self._lock:
            if name in self.state:
                self.state[name]["logs"].append(msg)

    def snapshot(self) -> dict:
        """Tra ve ban sao trang thai hien tai (thread-safe)."""
        with self._lock:
            import copy
            return copy.deepcopy(self.state)


# ── ScanOrchestrator ──────────────────────────────────────────────────────────

class ScanOrchestrator:
    """Dieu phoi runtime Phase 1: Passive + Active Recon + Aggregation."""

    _PROGRESS = {
        "start":           0,
        "passive_start":   5,
        "passive_done":   30,
        "active_start":   35,
        "active_done":    70,
        "aggregate_start":75,
        "aggregate_done": 95,
        "done":          100,
    }

    def __init__(self, output_dir: str = "reports", tool_config: dict = None):
        self.output_dir  = output_dir
        self.tool_config = tool_config
        self.log_queue: queue.Queue = queue.Queue()
        self.result: dict  = {}
        self.status: str   = "idle"
        self.progress: int = 0
        self.scan_id: str  = ""
        self.started_at: str = ""
        self._current_target: str = ""
        self._stop_evt  = threading.Event()
        self._thread    = None
        self.timings: dict = {}
        self._tracker: ToolTracker = None

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self, target: str, tool_config: dict = None):
        if self.status == "running":
            return
        self._scan_tool_config = tool_config if tool_config is not None else self.tool_config
        self.status   = "running"
        self.result   = {}
        self.progress = 0
        self.timings  = {}
        self.scan_id  = uuid.uuid4().hex[:8].upper()
        self.started_at = time.strftime("%H:%M:%S")
        self._current_target = target
        self.log_queue = queue.Queue()
        self._stop_evt.clear()
        self._tracker = ToolTracker(self._tool_event)
        self._thread  = threading.Thread(target=self._run, args=(target,), daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_evt.set()

    def get_logs(self) -> list:
        logs = []
        try:
            while True:
                logs.append(self.log_queue.get_nowait())
        except queue.Empty:
            pass
        return logs

    @property
    def tools_state(self) -> dict:
        return self._tracker.snapshot() if self._tracker else {}

    @property
    def current_tool(self) -> str:
        return self._tracker.current_tool if self._tracker else ""

    @property
    def tool_counts(self) -> dict:
        return self._tracker.counts if self._tracker else {}

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _tool_event(self, entry: dict):
        """Nhan tool event tu ToolTracker va day vao queue."""
        self.log_queue.put(entry)

    def _log_cb(self, entry: dict):
        """Nhan log tu agents, gan them tool hien tai neu co."""
        entry["type"] = "log"
        cur = self._tracker.current_tool if self._tracker else None
        if cur:
            entry["tool"] = cur
            if self._tracker:
                self._tracker.add_log(cur, entry.get("message", ""))
        self.log_queue.put(entry)

    def _push(self, level: str, message: str, progress: int = None):
        if progress is not None:
            self.progress = progress
        self.log_queue.put({
            "type":     "log",
            "time":     time.strftime("%H:%M:%S"),
            "agent":    "Orchestrator",
            "level":    level.lower(),
            "message":  message,
            "progress": self.progress,
        })

    def _elapsed(self, key: str) -> str:
        ts = self.timings.get(key)
        return f"{time.time() - ts:.1f}s" if ts else ""

    # ── Run ───────────────────────────────────────────────────────────────────

    def _run(self, target: str):
        total_start = time.time()
        memory      = None
        try:
            from memory import ScanMemory
            memory = ScanMemory(target)
            tool_cfg   = getattr(self, "_scan_tool_config", None)
            mode_label = (tool_cfg or {}).get("mode", "auto")
            self._push("info",
                f"[{self.scan_id}] Bat dau scan: {target} | mode={mode_label}",
                self._PROGRESS["start"])
            self._run_direct(target, memory, total_start, tool_config=tool_cfg)
        except Exception as exc:
            self.status = "error"
            self._push("error", f"Loi nghiem trong: {exc}")

    def _run_direct(self, target: str, memory, total_start: float,
                    tool_config: dict = None):
        import os
        from utils import build_tool_config
        from agents.passive_recon_agent    import PassiveReconAgent
        from agents.active_recon_agent     import ActiveReconAgent
        from agents.recon_aggregator_agent import ReconAggregatorAgent

        effective_cfg = dict(tool_config or build_tool_config())
        # Inject ToolTracker vao tool_config de agents dung
        effective_cfg["tool_tracker"] = self._tracker

        project_root = os.path.dirname(__file__)
        data_dir     = os.path.join(project_root, "data")

        # ── Phase 1a: Passive Recon ───────────────────────────────────────────
        self._push("phase",
            "[1a] PassiveReconAgent — IP, WHOIS, DNS, SSL, Technology",
            self._PROGRESS["passive_start"])
        self.timings["passive"] = time.time()

        pr = PassiveReconAgent(
            log_callback=self._log_cb, memory=memory, tool_config=effective_cfg
        ).run(target)
        if pr.get("error"):
            memory.add_limitation(f"PassiveRecon error: {pr['error']}")

        if self._stop_evt.is_set():
            self.status = "error"; return

        passive = memory.get_passive_recon()
        self._push("phase",
            f"[1a] PassiveRecon done in {self._elapsed('passive')} | "
            f"IP: {passive.get('ip_addresses', ['?'])[0] if passive.get('ip_addresses') else '?'} | "
            f"SSL: {'OK' if passive.get('ssl', {}).get('subject') else 'N/A'}",
            self._PROGRESS["passive_done"])

        # ── Phase 1b: Active Recon ────────────────────────────────────────────
        self._push("phase",
            "[1b] ActiveReconAgent — HTTP, Ports, Crawl, Endpoints",
            self._PROGRESS["active_start"])
        self.timings["active"] = time.time()

        ar = ActiveReconAgent(
            log_callback=self._log_cb, memory=memory, tool_config=effective_cfg
        ).run(target)
        if ar.get("error"):
            memory.add_limitation(f"ActiveRecon error: {ar['error']}")

        if self._stop_evt.is_set():
            self.status = "error"; return

        active = memory.get_active_recon()
        crawl  = active.get("crawl", {})
        self._push("phase",
            f"[1b] ActiveRecon done in {self._elapsed('active')} | "
            f"Ports: {len(active.get('ports', []))} | "
            f"URLs: {len(crawl.get('urls', []))} | "
            f"Hidden: {len(active.get('hidden_endpoints', []))}",
            self._PROGRESS["active_done"])

        # ── Phase 1c: Aggregation ─────────────────────────────────────────────
        self._push("phase",
            "[1c] ReconAggregatorAgent — Canonical JSON",
            self._PROGRESS["aggregate_start"])
        self.timings["aggregate"] = time.time()

        agg = ReconAggregatorAgent(
            log_callback=self._log_cb, memory=memory, output_dir=data_dir,
        ).run(target)
        if agg.get("error"):
            raise RuntimeError(agg["error"])

        canonical = memory.get_canonical_phase1()
        s = canonical.get("summary", {})
        self._push("phase",
            f"[1c] Aggregation done in {self._elapsed('aggregate')} | "
            f"URLs:{s.get('total_urls',0)} Forms:{s.get('total_forms',0)} "
            f"Notable:{s.get('total_notable_endpoints',0)} Hidden:{s.get('total_hidden_endpoints',0)}",
            self._PROGRESS["aggregate_done"])

        if self._stop_evt.is_set():
            self.status = "error"; return

        json_path = os.path.join(data_dir, "phase1_canonical.json")
        self._push("phase", f"[Phase 1 Complete] JSON: {json_path}",
                   self._PROGRESS["done"])

        self._finalize({
            "target":    target,
            "phase1":    canonical,
            "json_path": json_path,
            "vuln":      {},
        }, total_start)

    def _finalize(self, results: dict, total_start: float):
        total_elapsed = f"{time.time() - total_start:.1f}s"
        phase1    = results.get("phase1", {})
        json_path = results.get("json_path", "")
        self.result = {
            "target":        results.get("target", self._current_target),
            "phase1":        phase1,
            "json_path":     json_path,
            "vuln":          results.get("vuln", {}),
            "total_elapsed": total_elapsed,
        }
        self.status = "done"

        try:
            from scan_history import build_entry, save_entry
            entry = build_entry(self._current_target, self.result)
            save_entry(entry)
            self._push("info", f"[Memory] Da luu lich su (ID: {entry['id']})")
        except Exception as exc:
            self._push("warning", f"[Memory] Khong the luu: {exc}")

        summary = phase1.get("summary", {})
        self._push("done",
            f"Phase 1 hoan tat trong {total_elapsed} | "
            f"URLs:{summary.get('total_urls',0)} Forms:{summary.get('total_forms',0)} "
            f"JSON:{json_path}",
            self._PROGRESS["done"])
