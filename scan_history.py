"""
scan_history.py — Persistent Agent Memory cho lich su quet bao mat.

=== SCOPE: Agent Memory (luu tru xuyen session) ===

Muc dich:
  - Luu moi ket qua scan thanh 1 entry JSON trong file history.json
  - Doc lai lich su khi app restart (persistent memory)
  - Cung cap API de UI hien thi lich su va so sanh cac lan scan

Cau truc moi entry:
  {
    "id":           "1774318834",          # timestamp string (unique key)
    "target":       "http://example.com",
    "scan_time":    "24/03/2026 09:20:34",
    "total_elapsed":"42.3s",
    "risk_score":   58,
    "risk_label":   "RUI RO CAO",
    "report_path":  "reports/report_...html",
    "pdf_path":     "reports/report_...pdf",
    "vuln_summary": {
        "total": 13, "critical": 0, "high": 4,
        "medium": 4, "low": 5, "info": 0
    },
    "top_findings": [                      # Top 5 lo hong nghiem trong nhat
        {"severity":"HIGH","title":"...","category":"...","cwe":"..."},
        ...
    ],
    "phase1_data": {                       # Full Phase 1 recon data
        "target": "http://example.com",
        "timestamp": "2026-04-03T21:27:33",
        "passive_recon": {...},            # PassiveReconAgent output
        "active_recon": {...},             # ActiveReconAgent output
        "summary": {...}                   # Aggregated summary
    }
  }

Luu tru: data/scan_history.json (tao tu dong neu chua co)
"""
import json
import os
import time
import threading


HISTORY_FILE = os.path.join(os.path.dirname(__file__), "data", "scan_history.json")
MAX_ENTRIES  = 50   # Giu toi da 50 ket qua gan nhat

_lock = threading.Lock()


def _ensure_dir():
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)


def load_history() -> list:
    """Doc toan bo lich su scan tu file. Tra ve list rong neu chua co."""
    _ensure_dir()
    if not os.path.isfile(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        return []


def save_entry(entry: dict) -> None:
    """
    Them 1 ket qua scan moi vao history.
    Thread-safe. Giu toi da MAX_ENTRIES entries.
    """
    with _lock:
        _ensure_dir()
        history = load_history()

        # Tranh luu trung entry (cung target + scan_time)
        existing_ids = {e.get("id") for e in history}
        if entry.get("id") in existing_ids:
            return

        history.insert(0, entry)          # Moi nhat len dau
        history = history[:MAX_ENTRIES]   # Gioi han so entry

        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, ensure_ascii=False, indent=2)


def build_entry(target: str, result: dict) -> dict:
    """
    Tao 1 history entry tu ket qua scan cua Orchestrator.

    Args:
        target : URL muc tieu
        result : orchestrator.result dict (chua 'vuln' va 'report')

    Returns:
        dict san sang luu vao history
    """
    report = result.get("report", {})
    vuln   = result.get("vuln", {})
    vulns  = vuln.get("vulnerabilities", [])
    phase1 = result.get("phase1", {})
    recon_summary = phase1.get("summary", {}) or report.get("summary", {})
    highlights = (phase1.get("crawl", {}) or {}).get("notable_endpoints", [])

    # Top 5 lo hong nghiem trong nhat
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_vulns = sorted(vulns, key=lambda v: sev_order.get(v.get("severity", "INFO"), 4))
    top_findings = [
        {
            "severity": v.get("severity", ""),
            "title":    v.get("title",    ""),
            "category": v.get("category", ""),
            "cwe":      v.get("cwe",      ""),
        }
        for v in sorted_vulns[:5]
    ]

    # Extract phase1 data for full storage (canonical format from ReconAggregatorAgent)
    phase1_data = None
    if phase1:
        phase1_data = {
            "target": phase1.get("target", target),
            "timestamp": phase1.get("timestamp", time.strftime("%Y-%m-%dT%H:%M:%S")),
            "passive_recon": phase1.get("passive_recon", {}),
            "active_recon": phase1.get("active_recon", {}),
            "summary": phase1.get("summary", recon_summary),
        }

    return {
        "id":           str(int(time.time())),
        "target":       target,
        "scan_time":    report.get("scan_time", time.strftime("%d/%m/%Y %H:%M:%S")),
        "total_elapsed":result.get("total_elapsed", ""),
        "risk_score":   report.get("risk_score", 0),
        "risk_label":   report.get("risk_label", ""),
        "report_path":  report.get("report_path", ""),
        "pdf_path":     report.get("pdf_path", ""),
        "vuln_summary": {
            "total":    vuln.get("total",    0),
            "critical": vuln.get("critical", 0),
            "high":     vuln.get("high",     0),
            "medium":   vuln.get("medium",   0),
            "low":      vuln.get("low",      0),
            "info":     vuln.get("info",     0),
        },
        "recon_summary": {
            "total_urls": recon_summary.get("total_urls", 0),
            "total_forms": recon_summary.get("total_forms", 0),
            "total_params": recon_summary.get("total_params", 0),
            "limitations": recon_summary.get("limitations", []),
        },
        "highlights": highlights[:5],
        "top_findings": top_findings,
        "phase1_data": phase1_data,  # Full phase1 recon data
    }


def get_entry(entry_id: str) -> dict | None:
    """Tim entry theo ID. Tra ve None neu khong tim thay."""
    for entry in load_history():
        if entry.get("id") == entry_id:
            return entry
    return None


def delete_entry(entry_id: str) -> bool:
    """Xoa 1 entry khoi history. Tra ve True neu xoa thanh cong."""
    with _lock:
        history = load_history()
        new_history = [e for e in history if e.get("id") != entry_id]
        if len(new_history) == len(history):
            return False
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(new_history, f, ensure_ascii=False, indent=2)
        return True
