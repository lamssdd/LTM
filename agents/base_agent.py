"""
base_agent.py — Lop co so cho tat ca Agent

Moi Agent co:
  - PROMPT  : mo ta nhiem vu cu the cua agent
  - run()   : template method (thiet lap trang thai -> execute())
  - log()   : ghi log va gui qua callback
  - memory  : tuy chon, tham chieu den ScanMemory dung chung
"""
import time
from abc import ABC, abstractmethod
from typing import Callable, Optional

from utils import make_log_entry


class BaseAgent(ABC):
    # Moi Agent con phai dinh nghia PROMPT mo ta nhiem vu
    PROMPT: str = "(chua dinh nghia)"

    def __init__(self, name: str,
                 log_callback: Callable[[dict], None] = None,
                 memory=None):          # memory: ScanMemory | None
        self.name         = name
        self.status       = "idle"      # idle | running | done | error
        self.log_callback = log_callback
        self.memory       = memory      # ScanMemory dung chung (tuy chon)

    # ── Logging ───────────────────────────────────────────────────────
    def log(self, message: str, level: str = "info") -> None:
        """Ghi log: tao entry chuan va gui qua callback."""
        entry = make_log_entry(self.name, level, message)
        if self.log_callback:
            self.log_callback(entry)

    # ── Template Method ───────────────────────────────────────────────
    def run(self, target: str, context: dict = None) -> dict:
        """
        Chay agent:
          1. Thiet lap trang thai
          2. Goi execute() (duoc override boi Agent con)
          3. Cap nhat trang thai khi hoan thanh / loi
        """
        self.status = "running"
        self.log(f"Bat dau: {target}", "info")
        try:
            result = self.execute(target, context or {})
            self.status = "done"
            self.log("Hoan thanh.", "success")
            return result
        except Exception as exc:
            self.status = "error"
            self.log(f"Loi: {exc}", "error")
            return {"error": str(exc)}

    @abstractmethod
    def execute(self, target: str, context: dict) -> dict:
        """Moi Agent con override phuong thuc nay."""
        pass
