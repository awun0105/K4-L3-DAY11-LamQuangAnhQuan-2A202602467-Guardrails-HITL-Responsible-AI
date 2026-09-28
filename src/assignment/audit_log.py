"""
Assignment 11 — Audit Log.

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations
import time
import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Ghi lại khi user gửi message (input + start timestamp)."""
        key = request_id or user_id
        self._open[key] = time.time()  # Ghi thời điểm bắt đầu để tính latency sau
        self.logs.append({
            "type": "input",
            "user_id": user_id,
            "request_id": request_id,
            "text": text,
            "timestamp": utc_now_iso(),
        })
    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Ghi lại khi hệ thống trả lời (hoặc chặn) + layer + latency."""
        key = request_id or user_id
        start = self._open.pop(key, None)  # Lấy thời điểm bắt đầu
        latency = time.time() - start if start else None  # Tính thời gian xử lý
        self.logs.append({
            "type": "output",
            "user_id": user_id,
            "request_id": request_id,
            "text": text[:300],              # Cắt ngắn để file không quá lớn
            "blocked": blocked,
            "layer": layer,                  # "input_guardrail" / "rate_limiter" / None
            "latency_s": round(latency, 3) if latency else None,
            "timestamp": utc_now_iso(),
        })
    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        """Ghi toàn bộ log ra file JSON."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)  # Tạo outputs/ nếu chưa có
        path.write_text(
            json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8"
        )

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
