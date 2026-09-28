"""
Assignment 11 — Monitoring & Alerts.

Tracks block rate, rate-limit hits, judge fail rate.
Fires alerts when thresholds are exceeded.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


def default_metrics_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "metrics.json")


@dataclass
class Alert:
    metric: str
    value: float
    threshold: float
    message: str


@dataclass
class MonitoringAlert:
    """Aggregate counters from pipeline plugins and emit alerts."""

    block_rate_threshold: float = 0.5
    rate_limit_hit_threshold: int = 5
    judge_fail_rate_threshold: float = 0.3
    alerts: list[Alert] = field(default_factory=list)

    # Counters — update these from your pipeline after each request
    total_requests: int = 0
    blocked_requests: int = 0
    rate_limit_hits: int = 0
    redacted_responses: int = 0
    judge_checks: int = 0
    judge_fails: int = 0

    def check_metrics(self) -> list[Alert]:
        """Kiểm tra metrics, tạo Alert nếu vượt ngưỡng."""
        new_alerts = []
        # === Block rate ===
        if self.total_requests > 0:
            block_rate = self.blocked_requests / self.total_requests
            if block_rate > self.block_rate_threshold:  # mặc định 0.5 = 50%
                a = Alert("block_rate", block_rate, self.block_rate_threshold,
                        f"Block rate {block_rate:.1%} exceeds {self.block_rate_threshold:.0%}")
                new_alerts.append(a)
        # === Rate limit hits ===
        if self.rate_limit_hits > self.rate_limit_hit_threshold:  # mặc định 5
            a = Alert("rate_limit_hits", self.rate_limit_hits,
                    self.rate_limit_hit_threshold,
                    f"Rate limit hits {self.rate_limit_hits} > {self.rate_limit_hit_threshold}")
            new_alerts.append(a)
        # === Judge fail rate ===
        if self.judge_checks > 0:
            fail_rate = self.judge_fails / self.judge_checks
            if fail_rate > self.judge_fail_rate_threshold:  # mặc định 0.3 = 30%
                a = Alert("judge_fail_rate", fail_rate, self.judge_fail_rate_threshold,
                        f"Judge fail rate {fail_rate:.1%} exceeds threshold")
                new_alerts.append(a)
        self.alerts.extend(new_alerts)
        return new_alerts


    def export_json(self, filepath: str | None = None):
        """Ghi metrics + alerts ra JSON.

        Dùng ``filepath or default_metrics_path()`` để chạy từ ``src/``
        không sinh nhầm ``src/outputs/``.
        """
        path = Path(filepath or default_metrics_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        # self.snapshot() đã được code sẵn — trả về dict với tất cả metrics
        path.write_text(
            json.dumps(self.snapshot(), ensure_ascii=False, indent=2), encoding="utf-8"
        )

    def snapshot(self) -> dict:
        block_rate = (
            self.blocked_requests / self.total_requests
            if self.total_requests
            else 0.0
        )
        judge_fail_rate = (
            self.judge_fails / self.judge_checks if self.judge_checks else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "blocked_requests": self.blocked_requests,
            "block_rate": block_rate,
            "rate_limit_hits": self.rate_limit_hits,
            "redacted_responses": self.redacted_responses,
            "judge_checks": self.judge_checks,
            "judge_fails": self.judge_fails,
            "judge_fail_rate": judge_fail_rate,
            "alerts": [
                {
                    "metric": a.metric,
                    "value": a.value,
                    "threshold": a.threshold,
                    "message": a.message,
                }
                for a in self.alerts
            ],
        }
