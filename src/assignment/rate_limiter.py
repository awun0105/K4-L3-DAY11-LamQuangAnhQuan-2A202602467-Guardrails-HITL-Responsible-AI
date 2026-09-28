"""
Assignment 11 — Rate Limiter (sliding window, per user).

Sliding-window, per-user rate limiting. Blocks abuse that other
guardrail layers do not address (flooding / cost attacks).
"""
from __future__ import annotations

from collections import defaultdict, deque
import time

from google.adk.plugins import base_plugin
from google.genai import types


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block users who exceed max_requests within window_seconds."""

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.user_windows: dict[str, deque] = defaultdict(deque)
        self.blocked_count = 0
        self.total_count = 0

    def _block_response(self, message: str) -> types.Content:
        return types.Content(
            role="model",
            parts=[types.Part.from_text(text=message)],
        )

    async def on_user_message_callback(self, *, invocation_context, user_message):
        """Return Content to block, or None to allow."""
        self.total_count += 1
        user_id = getattr(invocation_context, "user_id", None) or "anonymous"
        now = time.time()
        window = self.user_windows[user_id]

        # === Bước 1: Dọn dẹp timestamp cũ hơn window ===
        # Ví dụ: window_seconds=60, now=100
        # window = [30, 45, 55, 60, 70] → xóa [30, 45] (cũ hơn 100-60=40)
        while window and window[0] < now - self.window_seconds:
            window.popleft()
        # === Bước 2: Đã đủ max → chặn ===
        if len(window) >= self.max_requests:
            wait = self.window_seconds - (now - window[0])
            # ↑ Tính thời gian chờ = bao lâu nữa slot cũ nhất hết hạn
            self.blocked_count += 1
            return self._block_response(
                f"Rate limit exceeded. Try again in {wait:.0f}s."
            )
        # === Bước 3: Còn slot → ghi timestamp, cho qua ===
        window.append(now)
        return None
