"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
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
        self._open: dict[tuple[str, str | None], tuple[str, str, float]] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Record request context and the start of latency measurement."""
        self._open[user_id, request_id] = (text, utc_now_iso(), time.monotonic())

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Close the matching request and record its outcome."""
        pending = self._open.pop((user_id, request_id), None)
        self.logs.append({
            "user_id": user_id,
            "request_id": request_id,
            "input": pending[0] if pending else None,
            "timestamp": pending[1] if pending else utc_now_iso(),
            "output": text,
            "blocked": blocked,
            "layer": layer,
            "latency_ms": (time.monotonic() - pending[2]) * 1000 if pending else None,
        })

    def export_json(self, filepath: str | None = None):
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
