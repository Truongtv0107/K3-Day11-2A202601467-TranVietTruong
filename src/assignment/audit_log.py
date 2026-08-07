from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


class AuditLogPlugin:
    """Correlation-aware audit log for input, output, policy and HITL decisions."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None, metadata: dict | None = None) -> str:
        request_id = request_id or str(uuid.uuid4())
        self._open[request_id] = {
            "started": time.perf_counter(),
            "timestamp": utc_now_iso(),
            "request_id": request_id,
            "user_id": user_id,
            "input": text,
            "metadata": metadata or {},
        }
        return request_id

    def record_output(self, *, user_id: str, text: str, blocked: bool = False, layer: str | None = None,
                      request_id: str | None = None, metadata: dict | None = None) -> dict:
        request_id = request_id or str(uuid.uuid4())
        item = self._open.pop(request_id, {
            "started": time.perf_counter(), "timestamp": utc_now_iso(),
            "request_id": request_id, "user_id": user_id, "input": "", "metadata": {},
        })
        item["metadata"].update(metadata or {})
        item.update({
            "output": text,
            "blocked": bool(blocked),
            "layer": layer,
            "latency_ms": round((time.perf_counter() - item.pop("started")) * 1000, 3),
        })
        self.logs.append(item)
        return item

    def record_hitl(self, *, request_id: str, intent: str, proposed_diff: dict, decision: str,
                    reviewer_id: str | None = None, approval_id: str | None = None) -> dict:
        event = {
            "timestamp": utc_now_iso(), "request_id": request_id, "event_type": "hitl_decision",
            "intent": intent, "proposed_diff": proposed_diff, "decision": decision,
            "reviewer_id": reviewer_id, "approval_id": approval_id,
        }
        self.logs.append(event)
        return event

    def replay_snapshot(self, request_id: str) -> list[dict]:
        """Return all events for one correlation ID for incident replay."""
        return [event for event in self.logs if event.get("request_id") == request_id]

    def export_json(self, filepath: str = "outputs/audit_log.json") -> str:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
