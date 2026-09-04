import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIRECTORY = PROJECT_ROOT / "logs"
AUDIT_FILE = LOG_DIRECTORY / "audit.jsonl"

LOG_DIRECTORY.mkdir(parents=True, exist_ok=True)

audit_logger = logging.getLogger("agent_security_audit")
audit_logger.setLevel(logging.INFO)
audit_logger.propagate = False

if not audit_logger.handlers:
    handler = logging.FileHandler(
        AUDIT_FILE,
        encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(handler)


def new_request_id() -> str:
    return str(uuid.uuid4())


def write_audit(
    *,
    request_id: str,
    user: str,
    agent: str,
    tool: str,
    decision: str,
    outcome: str,
    duration_ms: float | None = None,
    reason: str | None = None,
    metadata: dict[str, Any] | None = None
) -> None:

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "user": user,
        "agent": agent,
        "tool": tool,
        "decision": decision,
        "outcome": outcome,
        "duration_ms": (
            round(duration_ms, 2)
            if duration_ms is not None
            else None
        ),
        "reason": reason,
        "metadata": metadata or {}
    }

    audit_logger.info(
        json.dumps(event, ensure_ascii=False)
    )