"""Append-only, hash-chained audit trail.

Each record links to its predecessor: ``hash = sha256(prev_hash + canonical_json)``
with a genesis of 64 zeros.  Deleting, reordering or editing any record breaks
verification, which is what makes the log usable as evidence of *what the agent
did and what it refused to do*.

The log is also a safety mechanism: a refusal (``outcome="denied"``) is written
before the exception is raised, so attempts to go out of scope are recorded
rather than silently dropped.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Iterable

from .model import canonical_json, sha256_hex

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str, engagement_id: str, actor: str, run_id: str = "-") -> None:
        self.path = path
        self.engagement_id = engagement_id
        self.actor = actor
        self.run_id = run_id
        self._lock = threading.Lock()
        self._seq = 0
        self._prev = GENESIS

        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        if os.path.exists(path) and os.path.getsize(path) > 0:
            self._load_tail()
        else:
            open(path, "a", encoding="utf-8").close()

    def _load_tail(self) -> None:
        last: dict[str, Any] | None = None
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = json.loads(line)
        if last is not None:
            self._seq = int(last["seq"])
            self._prev = last["hash"]

    def record(
        self,
        action: str,
        outcome: str,
        *,
        target: str | None = None,
        tier: int | None = None,
        detail: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            body = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "engagement": self.engagement_id,
                "run": self.run_id,
                "actor": self.actor,
                "action": action,
                "target": target,
                "tier": tier,
                "outcome": outcome,
                "detail": detail or {},
                "prev_hash": self._prev,
            }
            body["hash"] = sha256_hex(self._prev + canonical_json(body))
            line = canonical_json(body)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._prev = body["hash"]
            return body


def verify_chain(path: str) -> dict[str, Any]:
    """Recompute the chain and report the first inconsistency (if any)."""
    prev = GENESIS
    count = 0
    try:
        fh = open(path, "r", encoding="utf-8")
    except FileNotFoundError:
        return {"ok": False, "records": 0, "reason": "audit log not found", "path": path}

    with fh:
        for idx, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError as exc:
                return {"ok": False, "records": count, "reason": f"line {idx}: invalid JSON ({exc})", "path": path}
            claimed = rec.pop("hash", None)
            if rec.get("prev_hash") != prev:
                return {"ok": False, "records": count, "reason": f"line {idx}: prev_hash mismatch", "path": path}
            expected = sha256_hex(prev + canonical_json(rec))
            if claimed != expected:
                return {"ok": False, "records": count, "reason": f"line {idx}: hash mismatch (tampered or truncated)", "path": path}
            if rec.get("seq") != count + 1:
                return {"ok": False, "records": count, "reason": f"line {idx}: seq gap", "path": path}
            prev = claimed
            count += 1

    return {"ok": True, "records": count, "head": prev, "path": path}


def read_records(path: str) -> Iterable[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)
