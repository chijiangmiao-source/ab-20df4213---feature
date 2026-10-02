"""In-memory store of frozen audit conclusions."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone


def fingerprint(payload: dict) -> str:
    """Stable digest of a canonicalized request payload."""
    blob = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AuditRecord:
    """Immutable per-audit conclusion set."""

    audit_id: str
    digest: str
    rules: list
    verdicts: list
    created_at: str

    def response(self) -> dict:
        return {
            "audit_id": self.audit_id,
            "created_at": self.created_at,
            "rules": self.rules,
            "verdicts": self.verdicts,
        }


class AuditStore:
    """Thread-safe audit_id -> AuditRecord map.  Records never change."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, AuditRecord] = {}

    def get(self, audit_id: str) -> AuditRecord | None:
        with self._lock:
            return self._records.get(audit_id)

    def put_if_absent(self, record: AuditRecord) -> AuditRecord:
        """Store the record; return whatever record owns the slot."""
        with self._lock:
            existing = self._records.get(record.audit_id)
            if existing is not None:
                return existing
            self._records[record.audit_id] = record
            return record


def new_record(audit_id: str, payload: dict, verdicts: list) -> AuditRecord:
    return AuditRecord(
        audit_id=audit_id,
        digest=fingerprint(payload),
        rules=payload["rules"],
        verdicts=verdicts,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )


@dataclass(frozen=True)
class ReviewRecord:
    """Immutable publish-order review over a frozen source audit.

    The source rules and the constraints are frozen into the record, so
    the conclusion stays tied to exactly the inputs it was computed from.
    """

    review_id: str
    digest: str
    audit_id: str
    constraints: list
    rules: list
    result: dict
    created_at: str

    def response(self) -> dict:
        return {
            "review_id": self.review_id,
            "audit_id": self.audit_id,
            "created_at": self.created_at,
            "constraints": self.constraints,
            "rules": self.rules,
            "status": self.result["status"],
            "states_explored": self.result["states_explored"],
            "counterexample": self.result["counterexample"],
        }


class ReviewStore:
    """Thread-safe review_id -> ReviewRecord map.  Records never change."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, ReviewRecord] = {}

    def get(self, review_id: str) -> ReviewRecord | None:
        with self._lock:
            return self._records.get(review_id)

    def put_if_absent(self, record: ReviewRecord) -> ReviewRecord:
        """Store the record; return whatever record owns the slot."""
        with self._lock:
            existing = self._records.get(record.review_id)
            if existing is not None:
                return existing
            self._records[record.review_id] = record
            return record


def new_review_record(
    review_id: str, payload: dict, rules: list, result: dict
) -> ReviewRecord:
    return ReviewRecord(
        review_id=review_id,
        digest=fingerprint(payload),
        audit_id=payload["audit_id"],
        constraints=payload["constraints"],
        rules=rules,
        result=result,
        created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
