"""In-memory store of frozen audit conclusions and robustness reviews."""

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


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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


@dataclass(frozen=True)
class ReviewRecord:
    """Immutable per-review robustness conclusion.

    Freezes the source audit snapshot (rules and per-rule verdicts) as
    well as the submitted constraints, so reopening a review later keeps
    showing the exact source material the conclusion was derived from.
    """

    review_id: str
    digest: str
    source_audit_id: str
    source: dict
    constraints: list
    robust: bool
    counterexample: dict | None
    states_explored: int
    created_at: str

    def response(self) -> dict:
        return {
            "review_id": self.review_id,
            "source_audit_id": self.source_audit_id,
            "created_at": self.created_at,
            "constraints": self.constraints,
            "robust": self.robust,
            "counterexample": self.counterexample,
            "states_explored": self.states_explored,
            "source": self.source,
        }


class AuditStore:
    """Thread-safe immutable maps.  Records never change once stored."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, AuditRecord] = {}
        self._reviews: dict[str, ReviewRecord] = {}

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

    def get_review(self, review_id: str) -> ReviewRecord | None:
        with self._lock:
            return self._reviews.get(review_id)

    def put_review_if_absent(self, record: ReviewRecord) -> ReviewRecord:
        """Store the review; return whatever record owns the slot."""
        with self._lock:
            existing = self._reviews.get(record.review_id)
            if existing is not None:
                return existing
            self._reviews[record.review_id] = record
            return record


def new_record(audit_id: str, payload: dict, verdicts: list) -> AuditRecord:
    return AuditRecord(
        audit_id=audit_id,
        digest=fingerprint(payload),
        rules=payload["rules"],
        verdicts=verdicts,
        created_at=_now(),
    )


def new_review_record(
    review_id: str,
    digest: str,
    source: AuditRecord,
    constraints: list,
    result: dict,
) -> ReviewRecord:
    return ReviewRecord(
        review_id=review_id,
        digest=digest,
        source_audit_id=source.audit_id,
        source=source.response(),
        constraints=constraints,
        robust=result["robust"],
        counterexample=result["counterexample"],
        states_explored=result["states_explored"],
        created_at=_now(),
    )
