"""HTTP API for the flight data link rule isolation auditor."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse

from .engine import analyze
from .robustness import evaluate_robustness, normalize_constraints, validate_ordering
from .schemas import AuditRequest, ReviewRequest
from .store import AuditStore, fingerprint, new_record, new_review_record

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(title="飞行数据链路规则隔离审计", version="1.1.0")
store = AuditStore()


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc: RequestValidationError):
    errors = [
        {
            "loc": [str(part) for part in err.get("loc", [])],
            "msg": str(err.get("msg", "")),
            "type": str(err.get("type", "")),
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={"detail": "请求未通过校验", "errors": errors},
    )


def semantic_rejection(errors: list[dict]):
    """422 response for semantic validation (unknown source, cycles, ...)."""
    return JSONResponse(
        status_code=422,
        content={"detail": "请求未通过校验", "errors": errors},
    )


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/api/audits", status_code=201)
def create_audit(req: AuditRequest):
    """Freeze per-rule verdicts for a new audit identifier.

    Replaying the identical payload under the same audit id returns the
    existing frozen conclusions (200).  The same audit id with a different
    payload is rejected (409) and never rewrites the stored conclusions.
    """
    payload = req.model_dump(mode="json")
    digest = fingerprint(payload)

    existing = store.get(req.audit_id)
    if existing is not None:
        if existing.digest == digest:
            return JSONResponse(status_code=200, content=existing.response())
        raise HTTPException(status_code=409, detail=_conflict_detail(req.audit_id))

    record = new_record(req.audit_id, payload, analyze(req.rules))
    winner = store.put_if_absent(record)
    if winner.digest != digest:
        raise HTTPException(status_code=409, detail=_conflict_detail(req.audit_id))
    status_code = 201 if winner is record else 200
    return JSONResponse(status_code=status_code, content=winner.response())


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str):
    """Return the frozen conclusions for an audit identifier."""
    record = store.get(audit_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "audit_not_found",
                "message": f"审计标识 {audit_id!r} 不存在。",
                "audit_id": audit_id,
            },
        )
    return record.response()


@app.post("/api/reviews", status_code=201)
def create_review(req: ReviewRequest):
    """Freeze a release-order robustness review of a source audit.

    The source audit must exist, and every constraint must reference two
    distinct known rules; duplicate constraints and ordering cycles are
    rejected (422, no review is stored).  Replaying the identical payload
    under the same review id returns the frozen review (200); a changed
    source or constraint set under the same review id is rejected (409)
    without rewriting the existing review.
    """
    payload = req.model_dump(mode="json")

    source = store.get(req.source_audit_id)
    if source is None:
        return semantic_rejection(
            [
                {
                    "loc": ["body", "source_audit_id"],
                    "msg": (
                        f"来源审计标识 {req.source_audit_id!r} 不存在；"
                        "复核必须基于已冻结的来源审计。"
                    ),
                    "type": "source_audit_not_found",
                }
            ]
        )

    pairs = [(item.before, item.after) for item in req.constraints]
    errors = validate_ordering([rule["id"] for rule in source.rules], pairs)
    if errors:
        return semantic_rejection(errors)

    # Freeze the constraint *set*: pair order is irrelevant and replay
    # with reordered pairs is idempotent.
    normalized = normalize_constraints(pairs)
    constraints = [list(pair) for pair in normalized]
    canonical = dict(payload)
    canonical["constraints"] = constraints
    digest = fingerprint(canonical)

    existing = store.get_review(req.review_id)
    if existing is not None:
        if existing.digest == digest:
            return JSONResponse(status_code=200, content=existing.response())
        raise HTTPException(
            status_code=409, detail=_review_conflict_detail(req.review_id)
        )

    result = evaluate_robustness(source.rules, normalized)
    record = new_review_record(
        req.review_id, digest, source, constraints, result
    )
    winner = store.put_review_if_absent(record)
    if winner.digest != digest:
        raise HTTPException(
            status_code=409, detail=_review_conflict_detail(req.review_id)
        )
    status_code = 201 if winner is record else 200
    return JSONResponse(status_code=status_code, content=winner.response())


@app.get("/api/reviews/{review_id}")
def get_review(review_id: str):
    """Reopen a frozen robustness review by its identifier."""
    record = store.get_review(review_id)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "review_not_found",
                "message": f"复核标识 {review_id!r} 不存在。",
                "review_id": review_id,
            },
        )
    return record.response()


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


def _conflict_detail(audit_id: str) -> dict:
    return {
        "error": "audit_id_conflict",
        "message": (
            f"审计标识 {audit_id!r} 已存在且载荷不同；"
            "既有结论已冻结，拒绝改写。"
        ),
        "audit_id": audit_id,
    }


def _review_conflict_detail(review_id: str) -> dict:
    return {
        "error": "review_id_conflict",
        "message": (
            f"复核标识 {review_id!r} 已存在，但来源审计或发布约束不同；"
            "既有复核已冻结，拒绝改写。"
        ),
        "review_id": review_id,
    }
