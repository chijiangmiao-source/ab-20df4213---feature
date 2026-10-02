"""One-shot verification gate.

Runs, in order:
  1. build check   — byte-compile every shipped Python module
  2. code tests    — the pytest suite (region algebra, engine, robustness,
                     API lifecycle and rejection paths)
  3. HTTP smoke    — against the live service: one partially shadowed rule,
                     one fully shadowed rule, and an illegal retransmission
                     (same audit id, different payload); plus the review
                     API: robust conclusion, counterexample order, cycle
                     rejection and source audit regression

Exits 0 only if every step passes; the Compose ``verify`` service surfaces
this as its container exit code.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_URL = os.environ.get("APP_URL", "http://127.0.0.1:8080").rstrip("/")


def log(msg: str) -> None:
    print(msg, flush=True)


def sh(cmd: list[str]) -> bool:
    log(f"\n$ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=ROOT).returncode == 0


def build_check() -> bool:
    return sh([sys.executable, "-m", "compileall", "-q", "app", "verify", "tests"])


def code_tests() -> bool:
    return sh([sys.executable, "-m", "pytest", "-q", "tests"])


def http(method: str, path: str, body=None):
    """JSON request; returns (status, parsed_body_or_text)."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        APP_URL + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode()
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, raw
    try:
        return resp.status, json.loads(raw)
    except json.JSONDecodeError:
        return resp.status, raw


def wait_ready(timeout: float = 90.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status, body = http("GET", "/healthz")
            if status == 200 and isinstance(body, dict) and body.get("status") == "ok":
                return True
        except Exception:
            pass
        time.sleep(1.0)
    return False


def smoke() -> None:
    assert wait_ready(), f"服务在 {APP_URL} 上未通过健康检查"

    audit_id = f"smoke-{int(time.time())}"
    rules = [
        # r1: baseline rule.
        {"id": "r1", "protocol": "tcp",
         "src_cidr": "10.0.0.0/24", "dst_cidr": "192.168.0.0/24",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 80, "end": 85}},
        # r2: partially shadowed by r1 — only dst ports 86..90 remain.
        {"id": "r2", "protocol": "tcp",
         "src_cidr": "10.0.0.128/25", "dst_cidr": "192.168.0.0/25",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 80, "end": 90}},
        # r3: fully contained in r1 — never matches any packet.
        {"id": "r3", "protocol": "tcp",
         "src_cidr": "10.0.0.0/25", "dst_cidr": "192.168.0.0/25",
         "src_port": {"start": 0, "end": 65535}, "dst_port": {"start": 82, "end": 84}},
    ]

    status, body = http("POST", "/api/audits", {"audit_id": audit_id, "rules": rules})
    assert status == 201, f"创建审计失败: HTTP {status} {body}"
    verdicts = {v["rule_id"]: v for v in body["verdicts"]}

    v1 = verdicts["r1"]
    assert v1["status"] == "hit" and v1["witness"] == {
        "protocol": "tcp", "src_ip": "10.0.0.0", "dst_ip": "192.168.0.0",
        "src_port": 0, "dst_port": 80,
    }, f"r1 结论错误: {v1}"

    v2 = verdicts["r2"]
    assert v2["status"] == "hit" and v2["witness"] == {
        "protocol": "tcp", "src_ip": "10.0.0.128", "dst_ip": "192.168.0.0",
        "src_port": 0, "dst_port": 86,
    }, f"部分遮蔽的 r2 结论或最小见证错误: {v2}"

    v3 = verdicts["r3"]
    assert v3["status"] == "shadowed" and v3["covered_by"] == ["r1"], (
        f"完全遮蔽的 r3 结论或覆盖集合错误: {v3}"
    )
    log("  ✓ 部分遮蔽 / 完全遮蔽裁决与最小见证正确")

    # Frozen conclusions are retrievable by audit id.
    status, again = http("GET", f"/api/audits/{audit_id}")
    assert status == 200 and again["verdicts"] == body["verdicts"], (
        "按审计标识复查到的结论与提交时不一致"
    )

    # Idempotent replay of the identical payload.
    status, replay = http("POST", "/api/audits", {"audit_id": audit_id, "rules": rules})
    assert status == 200 and replay["verdicts"] == body["verdicts"], (
        f"相同载荷的幂等重放失败: HTTP {status}"
    )

    # Illegal retransmission: same audit id, different payload -> 409,
    # and the stored conclusions must stay untouched.
    tampered = json.loads(json.dumps({"audit_id": audit_id, "rules": rules}))
    tampered["rules"][1]["dst_port"]["end"] = 91
    status, conflict = http("POST", "/api/audits", tampered)
    assert status == 409, f"非法重传未被拒绝: HTTP {status} {conflict}"
    status, after = http("GET", f"/api/audits/{audit_id}")
    assert status == 200 and after["verdicts"] == body["verdicts"], (
        "非法重传改写了既有冻结结论"
    )
    log("  ✓ 非法重传被拒绝（409）且既有结论未被改写")

    # Invalid CIDR must be rejected and must not create a record.
    bad_id = audit_id + "-bad"
    bad = {"audit_id": bad_id, "rules": [dict(rules[0], src_cidr="10.0.0.0/33")]}
    status, _ = http("POST", "/api/audits", bad)
    assert status == 422, f"非法 CIDR 未被拒绝: HTTP {status}"
    status, _ = http("GET", f"/api/audits/{bad_id}")
    assert status == 404, "被拒绝的请求不应留下审计记录"
    log("  ✓ 非法 CIDR 被拒绝（422）且未留下记录")

    # The page is served.
    status, page = http("GET", "/")
    assert status == 200 and "规则隔离审计" in page, "页面不可用"
    log("  ✓ 页面与健康端点可用")

    review_smoke(audit_id, rules)


def review_smoke(source_audit_id, rules):
    """HTTP smoke for the release-order robustness review API."""
    import time as _time

    rid_base = f"review-{int(_time.time())}"

    # 1) Robust conclusion: force the narrow rules r2 and r3 before the
    # broad rule r1; every compatible order keeps each rule hittable.
    robust_id = rid_base + "-ok"
    body = {
        "review_id": robust_id,
        "source_audit_id": source_audit_id,
        "constraints": [
            {"before": "r2", "after": "r1"},
            {"before": "r3", "after": "r1"},
        ],
    }
    status, resp = http("POST", "/api/reviews", body)
    assert status == 201, f"稳健复核创建失败: HTTP {status} {resp}"
    assert resp["robust"] is True and resp["counterexample"] is None, (
        f"稳健结论错误: {resp}"
    )
    assert resp["source"]["rules"] == rules, "复核快照未冻结来源规则"
    log("  ✓ 稳健结论正确且来源规则已随复核冻结")

    # Reopening returns the identical frozen review.
    status, reopened = http("GET", f"/api/reviews/{robust_id}")
    assert status == 200 and reopened == resp, "重开复核得到的结论不一致"
    # Idempotent replay.
    status, replay = http("POST", "/api/reviews", body)
    assert status == 200 and replay == resp, f"复核幂等重放失败: HTTP {status}"

    # 2) Counterexample order with no constraints.
    bad_id = rid_base + "-bad"
    status, resp = http("POST", "/api/reviews", {
        "review_id": bad_id, "source_audit_id": source_audit_id, "constraints": [],
    })
    assert status == 201, f"反例复核创建失败: HTTP {status} {resp}"
    assert resp["robust"] is False, "无约束时应存在遮蔽顺序"
    ce = resp["counterexample"]
    assert ce is not None, "不稳健时必须给出完整反例顺序"
    assert len(ce["order"]) == len(rules) == 3
    assert set(ce["order"]) == {"r1", "r2", "r3"}, f"反例不是完整顺序: {ce['order']}"
    assert ce["order"][ce["position"]] == ce["shadowed_rule"], "位置与被遮蔽规则不一致"
    assert ce["shadowed_rule"] not in ce["covered_by"], "覆盖者不应包含被遮蔽规则自身"
    assert all(ce["order"].index(c) < ce["position"] for c in ce["covered_by"]), (
        "覆盖者必须位于被遮蔽规则之前"
    )
    log(f"  ✓ 反例顺序正确：{' → '.join(ce['order'])}，{ce['shadowed_rule']} 被遮蔽")

    # 3) Ordering cycle is rejected (422) and leaves no review record;
    # also cover unknown-rule / self / duplicate rejections.
    for name, constraints in [
        ("cycle", [{"before": "r1", "after": "r2"},
                   {"before": "r2", "after": "r3"},
                   {"before": "r3", "after": "r1"}]),
        ("unknown", [{"before": "r1", "after": "rx"}]),
        ("self", [{"before": "r2", "after": "r2"}]),
        ("duplicate", [{"before": "r1", "after": "r2"},
                       {"before": "r1", "after": "r2"}]),
    ]:
        rej_id = rid_base + "-" + name
        status, resp = http("POST", "/api/reviews", {
            "review_id": rej_id,
            "source_audit_id": source_audit_id,
            "constraints": constraints,
        })
        assert status == 422, f"{name} 约束未被拒绝: HTTP {status} {resp}"
        status, _ = http("GET", f"/api/reviews/{rej_id}")
        assert status == 404, f"{name} 拒绝不应留下复核记录"
    log("  ✓ 先后环 / 未知规则 / 自约束 / 重复约束均拒绝（422）且不留痕")

    # Unknown source audit is rejected as well.
    status, resp = http("POST", "/api/reviews", {
        "review_id": rid_base + "-nosrc",
        "source_audit_id": "no-such-audit",
        "constraints": [],
    })
    assert status == 422, f"来源不存在未被拒绝: HTTP {status}"
    log("  ✓ 来源审计不存在被拒绝（422）")

    # 4) Same review id with changed constraints -> 409, original kept.
    status, conflict = http("POST", "/api/reviews", {
        "review_id": robust_id,
        "source_audit_id": source_audit_id,
        "constraints": [{"before": "r3", "after": "r1"}],
    })
    assert status == 409, f"改换约束未被拒绝: HTTP {status} {conflict}"
    status, kept = http("GET", f"/api/reviews/{robust_id}")
    assert status == 200 and kept["constraints"] == [["r2", "r1"], ["r3", "r1"]], (
        "冲突请求改写了既有冻结复核"
    )
    log("  ✓ 同标识改换约束被拒绝（409）且既有复核未被改写")

    # Source audit regression: original per-rule verdicts remain
    # available by audit id and inside the review snapshot.
    status, frozen_audit = http("GET", f"/api/audits/{source_audit_id}")
    assert status == 200, "来源审计裁决仍须可按标识查看"
    assert frozen_audit["verdicts"] == reopened["source"]["verdicts"], (
        "复核快照中的逐规则裁决与来源审计不一致"
    )
    log("  ✓ 来源审计逐规则裁决仍可按标识查看（来源回归）")


def main() -> int:
    results: list[tuple[str, bool]] = []
    results.append(("构建检查 (compileall)", build_check()))
    results.append(("代码测试 (pytest)", code_tests()))
    try:
        smoke()
        results.append(("HTTP 冒烟", True))
    except Exception as exc:  # noqa: BLE001 - report any smoke failure
        log(f"  ✗ HTTP 冒烟失败: {exc}")
        results.append(("HTTP 冒烟", False))

    log("\n================ 验证结果 ================")
    for name, ok in results:
        log(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    ok = all(ok for _, ok in results)
    log(f"  总体: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
