"""API tests: lifecycle, freezing, conflict and validation rejections."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def fresh_audit_id() -> str:
    return "t-" + uuid.uuid4().hex[:12]


def make_payload(audit_id, dp2_end=90):
    return {
        "audit_id": audit_id,
        "rules": [
            {
                "id": "r1",
                "protocol": "tcp",
                "src_cidr": "10.0.0.0/24",
                "dst_cidr": "192.168.0.0/24",
                "src_port": {"start": 0, "end": 65535},
                "dst_port": {"start": 80, "end": 85},
            },
            {
                "id": "r2",
                "protocol": "tcp",
                "src_cidr": "10.0.0.128/25",
                "dst_cidr": "192.168.0.0/25",
                "src_port": {"start": 0, "end": 65535},
                "dst_port": {"start": 80, "end": dp2_end},
            },
            {
                "id": "r3",
                "protocol": "tcp",
                "src_cidr": "10.0.0.0/25",
                "dst_cidr": "192.168.0.0/25",
                "src_port": {"start": 0, "end": 65535},
                "dst_port": {"start": 82, "end": 84},
            },
        ],
    }


class TestLifecycle:
    def test_create_then_get_frozen(self):
        audit_id = fresh_audit_id()
        resp = client.post("/api/audits", json=make_payload(audit_id))
        assert resp.status_code == 201
        body = resp.json()
        verdicts = {v["rule_id"]: v for v in body["verdicts"]}

        assert verdicts["r1"]["status"] == "hit"
        assert verdicts["r1"]["witness"] == {
            "protocol": "tcp",
            "src_ip": "10.0.0.0",
            "dst_ip": "192.168.0.0",
            "src_port": 0,
            "dst_port": 80,
        }
        # r2 is partially shadowed: only dst ports 86..90 remain.
        assert verdicts["r2"]["status"] == "hit"
        assert verdicts["r2"]["witness"]["dst_port"] == 86
        # r3 is fully shadowed by r1.
        assert verdicts["r3"]["status"] == "shadowed"
        assert verdicts["r3"]["covered_by"] == ["r1"]

        again = client.get(f"/api/audits/{audit_id}")
        assert again.status_code == 200
        assert again.json() == body

    def test_idempotent_replay_returns_same_conclusions(self):
        audit_id = fresh_audit_id()
        payload = make_payload(audit_id)
        first = client.post("/api/audits", json=payload)
        replay = client.post("/api/audits", json=payload)
        assert first.status_code == 201
        assert replay.status_code == 200
        assert replay.json() == first.json()

    def test_conflicting_payload_rejected_and_original_kept(self):
        audit_id = fresh_audit_id()
        original = make_payload(audit_id)
        assert client.post("/api/audits", json=original).status_code == 201

        tampered = make_payload(audit_id, dp2_end=91)
        conflict = client.post("/api/audits", json=tampered)
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["error"] == "audit_id_conflict"

        frozen = client.get(f"/api/audits/{audit_id}")
        assert frozen.status_code == 200
        assert frozen.json()["rules"] == original["rules"]

    def test_unknown_audit_returns_404(self):
        resp = client.get("/api/audits/" + fresh_audit_id())
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "audit_not_found"


class TestValidation:
    def post(self, **overrides):
        payload = make_payload(fresh_audit_id())
        payload.update(overrides)
        return client.post("/api/audits", json=payload)

    @pytest.mark.parametrize(
        "cidr",
        ["10.0.0.0/33", "10.0.0.1/24", "300.1.1.1/8", "fe80::/10", "not-a-cidr", ""],
    )
    def test_invalid_cidr_rejected(self, cidr):
        payload = make_payload(fresh_audit_id())
        payload["rules"][0]["src_cidr"] = cidr
        resp = client.post("/api/audits", json=payload)
        assert resp.status_code == 422

    @pytest.mark.parametrize(
        "rng",
        [
            {"start": 90, "end": 80},      # start > end
            {"start": -1, "end": 80},      # below range
            {"start": 0, "end": 65536},    # above range
        ],
    )
    def test_invalid_port_range_rejected(self, rng):
        payload = make_payload(fresh_audit_id())
        payload["rules"][0]["dst_port"] = rng
        resp = client.post("/api/audits", json=payload)
        assert resp.status_code == 422

    def test_duplicate_rule_ids_rejected(self):
        payload = make_payload(fresh_audit_id())
        payload["rules"][1]["id"] = "r1"
        resp = client.post("/api/audits", json=payload)
        assert resp.status_code == 422

    def test_too_many_rules_rejected(self):
        payload = make_payload(fresh_audit_id())
        template = payload["rules"][0]
        payload["rules"] = [
            dict(template, id=f"r{i}") for i in range(19)
        ]
        resp = client.post("/api/audits", json=payload)
        assert resp.status_code == 422

    def test_zero_rules_rejected(self):
        resp = self.post(rules=[])
        assert resp.status_code == 422

    @pytest.mark.parametrize("audit_id", ["", "has space", "bad/id", "-lead", "x" * 65])
    def test_invalid_audit_id_rejected(self, audit_id):
        resp = self.post(audit_id=audit_id)
        assert resp.status_code == 422

    def test_rejection_does_not_create_record(self):
        audit_id = fresh_audit_id()
        payload = make_payload(audit_id)
        payload["rules"][0]["src_cidr"] = "10.0.0.0/33"
        assert client.post("/api/audits", json=payload).status_code == 422
        assert client.get(f"/api/audits/{audit_id}").status_code == 404


class TestReviewBasics:
    def post_audit(self, audit_id=None):
        audit_id = audit_id or fresh_audit_id()
        resp = client.post("/api/audits", json=make_payload(audit_id))
        assert resp.status_code == 201
        return audit_id, resp.json()

    def review_payload(self, review_id, audit_id, constraints=None):
        return {
            "review_id": review_id,
            "source_audit_id": audit_id,
            "constraints": constraints or [],
        }

    def test_robust_conclusion_frozen_and_reopenable(self):
        audit_id, audit_body = self.post_audit()
        review_id = fresh_audit_id()
        # r2 forces a safe order relative to r3 (both live in the same
        # subnet): pinning r2 before r3 removes the only shadowing risk
        # among those rules... simply constrain r1 (the broad rule) last:
        constraints = [
            {"before": "r2", "after": "r1"},
            {"before": "r3", "after": "r1"},
        ]
        resp = client.post(
            "/api/reviews",
            json=self.review_payload(review_id, audit_id, constraints),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["review_id"] == review_id
        assert body["source_audit_id"] == audit_id
        assert body["constraints"] == [
            [c["before"], c["after"]]
            for c in sorted(constraints, key=lambda c: (c["before"], c["after"]))
        ]
        assert body["robust"] is True
        assert body["counterexample"] is None
        # The source audit snapshot is carried along for per-rule lookup.
        assert body["source"]["verdicts"] == audit_body["verdicts"]
        assert body["source"]["rules"] == audit_body["rules"]

        again = client.get(f"/api/reviews/{review_id}")
        assert again.status_code == 200
        assert again.json() == body

    def test_counterexample_order_reported(self):
        audit_id, _ = self.post_audit()
        review_id = fresh_audit_id()
        # No constraints: the source rules contain a containment pair
        # (r1 covers r3 in its slice), so some legal order shadows r3.
        resp = client.post(
            "/api/reviews", json=self.review_payload(review_id, audit_id)
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["robust"] is False
        ce = body["counterexample"]
        assert ce["shadowed_rule"] == "r3"
        assert "r1" in ce["covered_by"]
        assert len(ce["order"]) == 3
        assert set(ce["order"]) == {"r1", "r2", "r3"}
        assert ce["order"][ce["position"]] == "r3"

    def test_idempotent_review_replay(self):
        audit_id, _ = self.post_audit()
        review_id = fresh_audit_id()
        payload = self.review_payload(
            review_id, audit_id, [{"before": "r2", "after": "r1"}]
        )
        first = client.post("/api/reviews", json=payload)
        replay = client.post("/api/reviews", json=payload)
        assert first.status_code == 201
        assert replay.status_code == 200
        assert replay.json() == first.json()

    def test_constraint_set_replay_is_order_independent(self):
        audit_id, _ = self.post_audit()
        review_id = fresh_audit_id()
        first = self.review_payload(
            review_id,
            audit_id,
            [{"before": "r2", "after": "r1"}, {"before": "r3", "after": "r1"}],
        )
        assert client.post("/api/reviews", json=first).status_code == 201
        reordered = self.review_payload(
            review_id,
            audit_id,
            [{"before": "r3", "after": "r1"}, {"before": "r2", "after": "r1"}],
        )
        resp = client.post("/api/reviews", json=reordered)
        assert resp.status_code == 200
        assert resp.json()["constraints"] == [["r2", "r1"], ["r3", "r1"]]

    def test_changed_constraints_conflict_and_original_kept(self):
        audit_id, _ = self.post_audit()
        review_id = fresh_audit_id()
        payload = self.review_payload(
            review_id, audit_id, [{"before": "r2", "after": "r1"}]
        )
        assert client.post("/api/reviews", json=payload).status_code == 201

        changed = self.review_payload(
            review_id, audit_id, [{"before": "r3", "after": "r1"}]
        )
        resp = client.post("/api/reviews", json=changed)
        assert resp.status_code == 409
        assert resp.json()["detail"]["error"] == "review_id_conflict"

        frozen = client.get(f"/api/reviews/{review_id}")
        assert frozen.status_code == 200
        assert frozen.json()["constraints"] == [["r2", "r1"]]

    def test_changed_source_audit_conflict(self):
        audit_a, _ = self.post_audit()
        audit_b, _ = self.post_audit()
        review_id = fresh_audit_id()
        first = self.review_payload(review_id, audit_a)
        assert client.post("/api/reviews", json=first).status_code == 201
        swapped = self.review_payload(review_id, audit_b)
        resp = client.post("/api/reviews", json=swapped)
        assert resp.status_code == 409
        frozen = client.get(f"/api/reviews/{review_id}")
        assert frozen.json()["source_audit_id"] == audit_a

    def test_unknown_source_audit_rejected(self):
        review_id = fresh_audit_id()
        resp = client.post(
            "/api/reviews", json=self.review_payload(review_id, fresh_audit_id())
        )
        assert resp.status_code == 422
        assert resp.json()["errors"][0]["type"] == "source_audit_not_found"
        assert client.get(f"/api/reviews/{review_id}").status_code == 404

    @pytest.mark.parametrize(
        "constraints,etype",
        [
            ([{"before": "r1", "after": "rx"}], "unknown_rule"),
            ([{"before": "rx", "after": "r1"}], "unknown_rule"),
            ([{"before": "r1", "after": "r1"}], "self_constraint"),
            (
                [
                    {"before": "r1", "after": "r2"},
                    {"before": "r1", "after": "r2"},
                ],
                "duplicate_constraint",
            ),
            (
                [
                    {"before": "r1", "after": "r2"},
                    {"before": "r2", "after": "r3"},
                    {"before": "r3", "after": "r1"},
                ],
                "ordering_cycle",
            ),
        ],
    )
    def test_invalid_constraints_rejected(self, constraints, etype):
        audit_id, _ = self.post_audit()
        review_id = fresh_audit_id()
        resp = client.post(
            "/api/reviews",
            json=self.review_payload(review_id, audit_id, constraints),
        )
        assert resp.status_code == 422
        assert any(e["type"] == etype for e in resp.json()["errors"])
        assert client.get(f"/api/reviews/{review_id}").status_code == 404

    def test_more_than_six_constraints_rejected(self):
        audit_id, _ = self.post_audit()
        review_id = fresh_audit_id()
        payload = self.review_payload(
            review_id,
            audit_id,
            [{"before": "r1", "after": "r2"} for _ in range(7)],
        )
        resp = client.post("/api/reviews", json=payload)
        assert resp.status_code == 422
        assert client.get(f"/api/reviews/{review_id}").status_code == 404

    def test_unknown_review_returns_404(self):
        resp = client.get("/api/reviews/" + fresh_audit_id())
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "review_not_found"

    def test_source_audit_still_regressed_after_review(self):
        audit_id, audit_body = self.post_audit()
        review_id = fresh_audit_id()
        assert (
            client.post(
                "/api/reviews", json=self.review_payload(review_id, audit_id)
            ).status_code
            == 201
        )
        # The original per-rule verdicts remain available by audit id and
        # keep their exact frozen content.
        resp = client.get(f"/api/audits/{audit_id}")
        assert resp.status_code == 200
        assert resp.json() == audit_body
        # And they are reachable through the review snapshot as well.
        review = client.get(f"/api/reviews/{review_id}").json()
        assert review["source"]["audit_id"] == audit_id
        assert {v["rule_id"]: v["status"] for v in review["source"]["verdicts"]} == {
            v["rule_id"]: v["status"] for v in audit_body["verdicts"]
        }


class TestBasics:
    def test_healthz(self):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_index_page_served(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "规则隔离审计" in resp.text
