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


class TestBasics:
    def test_healthz(self):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_index_page_served(self):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "规则隔离审计" in resp.text


def fresh_review_id() -> str:
    return "rv-" + uuid.uuid4().hex[:12]


def make_audit_with_rules(audit_id):
    """Create the standard three-rule audit (r3 fully inside r1)."""
    resp = client.post("/api/audits", json=make_payload(audit_id))
    assert resp.status_code == 201
    return resp.json()


def review_payload(review_id, audit_id, constraints=None):
    return {
        "review_id": review_id,
        "audit_id": audit_id,
        "constraints": constraints if constraints is not None else [],
    }


class TestReviewLifecycle:
    def test_not_robust_counterexample(self):
        audit_id = fresh_audit_id()
        make_audit_with_rules(audit_id)
        review_id = fresh_review_id()
        resp = client.post(
            "/api/reviews", json=review_payload(review_id, audit_id)
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["review_id"] == review_id
        assert body["audit_id"] == audit_id
        assert body["status"] == "not_robust"
        ce = body["counterexample"]
        # r3 is fully contained in r1: the id-stable counterexample
        # publishes r1 first, then r3, then r2.
        assert ce["order"] == ["r1", "r3", "r2"]
        assert ce["shadowed_rule"] == "r3"
        assert ce["covered_by"] == ["r1"]
        # The frozen source rules are part of the review.
        assert [r["id"] for r in body["rules"]] == ["r1", "r2", "r3"]

        again = client.get(f"/api/reviews/{review_id}")
        assert again.status_code == 200
        assert again.json() == body

    def test_robust_under_constraint(self):
        audit_id = fresh_audit_id()
        make_audit_with_rules(audit_id)
        review_id = fresh_review_id()
        # Forcing r3 earlier than r1 removes the only shadowing order.
        resp = client.post(
            "/api/reviews",
            json=review_payload(
                review_id, audit_id, [{"before": "r3", "after": "r1"}]
            ),
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["status"] == "robust"
        assert body["counterexample"] is None
        assert body["constraints"] == [{"before": "r3", "after": "r1"}]

    def test_idempotent_replay(self):
        audit_id = fresh_audit_id()
        make_audit_with_rules(audit_id)
        payload = review_payload(fresh_review_id(), audit_id)
        first = client.post("/api/reviews", json=payload)
        replay = client.post("/api/reviews", json=payload)
        assert first.status_code == 201
        assert replay.status_code == 200
        assert replay.json() == first.json()

    def test_conflict_keeps_original(self):
        audit_id = fresh_audit_id()
        make_audit_with_rules(audit_id)
        review_id = fresh_review_id()
        original = review_payload(review_id, audit_id)
        assert client.post("/api/reviews", json=original).status_code == 201

        changed = review_payload(
            review_id, audit_id, [{"before": "r3", "after": "r1"}]
        )
        conflict = client.post("/api/reviews", json=changed)
        assert conflict.status_code == 409
        assert conflict.json()["detail"]["error"] == "review_id_conflict"

        frozen = client.get(f"/api/reviews/{review_id}")
        assert frozen.status_code == 200
        assert frozen.json()["constraints"] == []
        assert frozen.json()["status"] == "not_robust"

    def test_conflict_on_changed_source(self):
        audit_a, audit_b = fresh_audit_id(), fresh_audit_id()
        make_audit_with_rules(audit_a)
        make_audit_with_rules(audit_b)
        review_id = fresh_review_id()
        assert (
            client.post(
                "/api/reviews", json=review_payload(review_id, audit_a)
            ).status_code
            == 201
        )
        conflict = client.post(
            "/api/reviews", json=review_payload(review_id, audit_b)
        )
        assert conflict.status_code == 409
        assert client.get(f"/api/reviews/{review_id}").json()["audit_id"] == audit_a

    def test_unknown_review_returns_404(self):
        resp = client.get("/api/reviews/" + fresh_review_id())
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "review_not_found"

    def test_source_audit_still_readable_after_review(self):
        audit_id = fresh_audit_id()
        created = make_audit_with_rules(audit_id)
        review_id = fresh_review_id()
        assert (
            client.post(
                "/api/reviews", json=review_payload(review_id, audit_id)
            ).status_code
            == 201
        )
        frozen = client.get(f"/api/audits/{audit_id}")
        assert frozen.status_code == 200
        assert frozen.json() == created


class TestReviewValidation:
    def setup_method(self):
        self.audit_id = fresh_audit_id()
        make_audit_with_rules(self.audit_id)

    def post(self, review_id=None, **overrides):
        payload = review_payload(
            review_id or fresh_review_id(), self.audit_id
        )
        payload.update(overrides)
        return client.post("/api/reviews", json=payload)

    def test_missing_source_audit_rejected(self):
        resp = self.post(audit_id=fresh_audit_id())
        assert resp.status_code == 404
        assert resp.json()["detail"]["error"] == "audit_not_found"

    def test_unknown_rule_reference_rejected(self):
        resp = self.post(constraints=[{"before": "r1", "after": "nope"}])
        assert resp.status_code == 422
        assert resp.json()["detail"]["error"] == "unknown_rules"

    def test_same_rule_constraint_rejected(self):
        resp = self.post(constraints=[{"before": "r1", "after": "r1"}])
        assert resp.status_code == 422

    def test_duplicate_constraint_rejected(self):
        resp = self.post(
            constraints=[
                {"before": "r1", "after": "r2"},
                {"before": "r1", "after": "r2"},
            ]
        )
        assert resp.status_code == 422

    def test_cycle_rejected(self):
        resp = self.post(
            constraints=[
                {"before": "r1", "after": "r2"},
                {"before": "r2", "after": "r1"},
            ]
        )
        assert resp.status_code == 422

    def test_three_node_cycle_rejected(self):
        resp = self.post(
            constraints=[
                {"before": "r1", "after": "r2"},
                {"before": "r2", "after": "r3"},
                {"before": "r3", "after": "r1"},
            ]
        )
        assert resp.status_code == 422

    def test_cycle_with_downstream_chain_rejected(self):
        # The alphabetically-first rule sits downstream of the cycle;
        # the cycle message must still be extracted cleanly.
        resp = self.post(
            constraints=[
                {"before": "r2", "after": "r3"},
                {"before": "r3", "after": "r2"},
                {"before": "r2", "after": "r1"},
            ]
        )
        assert resp.status_code == 422

    def test_too_many_constraints_rejected(self):
        # Seven pairs exceed the 6-constraint limit regardless of content.
        many = [
            {"before": "r1", "after": "r2"},
            {"before": "r1", "after": "r3"},
            {"before": "r2", "after": "r3"},
            {"before": "r3", "after": "r2"},
            {"before": "r2", "after": "r1"},
            {"before": "r3", "after": "r1"},
            {"before": "r1", "after": "r2"},
        ]
        resp = self.post(constraints=many)
        assert resp.status_code == 422

    def test_rejection_leaves_no_record(self):
        review_id = fresh_review_id()
        resp = self.post(
            review_id=review_id,
            constraints=[{"before": "r1", "after": "r2"}, {"before": "r2", "after": "r1"}],
        )
        assert resp.status_code == 422
        assert client.get(f"/api/reviews/{review_id}").status_code == 404

    def test_missing_source_leaves_no_record(self):
        review_id = fresh_review_id()
        resp = self.post(review_id=review_id, audit_id=fresh_audit_id())
        assert resp.status_code == 404
        assert client.get(f"/api/reviews/{review_id}").status_code == 404
