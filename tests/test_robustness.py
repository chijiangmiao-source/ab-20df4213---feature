"""Tests for release-order robustness analysis over exact 5-D regions."""

from __future__ import annotations

import itertools
import random

from app.region import intersects, subtract_region
from app.robustness import (
    MAX_CONSTRAINTS,
    box_of_dict,
    evaluate_robustness,
    normalize_constraints,
    validate_ordering,
)


def rule(
    rid,
    protocol="tcp",
    src="10.0.0.0/24",
    dst="192.168.0.0/24",
    sp=(0, 65535),
    dp=(0, 65535),
):
    return {
        "id": rid,
        "protocol": protocol,
        "src_cidr": src,
        "dst_cidr": dst,
        "src_port": {"start": sp[0], "end": sp[1]},
        "dst_port": {"start": dp[0], "end": dp[1]},
    }


class TestValidation:
    def test_unknown_rule_rejected(self):
        errors = validate_ordering(["r1", "r2"], [("r1", "rx")])
        assert errors and errors[0]["type"] == "unknown_rule"

    def test_self_constraint_rejected(self):
        errors = validate_ordering(["r1"], [("r1", "r1")])
        assert errors and errors[0]["type"] == "self_constraint"

    def test_duplicate_constraint_rejected(self):
        errors = validate_ordering(["r1", "r2"], [("r1", "r2"), ("r1", "r2")])
        assert len(errors) == 1
        assert errors[0]["type"] == "duplicate_constraint"

    def test_cycle_rejected(self):
        errors = validate_ordering(["a", "b", "c"], [("a", "b"), ("b", "c"), ("c", "a")])
        assert errors and errors[0]["type"] == "ordering_cycle"
        assert "a" in errors[0]["msg"]

    def test_self_consistent_dag_accepted(self):
        assert validate_ordering(["a", "b", "c"], [("a", "b"), ("b", "c")]) == []

    def test_normalize_deduplicates_and_sorts(self):
        assert normalize_constraints([("b", "c"), ("a", "b"), ("b", "c")]) == [
            ("a", "b"),
            ("b", "c"),
        ]

    def test_constant_cap(self):
        assert MAX_CONSTRAINTS == 6


class TestRobust:
    def test_single_rule_is_robust(self):
        result = evaluate_robustness([rule("r1")], [])
        assert result["robust"] is True
        assert result["counterexample"] is None
        # Prefix states include the empty prefix and the full order.
        assert result["states_explored"] == 2

    def test_disjoint_rules_robust_in_any_order(self):
        rules = [
            rule("r1", dp=(80, 85)),
            rule("r2", dp=(90, 95)),
        ]
        assert evaluate_robustness(rules, [])["robust"] is True

    def test_protocol_disjoint_robust(self):
        rules = [rule("r1", protocol="tcp"), rule("r2", protocol="udp")]
        assert evaluate_robustness(rules, [])["robust"] is True

    def test_constraint_forcing_disjoint_rule_first_stays_safe(self):
        # TCP coverer plus an independent UDP rule: forcing the UDP rule
        # first leaves exactly one legal order, in which the TCP rule
        # still owns its whole protocol slice.
        rules = [
            rule("coverer", dp=(0, 100)),
            rule("other", protocol="udp"),
        ]
        result = evaluate_robustness(rules, [("other", "coverer")])
        assert result["robust"] is True

    def test_constraint_eliminates_counterexample(self):
        # Without constraints r2 (narrower) could be released first and
        # then r1 (broader) covers r2... actually the broader shadowed is
        # the later one: build r1 broad, r2 inside r1.  Unconstrained:
        # order [r2, r1] shadows r1? No — broad after narrow is not fully
        # covered.  The only bad order puts the broad rule first.
        rules = [
            rule("broad", dp=(0, 100)),
            rule("narrow", dp=(20, 30)),
        ]
        assert evaluate_robustness(rules, [])["robust"] is False
        # Forcing the narrow rule first makes both orders safe:
        # [narrow, broad] leaves broad with ports outside 20..30.
        saved = evaluate_robustness(rules, [("narrow", "broad")])
        assert saved["robust"] is True


class TestCounterexample:
    def test_containment_bad_order_is_stable(self):
        rules = [
            rule("broad", dp=(0, 100)),
            rule("narrow", dp=(20, 30)),
        ]
        result = evaluate_robustness(rules, [])
        assert result["robust"] is False
        ce = result["counterexample"]
        # Smallest rule id first: "broad" < "narrow", and that order is
        # exactly the shadowing one.
        assert ce["order"] == ["broad", "narrow"]
        assert ce["shadowed_rule"] == "narrow"
        assert ce["position"] == 1
        assert ce["covered_by"] == ["broad"]

    def test_counterexample_is_a_full_order_respecting_constraints(self):
        rules = [
            rule("a-broad", dp=(0, 100)),
            rule("b-narrow", dp=(20, 30)),
            rule("c-free", dp=(200, 300)),
        ]
        result = evaluate_robustness(rules, [("c-free", "b-narrow")])
        assert result["robust"] is False
        ce = result["counterexample"]
        assert len(ce["order"]) == 3
        assert set(ce["order"]) == {"a-broad", "b-narrow", "c-free"}
        assert ce["order"].index("c-free") < ce["order"].index("b-narrow")
        assert ce["shadowed_rule"] == "b-narrow"
        assert ce["covered_by"] == ["a-broad"]

    def test_multi_rule_cover_requires_all_coverers_earlier(self):
        rules = [
            rule("piece-a", dp=(0, 49)),
            rule("piece-b", dp=(50, 100)),
            rule("wide", dp=(0, 100)),
        ]
        result = evaluate_robustness(rules, [])
        assert result["robust"] is False
        ce = result["counterexample"]
        assert ce["shadowed_rule"] == "wide"
        assert set(ce["covered_by"]) == {"piece-a", "piece-b"}
        assert ce["order"][:2] == ["piece-a", "piece-b"]
        assert ce["position"] == 2

    def test_forcing_one_piece_first_does_not_save_full_rule(self):
        rules = [
            rule("piece-a", dp=(0, 49)),
            rule("piece-b", dp=(50, 100)),
            rule("wide", dp=(0, 100)),
        ]
        # piece-a first is not enough; piece-b can still follow before
        # wide: [piece-a, piece-b, wide] remains a legal and bad order.
        result = evaluate_robustness(rules, [("piece-a", "wide")])
        assert result["robust"] is False
        assert result["counterexample"]["shadowed_rule"] == "wide"

    def test_constraint_breaking_cover_saves_order(self):
        rules = [
            rule("broad", dp=(0, 100)),
            rule("narrow", dp=(20, 30)),
            rule("free", dp=(200, 300)),
        ]
        # Unconstrained the id-stable bad order is [broad, free, narrow]
        # (narrow fully covered).  Forcing narrow before broad makes
        # every legal order safe: broad then keeps ports outside 20..30.
        assert evaluate_robustness(rules, [])["robust"] is False
        result = evaluate_robustness(rules, [("narrow", "broad")])
        assert result["robust"] is True


class TestExactness:
    def test_partial_overlap_never_counts_as_cover(self):
        rules = [
            rule("r1", src="10.0.0.0/25"),
            rule("r2", src="10.0.0.0/24"),
        ]
        # Either order: the /24 rule keeps the upper half (or the whole
        # slice minus...); the /25 rule is contained in the /24, so the
        # bad order [r1(/25 second?)]: smallest-id order puts r1 first
        # and r2 second — r2 only partially covered -> safe. The reverse
        # order r2 first fully shadows r1 -> bad.
        result = evaluate_robustness(rules, [])
        assert result["robust"] is False
        ce = result["counterexample"]
        assert ce["shadowed_rule"] == "r1"
        assert ce["order"] == ["r2", "r1"]

    def test_all_prefix_states_enumerated_for_chain_dag(self):
        rules = [rule(f"r{i}", dp=(100 * i, 100 * i + 50)) for i in range(4)]
        # Disjoint port ranges: robust, and the chain constraints allow
        # exactly one order, hence n + 1 prefix states (empty + full).
        result = evaluate_robustness(rules, [("r0", "r1"), ("r1", "r2"), ("r2", "r3")])
        assert result["robust"] is True
        assert result["states_explored"] == 5

    def test_states_union_iso_identical_boxes(self):
        # Two identical rules: one of the two is necessarily shadowed in
        # every order -> not robust, and the counterexample lists the
        # later id with the earlier as coverer.
        rules = [rule("x1"), rule("x2")]
        result = evaluate_robustness(rules, [])
        assert result["robust"] is False
        ce = result["counterexample"]
        assert ce["order"] == ["x1", "x2"]
        assert ce["covered_by"] == ["x1"]


def oracle_evaluate(rules, constraints):
    """Brute-force oracle: iterate every constraint-compatible permutation.

    Returns the rule-id tuple of the lexicographically first bad order,
    or None when every order is safe.  Coverage uses the same exact box
    algebra but with a plainly independent loop.
    """
    ids = [r["id"] for r in rules]
    boxes = {r["id"]: box_of_dict(r) for r in rules}
    must_before: dict[str, set[str]] = {rid: set() for rid in ids}
    for before, after in constraints:
        must_before[after].add(before)

    for perm in itertools.permutations(sorted(ids)):
        if any(
            any(pred not in set(perm[: idx]) for pred in must_before[rid])
            for idx, rid in enumerate(perm)
        ):
            continue
        region_boxes: list[tuple] = []
        for rid in perm:
            box = boxes[rid]
            remainder = [box]
            for earlier in region_boxes:
                if remainder:
                    remainder = subtract_region(remainder, earlier)
            if not remainder:
                return perm
            region_boxes.append(box)
    return None


class TestAgainstBruteForceOracle:
    """Enumerate tiny rule/constraint spaces exhaustively against an oracle."""

    def test_small_port_grid_matches_oracle(self):
        # Six tiny boxes over a small dst-port grid, including rules with
        # disjoint / partial / containment relations.
        templates = [
            ("a", (0, 2)),
            ("b", (1, 4)),
            ("c", (3, 3)),
            ("d", (5, 7)),
            ("e", (0, 7)),
            ("f", (6, 9)),
        ]
        rules = [rule(rid, dp=dp) for rid, dp in templates]
        constraint_sets = [
            [],
            [("a", "e")],
            [("e", "a"), ("d", "e")],
            [("a", "b"), ("b", "c"), ("c", "d")],
            [("e", "f"), ("f", "a"), ("a", "b")],
            [("d", "e"), ("c", "e"), ("b", "e"), ("a", "e")],
        ]
        for cons in constraint_sets:
            result = evaluate_robustness(rules, cons)
            expected_order = oracle_evaluate(rules, cons)
            assert result["robust"] is (expected_order is None), cons
            if expected_order is not None:
                assert tuple(result["counterexample"]["order"]) == expected_order, cons

    def test_random_boxes_match_oracle(self):
        rng = random.Random(20261002)
        for _ in range(120):
            n = rng.randint(1, 6)
            rules = [
                rule(
                    f"r{idx}",
                    protocol=rng.choice(["tcp", "udp", "both"]),
                    src=rng.choice(["10.0.0.0/24", "10.0.0.0/25", "10.0.0.128/25"]),
                    dst=rng.choice(["192.168.0.0/24", "192.168.0.0/25"]),
                    dp=tuple(sorted((rng.randint(0, 6), rng.randint(0, 6)))),
                )
                for idx in range(n)
            ]
            possible = [(a, b) for a in range(n) for b in range(n) if a != b]
            rng.shuffle(possible)
            cons = [(f"r{a}", f"r{b}") for a, b in possible[: rng.randint(0, 4)]]
            # Skip cyclic constraint sets (validation would reject them).
            if validate_ordering([r["id"] for r in rules], cons):
                continue
            result = evaluate_robustness(rules, cons)
            expected_order = oracle_evaluate(rules, cons)
            assert result["robust"] is (expected_order is None), (rules, cons)
            if expected_order is not None:
                assert tuple(result["counterexample"]["order"]) == expected_order, (
                    rules,
                    cons,
                )

    def test_covered_by_lists_earlier_intersecting_rules(self):
        rules = [rule("a", dp=(0, 2)), rule("b", dp=(1, 4)), rule("c", dp=(0, 4))]
        result = evaluate_robustness(rules, [])
        ce = result["counterexample"]
        assert ce is not None
        # The covered_by list equals exactly the earlier rules whose
        # boxes intersect the shadowed rule, in prefix order.
        shadowed_box = box_of_dict(
            next(r for r in rules if r["id"] == ce["shadowed_rule"])
        )
        earlier_boxes = {
            rid: box_of_dict(next(r for r in rules if r["id"] == rid))
            for rid in ce["order"][: ce["position"]]
        }
        assert ce["covered_by"] == [
            rid for rid, box in earlier_boxes.items() if intersects(shadowed_box, box)
        ]
