"""Tests for the publish-order robustness solver.

The solver enumerates constraint-allowed priority prefix states over
exact 5-D regions; these tests check robust conclusions, counterexample
validity (order legality, coverage basis) and determinism.
"""

from __future__ import annotations

from app.region import rule_box, subtract_region
from app.review import solve_review
from app.schemas import Constraint, PortRange, Rule


def make_rule(
    rid,
    protocol="tcp",
    src="10.0.0.0/24",
    dst="192.168.0.0/24",
    sp=(0, 65535),
    dp=(0, 65535),
):
    return Rule(
        id=rid,
        protocol=protocol,
        src_cidr=src,
        dst_cidr=dst,
        src_port=PortRange(start=sp[0], end=sp[1]),
        dst_port=PortRange(start=dp[0], end=dp[1]),
    )


def cons(before, after):
    return Constraint(before=before, after=after)


def box_of(rule):
    return rule_box(
        rule.protocol,
        rule.src_cidr,
        rule.dst_cidr,
        (rule.src_port.start, rule.src_port.end),
        (rule.dst_port.start, rule.dst_port.end),
    )


def assert_valid_counterexample(rules, constraints, result):
    """The counterexample order must be a complete, constraint-legal
    publish order whose covered_by basis provably covers the shadowed
    rule (checked with the exact region algebra)."""
    assert result["status"] == "not_robust"
    ce = result["counterexample"]
    order, shadowed, covered_by = (
        ce["order"],
        ce["shadowed_rule"],
        ce["covered_by"],
    )
    assert sorted(order) == sorted(r.id for r in rules)
    pos = {rid: i for i, rid in enumerate(order)}
    for c in constraints:
        assert pos[c.before] < pos[c.after]
    assert pos[shadowed] > 0, "first rule can never be shadowed"
    by_id = {r.id: r for r in rules}
    shadowed_box = box_of(by_id[shadowed])
    # covered_by lists exactly the earlier intersecting rules, in order.
    earlier = order[: pos[shadowed]]
    expected = [
        rid
        for rid in earlier
        if subtract_region([shadowed_box], box_of(by_id[rid])) != [shadowed_box]
    ]
    assert covered_by == expected
    # The basis really covers the shadowed rule.
    remainder = [shadowed_box]
    for rid in covered_by:
        remainder = subtract_region(remainder, box_of(by_id[rid]))
    assert remainder == []


class TestRobust:
    def test_disjoint_rules_are_robust(self):
        rules = [
            make_rule("r1", src="10.1.0.0/16"),
            make_rule("r2", src="10.2.0.0/16"),
            make_rule("r3", protocol="udp"),
        ]
        result = solve_review(rules, [])
        assert result["status"] == "robust"
        assert result["counterexample"] is None

    def test_constraint_removes_the_only_bad_order(self):
        # r3 is fully contained in r1; forcing r3 earlier makes every
        # legal order safe.
        rules = [
            make_rule("r1", dp=(80, 85)),
            make_rule("r2", src="10.0.0.128/25", dst="192.168.0.0/25", dp=(80, 90)),
            make_rule("r3", src="10.0.0.0/25", dst="192.168.0.0/25", dp=(82, 84)),
        ]
        result = solve_review(rules, [cons("r3", "r1")])
        assert result["status"] == "robust"

    def test_many_disjoint_rules_robust_fast(self):
        # 18 disjoint rules: the exact maximal-prefix filter proves no
        # rule can ever be covered, so no prefix state needs exploring.
        rules = [make_rule(f"r{i}", src=f"10.{i}.0.0/16") for i in range(18)]
        result = solve_review(rules, [])
        assert result == {
            "status": "robust",
            "counterexample": None,
            "states_explored": 0,
        }


class TestCounterexample:
    def test_simple_containment(self):
        rules = [make_rule("big"), make_rule("small", src="10.0.0.0/25")]
        result = solve_review(rules, [])
        assert result["status"] == "not_robust"
        ce = result["counterexample"]
        assert ce["order"] == ["big", "small"]
        assert ce["shadowed_rule"] == "small"
        assert ce["covered_by"] == ["big"]

    def test_cover_by_union_of_two_rules(self):
        rules = [
            make_rule("p", dp=(0, 49)),
            make_rule("q", dp=(50, 100)),
            make_rule("s", dp=(0, 100)),
        ]
        result = solve_review(rules, [])
        assert result["counterexample"]["shadowed_rule"] == "s"
        assert result["counterexample"]["covered_by"] == ["p", "q"]
        assert_valid_counterexample(rules, [], result)

    def test_protocol_split_cover(self):
        # 'both' forced last: it is shadowed by the tcp+udp union of
        # the two earlier rules even though neither covers it alone.
        rules = [
            make_rule("t", protocol="tcp", src="10.5.0.0/16"),
            make_rule("u", protocol="udp", src="10.5.0.0/16"),
            make_rule("both", protocol="both", src="10.5.0.0/16"),
        ]
        constraints = [cons("t", "both"), cons("u", "both")]
        result = solve_review(rules, constraints)
        assert result["counterexample"]["shadowed_rule"] == "both"
        assert result["counterexample"]["covered_by"] == ["t", "u"]
        assert_valid_counterexample(rules, constraints, result)

    def test_total_container_shadows_first(self):
        # Unconstrained: the enumeration finds the id-stable
        # counterexample where 'both' (published first) shadows 't'.
        rules = [
            make_rule("t", protocol="tcp", src="10.5.0.0/16"),
            make_rule("u", protocol="udp", src="10.5.0.0/16"),
            make_rule("both", protocol="both", src="10.5.0.0/16"),
        ]
        result = solve_review(rules, [])
        assert result["counterexample"]["shadowed_rule"] == "t"
        assert result["counterexample"]["covered_by"] == ["both"]
        assert_valid_counterexample(rules, [], result)

    def test_counterexample_respects_constraints(self):
        # Two independent containment pairs; constraining one pair safe
        # leaves the other as the counterexample.
        rules = [
            make_rule("a1", src="10.0.0.0/24"),
            make_rule("a2", src="10.0.0.0/25"),
            make_rule("b1", src="172.16.0.0/24"),
            make_rule("b2", src="172.16.0.0/25"),
        ]
        constraints = [cons("a2", "a1")]
        result = solve_review(rules, constraints)
        assert result["counterexample"]["shadowed_rule"] == "b2"
        assert result["counterexample"]["covered_by"] == ["b1"]
        assert_valid_counterexample(rules, constraints, result)

    def test_shadowed_rule_with_predecessor(self):
        # y is contained in z but must follow x; the counterexample
        # order must place x before y.
        rules = [
            make_rule("x", src="10.9.0.0/16"),
            make_rule("y", src="10.0.0.0/25"),
            make_rule("z"),
        ]
        constraints = [cons("x", "y")]
        result = solve_review(rules, constraints)
        assert result["counterexample"]["shadowed_rule"] == "y"
        assert result["counterexample"]["covered_by"] == ["z"]
        assert_valid_counterexample(rules, constraints, result)

    def test_enumerates_prefix_states(self):
        rules = [make_rule("big"), make_rule("small", src="10.0.0.0/25")]
        result = solve_review(rules, [])
        assert result["states_explored"] >= 1

    def test_deterministic(self):
        rules = [
            make_rule("a1", src="10.0.0.0/24"),
            make_rule("a2", src="10.0.0.0/25"),
            make_rule("b1", src="172.16.0.0/24"),
            make_rule("b2", src="172.16.0.0/25"),
        ]
        first = solve_review(rules, [])
        second = solve_review(list(reversed(rules)), [])
        assert first == second, "result must be stable regardless of input order"

    def test_larger_shadowable_set(self):
        # 17 rules where the alphabetically-first rule is shadowable:
        # forces the enumeration through many prefix states.
        rules = [make_rule("aaa", src="10.0.1.0/25")]
        rules += [make_rule(f"r{i:02d}", src=f"10.0.{i}.0/24") for i in range(1, 17)]
        result = solve_review(rules, [])
        assert result["counterexample"]["shadowed_rule"] == "aaa"
        assert result["counterexample"]["covered_by"] == ["r01"]
        assert_valid_counterexample(rules, [], result)
