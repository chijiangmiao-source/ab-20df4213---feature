"""Release-order robustness analysis for a frozen rule audit.

A safety engineer reopens a frozen audit (at most 18 rules) and pins at
most six "rule A must be released before rule B" constraints, then asks
whether **every** release order compatible with the constraints still
keeps, for every rule, a packet that rule matches first.

The solver enumerates the legal priority-prefix states.  A prefix state is
a downward-closed subset of the constraint DAG (a rule may only be placed
once every predecessor has been placed); every such state is a prefix of
some topological order and vice versa.  For each state the exact union of
the prefix rules is maintained as a list of disjoint boxes in the five
dimensions — protocol × src IPv4 × dst IPv4 × src port × dst port.  As
soon as a ready candidate box is fully covered by that union, a complete
counterexample order is constructed.  Ready candidates are taken in rule
identifier order, so the first counterexample found is the
identifier-lexicographically smallest bad order and is fully stable.

No CIDR-overlap heuristics, no port sampling and no random permutations:
coverage is decided purely by the exact box algebra in :mod:`app.region`.
"""

from __future__ import annotations

from .region import intersects, rule_box, subtract_region

MAX_CONSTRAINTS = 6


def box_of_dict(rule: dict) -> tuple:
    """Build the 5-D box of a frozen rule payload (model_dump form)."""
    return rule_box(
        rule["protocol"],
        rule["src_cidr"],
        rule["dst_cidr"],
        (rule["src_port"]["start"], rule["src_port"]["end"]),
        (rule["dst_port"]["start"], rule["dst_port"]["end"]),
    )


def validate_ordering(rule_ids: list[str], constraints: list[tuple[str, str]]) -> list[dict]:
    """Semantic checks for ordering constraints against the source rules.

    Returns a (possibly empty) list of validation error dicts shaped like
    pydantic errors: ``{"loc", "msg", "type"}``.  Rejected cases are:
    a constraint touching an unknown rule, a constraint with the same rule
    on both sides, a duplicated pair, and an ordering cycle.
    """
    known = set(rule_ids)
    errors: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for pos, (before, after) in enumerate(constraints):
        loc = ["body", "constraints", pos]
        if before not in known:
            errors.append(
                {
                    "loc": loc + ["before"],
                    "msg": f"约束引用了来源审计中不存在的规则标识: {before!r}",
                    "type": "unknown_rule",
                }
            )
        if after not in known:
            errors.append(
                {
                    "loc": loc + ["after"],
                    "msg": f"约束引用了来源审计中不存在的规则标识: {after!r}",
                    "type": "unknown_rule",
                }
            )
        if before == after:
            errors.append(
                {
                    "loc": loc + ["before"],
                    "msg": f"规则 {before!r} 不能约束为必须早于自身",
                    "type": "self_constraint",
                }
            )
        if (before, after) in seen:
            errors.append(
                {
                    "loc": loc,
                    "msg": f"重复的发布约束: {before!r} 必须早于 {after!r}",
                    "type": "duplicate_constraint",
                }
            )
        seen.add((before, after))

    # Cycle detection only makes sense when every endpoint is a known,
    # distinct rule; skip it if structural errors were already reported.
    if not errors:
        cycle = _find_cycle(rule_ids, constraints)
        if cycle is not None:
            errors.append(
                {
                    "loc": ["body", "constraints"],
                    "msg": "发布约束存在先后环: " + " → ".join(cycle),
                    "type": "ordering_cycle",
                }
            )
    return errors


def _find_cycle(rule_ids: list[str], constraints: list[tuple[str, str]]) -> list[str] | None:
    """Return one cycle as an id path closing back onto its first node."""
    adjacency: dict[str, list[str]] = {rid: [] for rid in rule_ids}
    for before, after in constraints:
        adjacency[before].append(after)
    for neighbours in adjacency.values():
        neighbours.sort()

    color: dict[str, int] = {rid: 0 for rid in rule_ids}  # 0 white, 1 gray, 2 black
    stack: list[str] = []

    def visit(node: str) -> list[str] | None:
        color[node] = 1
        stack.append(node)
        for nxt in adjacency[node]:
            if color[nxt] == 0:
                found = visit(nxt)
                if found is not None:
                    return found
            elif color[nxt] == 1:
                start = stack.index(nxt)
                return stack[start:] + [nxt]
        color[node] = 2
        stack.pop()
        return None

    for rid in sorted(rule_ids):
        if color[rid] == 0:
            found = visit(rid)
            if found is not None:
                return found
    return None


def normalize_constraints(constraints: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Freeze constraints as a set: deduplicated and pair-sorted."""
    return sorted(set(constraints))


def _contains(outer: tuple, inner: tuple) -> bool:
    """True iff every point of ``inner`` lies inside ``outer``."""
    return all(outer[d][0] <= inner[d][0] and inner[d][1] <= outer[d][1] for d in range(5))


def evaluate_robustness(rules: list[dict], constraints: list[tuple[str, str]]) -> dict:
    """Check every legal release order.

    ``rules`` are the frozen source rules in payload (dict) form and
    ``constraints`` are already validated, normalized ``(before, after)``
    pairs.  Returns::

        {"robust": True,  "counterexample": None, "states_explored": k}
        {"robust": False, "counterexample": {
             "order": [<full rule-id order>],
             "position": <0-based position of the shadowed rule>,
             "shadowed_rule": <id>,
             "covered_by": [<earlier intersecting rule ids in order>]},
         "states_explored": k}
    """
    ids = [rule["id"] for rule in rules]
    boxes = [box_of_dict(rule) for rule in rules]
    index = {rid: i for i, rid in enumerate(ids)}
    n = len(ids)
    full_mask = (1 << n) - 1

    # Bit masks for direct predecessors of every rule.
    predecessors = [0] * n
    for before, after in constraints:
        predecessors[index[after]] |= 1 << index[before]

    # Pairwise relation masks make the common cases O(1): a candidate is
    # provably uncovered when no earlier box intersects it, and provably
    # covered when one earlier box contains it.  Only the remaining
    # multi-box partial-cover case falls through to exact subtraction.
    intersects_mask = [0] * n
    contains_mask = [0] * n
    for i in range(n):
        for j in range(n):
            if i != j and intersects(boxes[i], boxes[j]):
                intersects_mask[i] |= 1 << j
                if _contains(boxes[j], boxes[i]):
                    contains_mask[i] |= 1 << j

    def ready_rules(mask: int) -> list[int]:
        """Rules not placed yet whose every predecessor is placed."""
        return sorted(
            (
                i
                for i in range(n)
                if not ((mask >> i) & 1) and (predecessors[i] & ~mask) == 0
            ),
            key=lambda i: ids[i],
        )

    def greedy_remainder(mask: int) -> list[str]:
        """Complete an order by always releasing the smallest ready id."""
        rest: list[str] = []
        while mask != full_mask:
            chosen = min(
                (
                    i
                    for i in range(n)
                    if not ((mask >> i) & 1) and (predecessors[i] & ~mask) == 0
                ),
                key=lambda i: ids[i],
            )
            rest.append(ids[chosen])
            mask |= 1 << chosen
        return rest

    def is_covered(candidate: int, mask: int, region: list[tuple[tuple, int]]) -> bool:
        """Exact containment of a candidate box in the prefix union.

        The union is a disjoint list of (box, origin_rule) fragments.
        Fragments whose origin rule does not intersect the candidate
        cannot intersect it either, so they are skipped before touching
        the box algebra.
        """
        if contains_mask[candidate] & mask:
            return True
        if not (intersects_mask[candidate] & mask):
            return False
        remainder = [boxes[candidate]]
        relevant = intersects_mask[candidate]
        for piece, origin in region:
            if not remainder:
                return True
            if not ((relevant >> origin) & 1):
                continue
            remainder = subtract_region(remainder, piece)
        return not remainder

    def add_box(
        region: list[tuple[tuple, int]], box: tuple, origin: int
    ) -> list[tuple[tuple, int]]:
        """Exact union: add ``box`` (introduced by rule ``origin``)."""
        fresh = [box]
        for piece, piece_origin in region:
            if not fresh:
                break
            # The piece lies inside its origin's box; origin boxes that
            # do not intersect the new box cannot contribute fragments.
            if not ((intersects_mask[origin] >> piece_origin) & 1):
                continue
            fresh = subtract_region(fresh, piece)
        return region + [(fragment, origin) for fragment in fresh]

    states_explored = 0
    visited: set[int] = {0}

    def dfs(mask: int, region: list[tuple[tuple, int]], path: list[int]) -> dict | None:
        nonlocal states_explored
        states_explored += 1
        for candidate in ready_rules(mask):
            if is_covered(candidate, mask, region):
                covered_by = [
                    ids[earlier]
                    for earlier in path
                    if (intersects_mask[candidate] >> earlier) & 1
                ]
                order = (
                    [ids[earlier] for earlier in path]
                    + [ids[candidate]]
                    + greedy_remainder(mask | (1 << candidate))
                )
                return {
                    "order": order,
                    "position": len(path),
                    "shadowed_rule": ids[candidate],
                    "covered_by": covered_by,
                }
            next_mask = mask | (1 << candidate)
            if next_mask not in visited:
                visited.add(next_mask)
                found = dfs(next_mask, add_box(region, boxes[candidate], candidate), path + [candidate])
                if found is not None:
                    return found
        return None

    counterexample = dfs(0, [], [])
    return {
        "robust": counterexample is None,
        "counterexample": counterexample,
        "states_explored": states_explored,
    }
