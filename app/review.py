"""Publish-order robustness review.

Given the frozen rules of a source audit and a set of precedence
constraints ("rule A must be published earlier than rule B"), decide
whether *every* publish order satisfying the constraints keeps every
rule with a first-hit packet — i.e. no rule is fully shadowed by the
union of the rules published before it.

The solver enumerates the priority **prefix states** allowed by the
constraints (down-sets of the precedence poset) and maintains the union
of each prefix as an exact region over protocol × src IPv4 × dst IPv4 ×
src port × dst port, using the same box algebra as the audit engine.
As soon as a candidate rule is fully covered by the current prefix
region, a concrete counterexample is built: a complete publish order
(canonicalized by rule id) together with the earlier rules whose union
covers the shadowed rule.  No CIDR string overlap, no port sampling,
no random permutations anywhere.

Exactness note: a rule can be shadowed in *some* legal order iff the
union of every rule not forced to be published after it covers its
region (the maximal prefix that may legally precede it).  The solver
uses this only as an exact per-candidate filter; the counterexample
itself is always produced by the prefix-state enumeration above.
"""

from __future__ import annotations

from .region import intersects, rule_box, subtract_region


def _box_of(rule) -> tuple:
    return rule_box(
        rule.protocol,
        rule.src_cidr,
        rule.dst_cidr,
        (rule.src_port.start, rule.src_port.end),
        (rule.dst_port.start, rule.dst_port.end),
    )


def _covered(box: tuple, cover_boxes: list[tuple]) -> bool:
    """True iff ``box`` is fully covered by the union of ``cover_boxes``
    (exact region subtraction, no sampling)."""
    remainder = [box]
    for other in cover_boxes:
        if not remainder:
            return True
        remainder = subtract_region(remainder, other)
    return not remainder


def _descendants(succs: list[list[int]], n: int) -> list[int]:
    """Bitmask of strict descendants per node (nodes forced to be
    published *after* it)."""
    desc = [0] * n
    for i in range(n):
        seen = 0
        stack = list(succs[i])
        while stack:
            j = stack.pop()
            if (seen >> j) & 1:
                continue
            seen |= 1 << j
            stack.extend(succs[j])
        desc[i] = seen
    return desc


def _stable_linear_extension(subset: list[int], pred_mask: list[int]) -> list[int]:
    """Canonical linear extension of ``subset`` under the precedence
    constraints: repeatedly take the smallest-index (hence smallest rule
    id) node whose predecessors are all placed.  Deterministic by rule
    id, independent of how the subset was discovered."""
    members = set(subset)
    subset_mask = _mask_of(members)
    placed: list[int] = []
    placed_mask = 0
    remaining = sorted(members)
    while remaining:
        for node in remaining:
            if pred_mask[node] & subset_mask & ~placed_mask == 0:
                placed.append(node)
                placed_mask |= 1 << node
                remaining.remove(node)
                break
        else:  # pragma: no cover - impossible for an acyclic poset
            raise AssertionError("约束图存在环，无法拓扑排序")
    return placed


def _mask_of(nodes) -> int:
    mask = 0
    for node in nodes:
        mask |= 1 << node
    return mask


def solve_review(rules, constraints) -> dict:
    """Review every constraint-legal publish order of ``rules``.

    Returns ``{"status": "robust", ...}`` when all legal orders keep a
    first-hit packet for every rule, otherwise
    ``{"status": "not_robust", "counterexample": {...}}`` with a
    complete counterexample order, the shadowed rule and the earlier
    rules covering it.
    """
    # Index rules by ascending rule id: index order == id order, so every
    # tie-break below is stable by rule id.
    order = sorted(range(len(rules)), key=lambda i: rules[i].id)
    ids = [rules[i].id for i in order]
    boxes = [_box_of(rules[i]) for i in order]
    n = len(ids)
    index = {rid: i for i, rid in enumerate(ids)}

    pred_mask = [0] * n
    succs: list[list[int]] = [[] for _ in range(n)]
    for c in constraints:
        before, after = index[c.before], index[c.after]
        pred_mask[after] |= 1 << before
        succs[before].append(after)
    desc = _descendants(succs, n)
    full_mask = (1 << n) - 1

    # Exact per-candidate filter: rule c can only ever be shadowed if the
    # union of all rules not forced after c (the maximal legal prefix
    # excluding c) covers its region.
    shadowable: list[bool] = [False] * n
    for c in range(n):
        allowed = full_mask & ~desc[c] & ~(1 << c)
        cover_boxes = [boxes[j] for j in range(n) if (allowed >> j) & 1]
        shadowable[c] = _covered(boxes[c], cover_boxes)

    if not any(shadowable):
        # Provably no rule can be shadowed in any order; the enumeration
        # below would visit every prefix state and find nothing.
        return {"status": "robust", "counterexample": None, "states_explored": 0}

    # Enumerate the prefix states allowed by the constraints (down-sets
    # of the poset), maintaining the prefix union as an exact region.
    union_boxes: list[tuple] = []  # boxes of the current prefix
    visited: set[int] = set()
    states_explored = 0
    found: tuple[int, int] | None = None  # (prefix mask, shadowed rule)

    def available(mask: int) -> list[int]:
        return [
            i
            for i in range(n)
            if not (mask >> i) & 1 and pred_mask[i] & ~mask == 0
        ]

    def dfs(mask: int) -> None:
        nonlocal states_explored, found
        if found is not None or mask in visited:
            return
        visited.add(mask)
        states_explored += 1
        candidates = available(mask)
        for c in candidates:
            if shadowable[c] and _covered(boxes[c], union_boxes):
                found = (mask, c)
                return
        for c in candidates:
            union_boxes.append(boxes[c])
            dfs(mask | (1 << c))
            union_boxes.pop()
            if found is not None:
                return

    dfs(0)

    if found is None:  # pragma: no cover - guaranteed by the filter above
        return {
            "status": "robust",
            "counterexample": None,
            "states_explored": states_explored,
        }

    prefix_mask, shadowed = found
    prefix = [i for i in range(n) if (prefix_mask >> i) & 1]
    rest = [i for i in range(n) if i != shadowed and not (prefix_mask >> i) & 1]
    head = _stable_linear_extension(prefix, pred_mask)
    tail = _stable_linear_extension(rest, pred_mask)
    full_order = head + [shadowed] + tail
    covered_by = [i for i in head if intersects(boxes[i], boxes[shadowed])]
    return {
        "status": "not_robust",
        "counterexample": {
            "order": [ids[i] for i in full_order],
            "shadowed_rule": ids[shadowed],
            "covered_by": [ids[i] for i in covered_by],
        },
        "states_explored": states_explored,
    }
