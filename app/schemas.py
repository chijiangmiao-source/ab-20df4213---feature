"""Request schemas and validation for the audit API."""

from __future__ import annotations

import ipaddress
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

AUDIT_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
RULE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
MAX_RULES = 18
MAX_CONSTRAINTS = 6
PORT_MIN = 0
PORT_MAX = 65535


def parse_cidr(value: str) -> tuple[int, int]:
    """Validate an IPv4 CIDR and return its inclusive uint32 interval.

    Strict parsing: host bits must be zero (``10.0.0.1/24`` is rejected;
    write ``10.0.0.0/24``).  A bare address is accepted as a /32.
    """
    try:
        net = ipaddress.IPv4Network(value, strict=True)
    except ValueError as exc:
        raise ValueError(
            f"非法 IPv4 CIDR: {value!r}（需为合法网络地址，主机位须为 0，例如 10.0.0.0/8）"
        ) from exc
    return int(net.network_address), int(net.broadcast_address)


class PortRange(BaseModel):
    """Closed port interval [start, end] within 0..65535."""

    start: int = Field(ge=PORT_MIN, le=PORT_MAX)
    end: int = Field(ge=PORT_MIN, le=PORT_MAX)

    @model_validator(mode="after")
    def _ordered(self) -> "PortRange":
        if self.end < self.start:
            raise ValueError(
                f"端口区间下界 {self.start} 不得大于上界 {self.end}"
            )
        return self


class Rule(BaseModel):
    id: str = Field(pattern=RULE_ID_PATTERN)
    protocol: Literal["tcp", "udp", "both"]
    src_cidr: str
    dst_cidr: str
    src_port: PortRange
    dst_port: PortRange

    @field_validator("src_cidr", "dst_cidr")
    @classmethod
    def _cidr_ok(cls, value: str) -> str:
        parse_cidr(value)
        return value


class AuditRequest(BaseModel):
    audit_id: str = Field(pattern=AUDIT_ID_PATTERN)
    rules: list[Rule] = Field(min_length=1, max_length=MAX_RULES)

    @model_validator(mode="after")
    def _unique_rule_ids(self) -> "AuditRequest":
        ids = [rule.id for rule in self.rules]
        duplicates = sorted({rid for rid in ids if ids.count(rid) > 1})
        if duplicates:
            raise ValueError(f"规则标识重复: {', '.join(duplicates)}")
        return self


class Constraint(BaseModel):
    """One publish constraint: rule ``before`` must be published earlier
    than rule ``after``."""

    before: str = Field(pattern=RULE_ID_PATTERN)
    after: str = Field(pattern=RULE_ID_PATTERN)

    @model_validator(mode="after")
    def _distinct_rules(self) -> "Constraint":
        if self.before == self.after:
            raise ValueError(
                f"约束两端不得为同一规则: {self.before}"
            )
        return self


class ReviewRequest(BaseModel):
    """Publish-order review over a frozen source audit.

    ``constraints`` holds at most ``MAX_CONSTRAINTS`` precedence pairs;
    the pairs must not repeat and must not form a precedence cycle.
    Whether the referenced rules exist is checked against the source
    audit in the endpoint (the schema has no access to the store).
    """

    review_id: str = Field(pattern=AUDIT_ID_PATTERN)
    audit_id: str = Field(pattern=AUDIT_ID_PATTERN)
    constraints: list[Constraint] = Field(
        default_factory=list, max_length=MAX_CONSTRAINTS
    )

    @model_validator(mode="after")
    def _constraints_acyclic_and_unique(self) -> "ReviewRequest":
        pairs = [(c.before, c.after) for c in self.constraints]
        duplicates = sorted({p for p in pairs if pairs.count(p) > 1})
        if duplicates:
            rendered = ", ".join(f"{b} 早于 {a}" for b, a in duplicates)
            raise ValueError(f"重复约束: {rendered}")
        cycle = find_cycle(pairs)
        if cycle:
            raise ValueError(f"约束存在先后环: {' -> '.join(cycle)}")
        return self


def find_cycle(pairs: list[tuple[str, str]]) -> list[str] | None:
    """Return one precedence cycle (list of rule ids, first repeated at
    the end) if the ``before -> after`` pairs contain one, else None."""
    succs: dict[str, list[str]] = {}
    nodes: set[str] = set()
    for before, after in pairs:
        succs.setdefault(before, []).append(after)
        nodes.add(before)
        nodes.add(after)
    # Kahn's algorithm; whatever keeps unmet predecessors lies on or
    # downstream of a cycle.
    indegree = {node: 0 for node in nodes}
    for before, after in pairs:
        indegree[after] += 1
    queue = sorted(node for node in nodes if indegree[node] == 0)
    freed = 0
    while queue:
        node = queue.pop()
        freed += 1
        for nxt in succs.get(node, []):
            indegree[nxt] -= 1
            if indegree[nxt] == 0:
                queue.append(nxt)
    if freed == len(nodes):
        return None
    # Extract a concrete cycle among the stuck nodes for the message.
    # Every stuck node has at least one predecessor inside `stuck` (its
    # remaining indegree counts exactly those), so walking predecessors
    # is guaranteed to revisit a node; reversing the walk orients the
    # cycle along the "before" direction.
    preds: dict[str, list[str]] = {}
    for before, after in pairs:
        preds.setdefault(after, []).append(before)
    stuck = {node for node in nodes if indegree[node] > 0}
    start = min(stuck)
    path = [start]
    seen = {start}
    cur = start
    while True:
        nxt = min(p for p in preds.get(cur, []) if p in stuck)
        if nxt in seen:
            cycle = path[path.index(nxt):] + [nxt]
            cycle.reverse()
            return cycle
        path.append(nxt)
        seen.add(nxt)
        cur = nxt
