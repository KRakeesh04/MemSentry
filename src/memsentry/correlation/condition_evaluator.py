"""Three-valued predicates: None means unknown, including under negation.

Equality is typed (no coercion); contains is literal/case-sensitive; contains_any/all
operate on substrings or collection members. Numeric ordering is strict. Address
ranges use each region's declared end convention. before/after are strict and
within_seconds includes its boundary. Time predicates reject uncertain timestamps.
Identity predicates always include analysis, host and acquisition scope; same_pid
is intentionally weaker and is never used by bundled rules to establish identity.
"""

from __future__ import annotations

import re
from typing import Any

from memsentry.correlation.context_builder import ContextIndex
from memsentry.correlation.normalization import NormalizedArtifact, integer

VALUE_OPS = frozenset(
    {
        "equals",
        "not_equals",
        "one_of",
        "contains",
        "contains_any",
        "contains_all",
        "exists",
        "greater_than",
        "less_than",
        "matches_regex",
    }
)
RELATION_OPS = frozenset(
    {
        "inside",
        "same_pid",
        "same_process_instance",
        "same_host",
        "same_logon_id",
        "same_account",
        "same_source_process",
        "same_target_process",
        "target_process",
        "parent_child",
        "before",
        "after",
        "within_seconds",
        "absent_from_view",
    }
)


def value_predicate(value: Any, op: str, expected: Any) -> bool | None:
    if value is None:
        return None
    try:
        if op == "exists":
            return bool(expected)  # Missing is unknown, never proof of absence.
        if op == "equals":
            return type(value) is type(expected) and bool(value == expected)
        if op == "not_equals":
            return not (type(value) is type(expected) and value == expected)
        if op == "one_of":
            return any(type(value) is type(item) and value == item for item in expected)
        if op == "contains":
            return expected in value
        if op == "contains_any":
            return any(item in value for item in expected)
        if op == "contains_all":
            return all(item in value for item in expected)
        if op == "greater_than":
            return bool(value > expected)
        if op == "less_than":
            return bool(value < expected)
        if op == "matches_regex":
            return re.search(expected, str(value)) is not None
    except (TypeError, ValueError):
        return None
    raise ValueError(f"Unknown predicate {op}")


def where(data: dict[str, Any], expression: dict[str, Any]) -> bool | None:
    results: list[bool | None] = []
    for key, children in expression.items():
        if key in {"all", "any", "not"}:
            values = [where(data, child) for child in children]
            if key == "all":
                result = False if False in values else (None if None in values else True)
            elif key == "any":
                result = True if True in values else (None if None in values else False)
            else:
                result = False if True in values else (None if None in values else True)
            results.append(result)
    if "field" in expression:
        op = next(key for key in expression if key in VALUE_OPS)
        results.append(value_predicate(data.get(expression["field"]), op, expression[op]))
    return False if False in results else (None if None in results else True)


def relation(
    index: ContextIndex,
    left: NormalizedArtifact,
    right: NormalizedArtifact,
    op: str,
    expression: dict[str, Any],
) -> bool | None:
    if left.scope != right.scope:
        return False
    if op == "same_host":
        return True if left.data.get("host_id") and right.data.get("host_id") else None
    if op == "same_pid":
        return (
            None
            if left.data.get("pid") is None or right.data.get("pid") is None
            else left.data["pid"] == right.data["pid"]
        )
    if op == "same_process_instance":
        return index.same(left, right)
    if op == "same_logon_id":
        a, b = left.data.get("logon_id"), right.data.get("logon_id")
        return a == b if a and b and left.data.get("host_id") else None
    if op == "same_account":
        if not left.data.get("host_id"):
            return None
        a, b = left.data.get("user_sid"), right.data.get("user_sid")
        if a and b and a != "S-1-0-0" and b != "S-1-0-0":
            return bool(a == b)
        left_account = (left.data.get("domain"), left.data.get("user"))
        right_account = (right.data.get("domain"), right.data.get("user"))
        if all(left_account) and all(right_account):
            return tuple(str(v).casefold() for v in left_account) == tuple(
                str(v).casefold() for v in right_account
            )
        return None
    if op in {"same_source_process", "same_target_process", "target_process", "parent_child"}:
        if op == "parent_child":
            identity = index.resolve(right, "parent")
            return identity == left.instance if identity else None
        if op == "same_source_process":
            return index.same(left, right)
        a = index.resolve(left, "target")
        b = right.instance if op == "target_process" else index.resolve(right, "target")
        return a == b if a and b else None
    if op == "inside":
        field = expression.get("field", "start_address")
        address, start, end = (
            integer(left.data.get(field)),
            integer(right.data.get("start")),
            integer(right.data.get("end")),
        )
        if None in (address, start, end):
            return None
        if not left.data.get("address_space") or left.data.get("address_space") != right.data.get(
            "address_space"
        ):
            return None
        same = index.same(left, right)
        if left.kind in {"remote_thread", "process_memory_write"}:
            target = index.resolve(left, "target")
            same = target == right.instance if target else None
        if same is not True:
            return same
        assert address is not None and start is not None and end is not None
        if start > end:
            return None
        return (
            start <= address <= end
            if right.data.get("end_inclusive") is True
            else start <= address < end
        )
    if op == "absent_from_view":
        # Absence requires an explicit, compatible and complete enumeration manifest.
        if (
            right.data.get("complete") is not True
            or right.data.get("compatible") is not True
            or right.data.get("snapshot_id") != left.data.get("snapshot_id")
            or not left.data.get("snapshot_id")
        ):
            return None
        if left.data.get("exited_at") or right.data.get("limitations"):
            return None
        members = right.data.get("process_keys")
        key = left.data.get("view_process_key")
        return key not in members if isinstance(members, list) and key else None
    if op in {"before", "after", "within_seconds"}:
        a, b = left.data.get("timestamp_utc"), right.data.get("timestamp_utc")
        if (
            a is None
            or b is None
            or left.data.get("timestamp_uncertainty_seconds", 0)
            or right.data.get("timestamp_uncertainty_seconds", 0)
        ):
            return None
        delta = (b - a).total_seconds()
        precision = max(
            left.data.get("timestamp_precision", 0.000001),
            right.data.get("timestamp_precision", 0.000001),
        )
        if op in {"before", "after"} and 0 < abs(delta) < precision:
            return None
        return bool(
            delta > 0
            if op == "before"
            else (delta < 0 if op == "after" else abs(delta) <= expression["seconds"])
        )
    raise ValueError(f"Unknown relation {op}")
