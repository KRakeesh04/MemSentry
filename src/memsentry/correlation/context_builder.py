"""Scoped process identities and reusable indexes, independent of detection rules."""

from __future__ import annotations

import json
from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from memsentry.correlation.normalization import NormalizedArtifact, integer, timestamp
from memsentry.models.artifact import Artifact


@dataclass(slots=True)
class ProcessContext:
    pid: int
    process_name: str | None
    ppid: int | None
    memory_regions: list[Artifact] = field(default_factory=list)
    network_connections: list[Artifact] = field(default_factory=list)
    threads: list[Artifact] = field(default_factory=list)
    modules: list[Artifact] = field(default_factory=list)
    signature_matches: list[Artifact] = field(default_factory=list)
    command_line: Artifact | None = None
    process_instance_id: str = ""
    identity_strength: str = "unresolved"
    artifacts: list[NormalizedArtifact] = field(default_factory=list)


def stable_id(parts: Any) -> str:
    return str(uuid5(NAMESPACE_URL, json.dumps(parts, sort_keys=True, default=str)))


class ContextIndex:
    def __init__(self, artifacts: list[NormalizedArtifact]) -> None:
        self.artifacts = sorted(artifacts, key=lambda a: a.id)
        self.by_type: dict[str, list[NormalizedArtifact]] = defaultdict(list)
        self.by_scope_type: dict[tuple[tuple[str, str, str], str], list[NormalizedArtifact]] = (
            defaultdict(list)
        )
        self.by_instance: dict[str, list[NormalizedArtifact]] = defaultdict(list)
        self.by_pid: dict[tuple[tuple[str, str, str], int], list[NormalizedArtifact]] = defaultdict(
            list
        )
        self.by_guid: dict[tuple[tuple[str, str, str], str], set[str]] = defaultdict(set)
        self.by_ppid: dict[tuple[tuple[str, str, str], int], list[NormalizedArtifact]] = (
            defaultdict(list)
        )
        self.by_target: dict[str, list[NormalizedArtifact]] = defaultdict(list)
        self.by_timestamp: dict[tuple[str, str, str], list[NormalizedArtifact]] = defaultdict(list)
        self._addresses: dict[
            tuple[str, str, str, str],
            tuple[list[int], list[NormalizedArtifact], list[NormalizedArtifact]],
        ] = {}
        self.contexts: dict[str, ProcessContext] = {}
        self.warnings: list[str] = []
        groups: dict[tuple[Any, ...], list[NormalizedArtifact]] = defaultdict(list)
        for a in self.artifacts:
            self.by_type[a.kind].append(a)
            self.by_scope_type[(a.scope, a.kind)].append(a)
            if a.data.get("ppid") is not None:
                self.by_ppid[(a.scope, a.data["ppid"])].append(a)
            if a.data.get("timestamp_utc") is not None:
                self.by_timestamp[a.scope].append(a)
            groups[(*a.scope, a.data.get("pid"))].append(a)
        guid_claims: dict[tuple[tuple[str, str, str], str], tuple[set[int], set[str]]] = {}
        for a in self.artifacts:
            guid = a.data.get("process_guid") or a.data.get("source_process_guid")
            if guid:
                pids, creations = guid_claims.setdefault((a.scope, guid), (set(), set()))
                if a.data.get("pid") is not None:
                    pids.add(a.data["pid"])
                if a.data.get("process_creation_time"):
                    creations.add(a.data["process_creation_time"])
        conflicting_guids = {
            key
            for key, (pids, creations) in guid_claims.items()
            if len(pids) > 1 or len(creations) > 1
        }
        for _, guid in sorted(conflicting_guids):
            self.warnings.append(
                f"Conflicting lifetime claims for process GUID {guid}; GUID linkage disabled"
            )
        for members in groups.values():
            strong: dict[tuple[str, str], str] = {}
            for a in members:
                guid = a.data.get("process_guid") or a.data.get("source_process_guid")
                if (a.scope, guid) in conflicting_guids:
                    guid = None
                creation = a.data.get("process_creation_time")
                explicit = a.data.get("process_instance_id")
                discriminator = (
                    ("guid", str(guid))
                    if guid
                    else (
                        ("instance", str(explicit))
                        if explicit
                        else (("created", str(creation)) if creation else None)
                    )
                )
                if discriminator:
                    a.instance = strong.setdefault(
                        discriminator,
                        stable_id(
                            [
                                a.scope,
                                None if guid or explicit else a.data.get("pid"),
                                discriminator,
                            ]
                        ),
                    )
                    a.identity_strength = discriminator[0]
            # A timestamp-only view may join a GUID only when an unambiguous row carries both.
            creation_guids: dict[str, set[str]] = defaultdict(set)
            for a in members:
                if a.data.get("process_creation_time") and a.data.get("process_guid"):
                    creation_guids[a.data["process_creation_time"]].add(a.data["process_guid"])
            for a in members:
                creation = a.data.get("process_creation_time")
                guid = a.data.get("process_guid")
                if (
                    creation
                    and guid
                    and (a.scope, guid) not in conflicting_guids
                    and len(creation_guids[creation]) == 1
                ):
                    old = strong.get(("created", str(creation)))
                    if old:
                        for other in members:
                            if other.instance == old:
                                other.instance, other.identity_strength = a.instance, "guid"
                        strong[("created", str(creation))] = a.instance or old
            identities = {a.instance for a in members if a.instance}
            for a in members:
                if not a.instance:
                    # Legacy snapshots have one PID scope; event streams without lifetime identity do not.
                    snapshot = not a.data.get("telemetry") and a.data.get("pid") is not None
                    if snapshot and len(identities) <= 1:
                        a.instance = next(
                            iter(identities), stable_id([a.scope, a.data["pid"], "snapshot"])
                        )
                        a.identity_strength = "snapshot"
                    else:
                        a.instance = stable_id([a.scope, "unresolved", a.id])
                        if snapshot:
                            self.warnings.append(
                                f"Ambiguous reused PID on artifact {a.id}; left unlinked"
                            )
                self.by_instance[a.instance].append(a)
                pid = a.data.get("pid")
                if pid is not None:
                    self.by_pid[(a.scope, pid)].append(a)
                guid = a.data.get("process_guid") or a.data.get("source_process_guid")
                if guid:
                    self.by_guid[(a.scope, guid)].add(a.instance)
        for identity, members in sorted(self.by_instance.items()):
            anchor = next((a for a in members if a.kind in {"process", "process_tree"}), members[0])
            context = ProcessContext(
                int(anchor.data["pid"]) if anchor.data.get("pid") is not None else -1,
                anchor.data.get("process_name"),
                anchor.data.get("ppid"),
                process_instance_id=identity,
                identity_strength=anchor.identity_strength,
                artifacts=members,
            )
            for a in members:
                attr = {
                    "memory_region": "memory_regions",
                    "network_connection": "network_connections",
                    "thread": "threads",
                    "module": "modules",
                    "signature_match": "signature_matches",
                }.get(a.kind)
                if attr:
                    getattr(context, attr).append(a.artifact)
                if a.kind == "command_line":
                    context.command_line = a.artifact
            self.contexts[identity] = context
        for events in self.by_timestamp.values():
            events.sort(key=lambda a: (a.data["timestamp_utc"], a.id))
        for a in self.artifacts:
            target = self.resolve(a, "target")
            if target:
                self.by_target[target].append(a)

    def address_candidates(
        self, instance: str, kind: str, field_name: str, region: NormalizedArtifact
    ) -> list[NormalizedArtifact] | None:
        """Binary-search observed addresses in a bound region; retain unknowns for tri-state logic."""
        start, end = integer(region.data.get("start")), integer(region.data.get("end"))
        if start is None or end is None or start > end:
            return None
        key = (instance, kind, field_name, str(region.data.get("address_space")))
        if key not in self._addresses:
            known: list[tuple[int, NormalizedArtifact]] = []
            unknown = []
            for a in self.by_instance.get(instance, []):
                if a.kind == kind:
                    address = integer(a.data.get(field_name))
                    if address is None or a.data.get("address_space") != region.data.get(
                        "address_space"
                    ):
                        unknown.append(a)
                    else:
                        known.append((address, a))
            known.sort(key=lambda item: (item[0], item[1].id))
            self._addresses[key] = (
                [item[0] for item in known],
                [item[1] for item in known],
                unknown,
            )
        addresses, artifacts, unknown = self._addresses[key]
        if not addresses and not unknown:
            return None
        stop = (
            bisect_right(addresses, end)
            if region.data.get("end_inclusive") is True
            else bisect_left(addresses, end)
        )
        return artifacts[bisect_left(addresses, start) : stop] + unknown

    def resolve(self, a: NormalizedArtifact, role: str) -> str | None:
        guid = a.data.get(f"{role}_process_guid")
        if guid:
            identities = self.by_guid.get((a.scope, guid), set())
            if not identities:
                # Referenced GUID is a scoped identity, not a fabricated graph node.
                return stable_id([a.scope, None, ("guid", str(guid))])
        else:
            pid = a.data.get(f"{role}_pid", a.data.get("ppid") if role == "parent" else None)
            if pid is None:
                return None
            candidates = self.by_pid.get((a.scope, pid), [])
            identities = {
                b.instance for b in candidates if b.instance and b.identity_strength != "unresolved"
            }
            # PID-only events never establish a historical lifetime relationship.
            if a.data.get("telemetry"):
                creation = a.data.get(f"{role}_creation_time")
                identities = {
                    b.instance
                    for b in candidates
                    if b.instance and creation and b.data.get("process_creation_time") == creation
                }
        identity = next(iter(identities)) if len(identities) == 1 else None
        if identity and role == "parent":
            child_created = timestamp(a.data.get("process_creation_time"))
            for parent in self.by_instance.get(identity, []):
                parent_created = timestamp(parent.data.get("process_creation_time"))
                parent_exited = timestamp(parent.data.get("exited_at"))
                if child_created and (
                    (parent_created and parent_created > child_created)
                    or (parent_exited and parent_exited < child_created)
                ):
                    return None
        return identity

    def same(self, a: NormalizedArtifact, b: NormalizedArtifact) -> bool | None:
        if a.scope != b.scope:
            return False
        if "unresolved" in {a.identity_strength, b.identity_strength}:
            return None
        return a.instance == b.instance
