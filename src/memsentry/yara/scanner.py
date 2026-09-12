"""Read-only YARA scanning and persistence for memory evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from memsentry.models.artifact import ArtifactCreate
from memsentry.models.plugin_run import PluginRunCreate
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.volatility.os_utils import normalise_os


class YaraError(RuntimeError):
    """Base error for YARA scanning."""


class YaraUnavailableError(YaraError):
    """Raised when the optional yara-python dependency is unavailable."""


class YaraRuleError(YaraError):
    """Raised when supplied YARA rules cannot be compiled."""


class YaraEvidenceError(YaraError):
    """Raised when evidence is missing, unreadable, or changed during scanning."""


class _YaraModule(Protocol):
    def compile(self, *, filepaths: dict[str, str]) -> Any: ...


@dataclass(frozen=True, slots=True)
class YaraMatch:
    """A JSON-safe representation of one YARA rule match."""

    rule: str
    namespace: str
    tags: tuple[str, ...]
    meta: dict[str, Any]
    strings: tuple[dict[str, Any], ...]


@dataclass(frozen=True, slots=True)
class YaraScanResult:
    """Result and audit metadata for one YARA scan."""

    requested: bool
    evidence_sha256_before: str | None
    evidence_sha256_after: str | None
    rule_sha256: dict[str, str]
    matches: tuple[YaraMatch, ...]
    warnings: tuple[str, ...] = ()
    plugin_run: Any | None = None


class YaraScanner:
    """Compile approved rule files and scan an evidence image without modifying it."""

    def __init__(
        self,
        plugin_run_repository: PluginRunRepository,
        artifact_repository: ArtifactRepository,
        raw_output_dir: str | Path | None = None,
        yara_module: _YaraModule | None = None,
    ) -> None:
        self.plugin_run_repository = plugin_run_repository
        self.artifact_repository = artifact_repository
        self.raw_output_dir = Path(raw_output_dir) if raw_output_dir else None
        self._yara_module = yara_module

    def scan(
        self,
        evidence_path: str | Path,
        analysis_run_id: UUID,
        rule_paths: list[str | Path] | tuple[str | Path, ...],
        os_type: str | None = None,
    ) -> YaraScanResult:
        """Scan evidence and persist one ``signature_match`` artifact per rule match."""
        evidence = Path(evidence_path)
        if not rule_paths:
            return YaraScanResult(False, None, None, {}, ())
        normalized_os = normalise_os(os_type) if os_type is not None else None
        self._verify_evidence(evidence)
        rules = self._resolve_rules(rule_paths)
        rule_hashes = {str(path): self._sha256_file(path) for path in rules}
        plugin_run = self.plugin_run_repository.create(
            PluginRunCreate(
                analysis_run_id=analysis_run_id,
                plugin_name="yara.scan",
                configuration={
                    "rule_paths": [str(path) for path in rules],
                    "rule_sha256": rule_hashes,
                    "os_type": normalized_os,
                },
            )
        )
        self.plugin_run_repository.mark_running(plugin_run.id)
        try:
            evidence_hash_before = self._sha256_file(evidence)
            compiled = self._compile(rules)
            raw_matches = compiled.match(str(evidence))
            matches = tuple(self._normalize_match(match) for match in raw_matches)
            evidence_hash_after = self._sha256_file(evidence)
            if evidence_hash_before != evidence_hash_after:
                raise YaraEvidenceError(
                    "Evidence changed during YARA scanning; integrity verification failed."
                )
            raw_path = self._store_raw_output(
                plugin_run.id,
                {
                    "evidence_sha256_before": evidence_hash_before,
                    "evidence_sha256_after": evidence_hash_after,
                    "rule_sha256": rule_hashes,
                    "matches": [asdict(match) for match in matches],
                },
            )
            for match in matches:
                self.artifact_repository.create(
                    ArtifactCreate(
                        analysis_run_id=analysis_run_id,
                        plugin_run_id=plugin_run.id,
                        artifact_type="signature_match",
                        original_data={
                            "normalized": asdict(match),
                            "evidence_sha256": evidence_hash_before,
                            "rule_sha256": rule_hashes,
                        },
                        provenance={
                            "source": "yara",
                            "plugin": "yara.scan",
                            "rule_files": [str(path) for path in rules],
                        },
                    )
                )
            completed = self.plugin_run_repository.mark_completed(
                plugin_run.id, raw_path, self._sha256_file(raw_path)
            )
            return YaraScanResult(
                True,
                evidence_hash_before,
                evidence_hash_after,
                rule_hashes,
                matches,
                plugin_run=completed,
            )
        except Exception as error:
            self.plugin_run_repository.mark_failed(plugin_run.id, str(error))
            if isinstance(error, YaraError):
                raise
            raise YaraError(f"YARA scan failed: {error}") from error

    def _compile(self, rules: list[Path]) -> Any:
        yara = self._yara_module or _import_yara()
        try:
            return yara.compile(filepaths={path.name: str(path) for path in rules})
        except Exception as error:
            raise YaraRuleError(f"Could not compile YARA rules: {error}") from error

    @staticmethod
    def _normalize_match(match: Any) -> YaraMatch:
        strings: list[dict[str, Any]] = []
        for item in getattr(match, "strings", ()):
            if hasattr(item, "offset"):
                offset, identifier, data = item.offset, item.identifier, item.data
            else:
                offset, identifier, data = item
            strings.append(
                {
                    "offset": int(offset),
                    "identifier": str(identifier),
                    "data_hex": bytes(data).hex(),
                }
            )
        return YaraMatch(
            rule=str(match.rule),
            namespace=str(getattr(match, "namespace", "default")),
            tags=tuple(str(tag) for tag in getattr(match, "tags", ())),
            meta=dict(getattr(match, "meta", {})),
            strings=tuple(strings),
        )

    @staticmethod
    def _resolve_rules(rule_paths: list[str | Path] | tuple[str | Path, ...]) -> list[Path]:
        resolved: set[Path] = set()
        for supplied in rule_paths:
            path = Path(supplied).expanduser()
            candidates = sorted(path.glob("*.yar")) + sorted(path.glob("*.yara")) if path.is_dir() else [path]
            for candidate in candidates:
                candidate = candidate.resolve()
                if candidate.suffix.lower() not in {".yar", ".yara"}:
                    raise YaraRuleError(f"Unsupported YARA rule file: {candidate}")
                if not candidate.is_file():
                    raise YaraRuleError(f"YARA rule file does not exist: {candidate}")
                resolved.add(candidate)
        if not resolved:
            raise YaraRuleError("No YARA rule files were supplied.")
        return sorted(resolved)

    @staticmethod
    def _verify_evidence(evidence: Path) -> None:
        if not evidence.is_file():
            raise YaraEvidenceError(f"Evidence image does not exist: {evidence}")
        if not evidence.stat().st_mode & 0o444:
            raise YaraEvidenceError(f"Evidence image is not readable: {evidence}")

    def _store_raw_output(self, run_id: UUID, payload: dict[str, Any]) -> Path:
        output_root = self.raw_output_dir or (Path.cwd() / "raw_output")
        output_root.mkdir(parents=True, exist_ok=True)
        output_path = output_root / f"{run_id}_yara.json"
        output_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        return output_path

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as file_handle:
            for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


def _import_yara() -> _YaraModule:
    try:
        import yara
    except ImportError as error:
        raise YaraUnavailableError(
            "YARA rules were supplied, but yara-python is not installed."
        ) from error
    return yara  # type: ignore[no-any-return]
