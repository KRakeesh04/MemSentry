"""Load correlation rules from YAML configuration files."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from memsentry.models.finding import FindingSeverity


@dataclass(frozen=True, slots=True)
class CorrelationRule:
    """A detection rule for correlating memory artifacts."""

    rule_id: str
    title: str
    description: str
    severity: FindingSeverity
    base_score: float
    applicable_os: tuple[str, ...] = ("windows", "linux", "mac")
    required_artifacts: tuple[str, ...] = ()
    benign_explanations: tuple[str, ...] = ()


class RuleLoadError(RuntimeError):
    """Raised when rule configuration cannot be loaded."""


def load_rules_from_yaml(
    rule_file_path: str | Path, os_type: str = "windows"
) -> list[CorrelationRule]:
    """Load correlation rules from a YAML configuration file.

    Args:
        rule_file_path: Path to the YAML rule configuration file
        os_type: Operating system type for OS-specific rule filtering

    Returns:
        List of CorrelationRule objects

    Raises:
        RuleLoadError: If the YAML file cannot be loaded or parsed
    """
    try:
        rule_path = Path(rule_file_path)
        if not rule_path.exists():
            raise RuleLoadError(f"Rule file not found: {rule_path}")

        with rule_path.open("r", encoding="utf-8") as f:
            config = yaml.safe_load(f)

        if not config or "rules" not in config:
            raise RuleLoadError(f"Invalid rule configuration in {rule_path}")

        rules: list[CorrelationRule] = []
        for rule_config in config["rules"]:
            rule = _convert_yaml_rule_to_correlation_rule(rule_config)
            # Filter rules by OS applicability
            if os_type in rule.applicable_os:
                rules.append(rule)

        return rules

    except yaml.YAMLError as e:
        raise RuleLoadError(f"Failed to parse YAML rule file: {e}") from e
    except Exception as e:
        raise RuleLoadError(f"Failed to load rules: {e}") from e


def _convert_yaml_rule_to_correlation_rule(rule_config: dict[str, Any]) -> CorrelationRule:
    """Convert a YAML rule configuration to a CorrelationRule object.

    Args:
        rule_config: Dictionary containing rule configuration from YAML

    Returns:
        CorrelationRule object
    """
    rule_id = rule_config.get("id", "")
    name = rule_config.get("name", "")
    description = rule_config.get("description", "")
    severity_str = rule_config.get("severity", "low")
    score = rule_config.get("score", 0)
    applies_to = rule_config.get("applies_to", ["windows", "linux", "mac"])
    benign_explanations = rule_config.get("benign_explanations", [])

    # Convert severity string to FindingSeverity enum
    severity_map = {
        "informational": FindingSeverity.INFORMATIONAL,
        "low": FindingSeverity.LOW,
        "medium": FindingSeverity.MEDIUM,
        "high": FindingSeverity.HIGH,
        "critical": FindingSeverity.CRITICAL,
    }
    severity = severity_map.get(severity_str.lower(), FindingSeverity.LOW)

    # Convert score to confidence (normalize to 0.0-1.0 range)
    # Assuming max score is 50 based on the YAML file
    confidence = min(1.0, score / 50.0) if score > 0 else 0.5

    return CorrelationRule(
        rule_id=rule_id,
        title=name,
        description=description,
        severity=severity,
        base_score=confidence,
        applicable_os=tuple(applies_to),
        benign_explanations=tuple(benign_explanations),
    )


def get_default_rules_path() -> Path:
    """Get the default path to the correlation rules YAML file.

    Returns:
        Path to the default correlation_rules.yaml file
    """
    # Try multiple possible locations for the rules file
    possible_paths = [
        Path(__file__).parent.parent.parent / "resources" / "rules" / "correlation_rules.yaml",
        Path.cwd() / "resources" / "rules" / "correlation_rules.yaml",
        Path(__file__).parent.parent.parent.parent / "resources" / "rules" / "correlation_rules.yaml",
    ]

    for path in possible_paths:
        if path.exists():
            return path

    # Return the first path as default even if it doesn't exist
    # (error handling will occur during loading)
    return possible_paths[0]
