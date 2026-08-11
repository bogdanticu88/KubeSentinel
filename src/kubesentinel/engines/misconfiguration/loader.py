"""Loads rule definitions from the packaged YAML rule set."""

from pathlib import Path

import yaml
from pydantic import ValidationError

from kubesentinel.models.rule import Rule

RULES_ROOT = Path(__file__).resolve().parents[2] / "rules"


class RuleLoadError(Exception):
    """A rule file could not be parsed or failed schema validation."""


def load_rules(rules_root: Path = RULES_ROOT) -> list[Rule]:
    rules: list[Rule] = []
    seen_ids: dict[str, Path] = {}

    for rule_file in sorted(rules_root.rglob("*.yaml")):
        try:
            raw = yaml.safe_load(rule_file.read_text(encoding="utf-8"))
        except OSError as read_error:
            raise RuleLoadError(
                f"{rule_file}: could not read the file: {read_error}"
            ) from read_error
        except yaml.YAMLError as parse_error:
            raise RuleLoadError(f"{rule_file}: invalid YAML: {parse_error}") from parse_error

        try:
            rule = Rule.model_validate(raw)
        except ValidationError as validation_error:
            raise RuleLoadError(f"{rule_file}: {validation_error}") from validation_error

        if rule.id in seen_ids:
            raise RuleLoadError(
                f"{rule_file}: duplicate rule id {rule.id!r}, already used by {seen_ids[rule.id]}"
            )
        seen_ids[rule.id] = rule_file
        rules.append(rule)

    return [rule for rule in rules if rule.enabled]
