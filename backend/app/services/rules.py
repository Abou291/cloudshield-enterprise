import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from app.core.domain import Asset, Finding, Severity
from app.services.risk import RiskEngine


class RuleCondition(BaseModel):
    path: str
    operator: str
    value: Any = None


class Rule(BaseModel):
    id: str
    name: str
    description: str
    resource_type: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    conditions: list[RuleCondition]
    remediation: str


def _get_path(document: dict[str, Any], path: str) -> Any:
    current: Any = document
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _matches(condition: RuleCondition, attributes: dict[str, Any]) -> bool:
    actual = _get_path(attributes, condition.path)
    expected = condition.value
    match condition.operator:
        case "equals":
            return actual == expected
        case "tcp_port_in_range":
            protocol = attributes.get("protocol", "tcp")
            if protocol == "-1":
                return True
            upper = attributes.get("to_port", actual)
            return (
                protocol in {"tcp", "6"}
                and isinstance(actual, int)
                and isinstance(upper, int)
                and actual <= expected <= upper
            )
        case "not_equals":
            return actual != expected
        case "contains":
            return isinstance(actual, (str, list, tuple, set)) and expected in actual
        case "older_than_days":
            return isinstance(actual, (int, float)) and actual > expected
        case "is_false":
            return actual is False
        case "is_true":
            return actual is True
        case "cidr_world":
            return actual in {"0.0.0.0/0", "::/0"}
        case _:
            raise ValueError(f"Unsupported rule operator: {condition.operator}")


class RuleEngine:
    def __init__(self, rules: list[Rule], risk_engine: RiskEngine | None = None) -> None:
        self.rules = rules
        self.risk_engine = risk_engine or RiskEngine()

    @classmethod
    def from_directory(cls, rules_dir: Path) -> "RuleEngine":
        rules: list[Rule] = []
        for path in sorted(rules_dir.glob("*.yaml")):
            payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            rules.extend(Rule.model_validate(item) for item in payload.get("rules", []))
        if not rules:
            raise ValueError(f"No rules found in {rules_dir}")
        ids = [rule.id for rule in rules]
        if len(ids) != len(set(ids)):
            raise ValueError("Rule IDs must be unique")
        return cls(rules)

    def evaluate(self, assets: list[Asset]) -> list[Finding]:
        findings: list[Finding] = []
        for asset in assets:
            for rule in self.rules:
                if rule.resource_type != asset.resource_type:
                    continue
                if not all(_matches(condition, asset.attributes) for condition in rule.conditions):
                    continue
                evidence = {
                    condition.path: _get_path(asset.attributes, condition.path)
                    for condition in rule.conditions
                }
                if any(c.operator == "tcp_port_in_range" for c in rule.conditions):
                    evidence["protocol"] = asset.attributes.get("protocol", "tcp")
                    evidence["to_port"] = asset.attributes.get(
                        "to_port", asset.attributes.get("from_port")
                    )
                fingerprint = hashlib.sha256(
                    f"{asset.account_id}|{asset.region}|{asset.resource_id}|{rule.id}".encode()
                ).hexdigest()
                findings.append(
                    Finding(
                        fingerprint=fingerprint,
                        rule_id=rule.id,
                        title=rule.name,
                        description=rule.description,
                        severity=rule.severity,
                        resource_id=asset.resource_id,
                        resource_type=asset.resource_type,
                        account_id=asset.account_id,
                        region=asset.region,
                        evidence=json.loads(json.dumps(evidence, default=str)),
                        recommendation=rule.remediation,
                        risk=self.risk_engine.score(rule.severity, asset, rule.confidence),
                    )
                )
        return sorted(findings, key=lambda finding: finding.risk.score, reverse=True)
