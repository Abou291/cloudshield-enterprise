from pathlib import Path
from typing import Any

import yaml

from app.core.domain import Finding, FindingStatus

FRAMEWORKS_PATH = Path(__file__).resolve().parents[1] / "compliance" / "frameworks.yaml"

CAVEAT = (
    "Indicative mapping of automated checks to control identifiers. 'no_findings_observed' "
    "means no failing check was seen, not that the control is satisfied; manual evidence "
    "and controls without an automated check are out of scope."
)


def load_frameworks(path: Path = FRAMEWORKS_PATH) -> list[dict[str, Any]]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return payload.get("frameworks", [])


def build_compliance_posture(
    findings: list[Finding],
    frameworks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Summarise which mapped controls currently have failing checks.

    Statuses: ``failing`` (an active finding exists for a mapped rule), ``unknown``
    (a scanner coverage gap means the check may not have run), ``no_findings_observed``.
    """
    frameworks = frameworks if frameworks is not None else load_frameworks()
    active = [item for item in findings if item.status != FindingStatus.RESOLVED]
    by_rule: dict[str, list[Finding]] = {}
    for item in active:
        by_rule.setdefault(item.rule_id, []).append(item)
    coverage_gap = "COV-001" in by_rule

    result = []
    for framework in frameworks:
        controls = []
        for control in framework.get("controls", []):
            matched = [item for rule in control["rules"] for item in by_rule.get(rule, [])]
            if matched:
                status = "failing"
            elif coverage_gap:
                status = "unknown"
            else:
                status = "no_findings_observed"
            controls.append(
                {
                    "id": control["id"],
                    "title": control["title"],
                    "rules": control["rules"],
                    "status": status,
                    "failing_findings": len(matched),
                    "highest_risk": max((item.risk.score for item in matched), default=None),
                }
            )
        result.append(
            {
                "id": framework["id"],
                "name": framework["name"],
                "controls_mapped": len(controls),
                "controls_failing": sum(c["status"] == "failing" for c in controls),
                "controls_unknown": sum(c["status"] == "unknown" for c in controls),
                "controls": controls,
            }
        )
    return {"caveat": CAVEAT, "coverage_incomplete": coverage_gap, "frameworks": result}
