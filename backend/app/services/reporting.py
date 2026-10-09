import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime

from app.core.domain import Finding, FindingStatus, ScanHistory
from app.services.compliance import build_compliance_posture


def _candidate_id(kind: str, findings: list[Finding]) -> str:
    material = "|".join(sorted(item.fingerprint for item in findings))
    return hashlib.sha256(f"{kind}|{material}".encode()).hexdigest()[:24]


def _flag(item: Finding, factor: str) -> bool:
    return item.risk.factors.get(factor, 0) > 0


def build_attack_paths(findings: list[Finding]) -> list[dict]:
    """Build conservative attack-path candidates from signals on the SAME resource.

    A candidate is emitted only when one resource is both reachable from the Internet
    and carries sensitive data or administrative privilege, and has at least two active
    findings. Co-presence of unrelated findings in the same account is deliberately not
    enough. These are prioritization hints, not proof of exploitability.
    """
    active = [item for item in findings if item.status != FindingStatus.RESOLVED]
    by_resource: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
    for item in active:
        by_resource[(item.account_id, item.region, item.resource_id)].append(item)

    kinds = (
        (
            "exposed-sensitive-resource",
            "sensitive_data",
            "Internet-exposed resource holding sensitive data",
            (
                "The same resource is reachable from the Internet and holds data marked "
                "sensitive, and it has several active findings. A compromise of this entry "
                "point would expose that data."
            ),
            (
                "Remove public access first, then fix the remaining findings on the resource "
                "(encryption, logging, transport security)."
            ),
        ),
        (
            "exposed-privileged-resource",
            "privileged",
            "Internet-exposed resource with administrative privilege",
            (
                "The same resource is reachable from the Internet and runs with administrative "
                "privilege, and it has several active findings. Compromising it would give "
                "broad access to the account."
            ),
            (
                "Restrict exposure, then replace administrative permissions with a "
                "least-privilege role."
            ),
        ),
    )

    candidates: list[dict] = []
    for (account_id, _region, _resource), group in by_resource.items():
        if len(group) < 2:
            continue
        ranked = sorted(group, key=lambda item: item.risk.score, reverse=True)
        if not _flag(ranked[0], "internet_exposure"):
            continue
        for kind, factor, title, rationale, remediation in kinds:
            if not _flag(ranked[0], factor):
                continue
            chain = ranked[:4]
            average = sum(item.risk.score for item in chain) / len(chain)
            score = min(100, round(average + 10))
            candidates.append(
                {
                    "path_id": _candidate_id(kind, chain),
                    "kind": kind,
                    "title": title,
                    "account_id": account_id,
                    "severity": "critical" if score >= 90 else "high",
                    "score": score,
                    "confidence": "candidate",
                    "rationale": rationale,
                    "caveat": (
                        "Correlated posture signals on one resource only; this does not prove "
                        "network reachability, credential compromise, or exploitability."
                    ),
                    "steps": [
                        {
                            "finding_fingerprint": item.fingerprint,
                            "rule_id": item.rule_id,
                            "title": item.title,
                            "resource_id": item.resource_id,
                            "resource_type": item.resource_type,
                            "region": item.region,
                            "risk_score": item.risk.score,
                        }
                        for item in chain
                    ],
                    "remediation": remediation,
                }
            )

    return sorted(candidates, key=lambda item: (item["score"], item["path_id"]), reverse=True)


def build_executive_summary(findings: list[Finding]) -> dict:
    active = [item for item in findings if item.status != FindingStatus.RESOLVED]
    counts = Counter(item.severity.value for item in active)
    accounts = sorted({item.account_id for item in active})
    regions = sorted({item.region for item in active})
    attack_paths = build_attack_paths(active)
    return {
        "findings": len(active),
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "highest_risk": max((item.risk.score for item in active), default=None),
        "accounts_affected": len(accounts),
        "regions_affected": len(regions),
        "internet_exposed": sum(
            item.risk.factors.get("internet_exposure", 0) > 0 for item in active
        ),
        "privileged": sum(item.risk.factors.get("privileged", 0) > 0 for item in active),
        "sensitive_data": sum(
            item.risk.factors.get("sensitive_data", 0) > 0 for item in active
        ),
        "attack_path_candidates": len(attack_paths),
        "top_risks": [
            {
                "fingerprint": item.fingerprint,
                "rule_id": item.rule_id,
                "title": item.title,
                "resource_id": item.resource_id,
                "account_id": item.account_id,
                "region": item.region,
                "severity": item.severity.value,
                "risk_score": item.risk.score,
            }
            for item in sorted(active, key=lambda item: item.risk.score, reverse=True)[:5]
        ],
    }


def build_security_report(
    tenant_id: str,
    source: str,
    findings: list[Finding],
    scans: list[ScanHistory],
) -> dict:
    counts = Counter(str(item.severity) for item in findings)
    highest_risk = max((item.risk.score for item in findings), default=None)
    latest = next((scan for scan in scans if scan.source == source), None)
    payload = {
        "schema": "aegisshield.security-report.v2",
        "generated_at": datetime.now(UTC).isoformat(),
        "tenant_id": tenant_id,
        "source": source,
        "summary": {
            "findings": len(findings),
            "critical": counts.get("critical", 0),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "highest_risk": highest_risk,
            "latest_scan_status": latest.status if latest else None,
            "latest_scan_started_at": (
                latest.started_at.isoformat() if latest else None
            ),
        },
        "executive_summary": build_executive_summary(findings),
        "attack_paths": build_attack_paths(findings),
        "compliance": build_compliance_posture(findings),
        "findings": [item.model_dump(mode="json") for item in findings],
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    payload["integrity_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload
