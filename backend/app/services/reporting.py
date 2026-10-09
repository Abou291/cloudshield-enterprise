import hashlib
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime

from app.core.domain import Finding, FindingStatus, ScanHistory
from app.services.compliance import build_compliance_posture


def _candidate_id(kind: str, findings: list[Finding]) -> str:
    material = "|".join(sorted(item.fingerprint for item in findings))
    return hashlib.sha256(f"{kind}|{material}".encode()).hexdigest()[:24]


def build_attack_paths(findings: list[Finding]) -> list[dict]:
    """Build conservative attack-path candidates from correlated posture signals.

    These are prioritization hints, not proof of network or IAM reachability.
    AegisShield only emits a path when multiple independent findings increase
    the impact of the same AWS account.
    """
    active = [item for item in findings if item.status != FindingStatus.RESOLVED]
    by_account: dict[str, list[Finding]] = defaultdict(list)
    for item in active:
        by_account[item.account_id].append(item)

    candidates: list[dict] = []
    for account_id, account_findings in by_account.items():
        exposed = sorted(
            (
                item
                for item in account_findings
                if item.risk.factors.get("internet_exposure", 0) > 0
            ),
            key=lambda item: item.risk.score,
            reverse=True,
        )
        privileged = sorted(
            (
                item
                for item in account_findings
                if item.risk.factors.get("privileged", 0) > 0
            ),
            key=lambda item: item.risk.score,
            reverse=True,
        )
        sensitive = sorted(
            (
                item
                for item in account_findings
                if item.risk.factors.get("sensitive_data", 0) > 0
            ),
            key=lambda item: item.risk.score,
            reverse=True,
        )

        def append_candidate(
            kind: str,
            title: str,
            rationale: str,
            remediation: str,
            chain: list[Finding],
            candidate_account_id: str = account_id,
        ) -> None:
            unique = list({item.fingerprint: item for item in chain}.values())
            if len(unique) < 2:
                return
            average = sum(item.risk.score for item in unique) / len(unique)
            score = min(100, round(average + 10))
            candidates.append(
                {
                    "path_id": _candidate_id(kind, unique),
                    "kind": kind,
                    "title": title,
                    "account_id": candidate_account_id,
                    "severity": "critical" if score >= 90 else "high",
                    "score": score,
                    "confidence": "candidate",
                    "rationale": rationale,
                    "caveat": (
                        "Correlated posture signals only; this does not prove "
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
                        for item in unique
                    ],
                    "remediation": remediation,
                }
            )

        if exposed and privileged:
            append_candidate(
                "exposure-to-privilege",
                "Internet exposure combined with privileged identity risk",
                (
                    "The same AWS account contains an internet-exposed finding and "
                    "a privileged IAM finding. If the exposed workload is compromised, "
                    "excessive privileges can increase blast radius."
                ),
                (
                    "Reduce public exposure first, then remove unnecessary administrative "
                    "permissions and validate workload identity boundaries."
                ),
                [exposed[0], privileged[0]],
            )
        if exposed and sensitive:
            append_candidate(
                "exposure-to-sensitive-data",
                "Internet exposure combined with sensitive-data risk",
                (
                    "The account contains both an internet-exposed finding and a "
                    "sensitive-data finding, increasing potential impact if an exposed "
                    "entry point is compromised."
                ),
                (
                    "Restrict public access, validate segmentation and access paths, "
                    "then rotate or harden the affected sensitive data controls."
                ),
                [exposed[0], sensitive[0]],
            )

        critical = sorted(
            (item for item in account_findings if item.severity.value == "critical"),
            key=lambda item: item.risk.score,
            reverse=True,
        )
        if len(critical) >= 2:
            append_candidate(
                "critical-risk-cluster",
                "Multiple critical risks concentrated in one AWS account",
                (
                    "Several independent critical findings are concentrated in the same "
                    "AWS account. This increases operational blast radius even when a "
                    "direct exploit chain has not been proven."
                ),
                (
                    "Treat the account as a priority remediation scope, starting with "
                    "internet exposure and privileged identities before lower-impact issues."
                ),
                critical[:3],
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
