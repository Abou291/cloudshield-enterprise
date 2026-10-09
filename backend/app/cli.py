"""Offline read-only AWS scan: ``python -m app.cli --profile lab --output report.json``.

Runs the same collectors, context enrichment, rule engine and report builders as the API,
without a database. Meant to produce reproducible evidence from a real account, for example
to validate detections against the deliberately misconfigured stack in
``infra/aws/validation-lab.yaml``.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

from app.core.domain import Finding
from app.scanners.aws import AwsInventoryProvider
from app.services.compliance import build_compliance_posture
from app.services.context import enrich_context
from app.services.reporting import build_attack_paths, build_executive_summary
from app.services.rules import RuleEngine

RULES_DIR = Path(__file__).resolve().parent / "rules"


def _pseudonym(value: str) -> str:
    return "anon-" + hashlib.sha256(value.encode()).hexdigest()[:10]


def anonymize(findings: list[Finding]) -> list[Finding]:
    """Replace account ids and resource identifiers by stable hashes (rule ids are kept)."""
    result = []
    for finding in findings:
        data = finding.model_copy(deep=True)
        data.account_id = _pseudonym(finding.account_id)
        data.resource_id = _pseudonym(finding.resource_id)
        data.evidence = {}
        result.append(data)
    return result


def check_expectations(findings: list[Finding], expected: set[str]) -> tuple[set[str], set[str]]:
    """Return (missing, unexpected) rule ids compared with the expected set."""
    seen = {item.rule_id for item in findings}
    return expected - seen, seen - expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", default="eu-west-3")
    parser.add_argument("--profile")
    parser.add_argument("--role-arn")
    parser.add_argument("--external-id")
    parser.add_argument("--account-id", help="Abort if the credentials belong to another account")
    parser.add_argument("--all-regions", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--anonymize", action="store_true", help="Hash account and resource ids")
    parser.add_argument(
        "--expect",
        help="Comma-separated rule ids that must be found; exit 1 if one is missing",
    )
    args = parser.parse_args(argv)

    provider = AwsInventoryProvider(
        args.region,
        args.role_arn,
        args.external_id,
        args.account_id,
        args.profile,
        args.all_regions,
    )
    assets = provider.collect()
    context_stats = enrich_context(assets)
    findings = RuleEngine.from_directory(RULES_DIR).evaluate(assets)
    gaps = sorted(
        asset.attributes.get("service", asset.name)
        for asset in assets
        if asset.resource_type == "coverage_gap"
    )
    published = anonymize(findings) if args.anonymize else findings
    report = {
        "schema": "aegisshield.offline-scan.v1",
        "anonymized": args.anonymize,
        "assets_scanned": len(assets),
        "context_coverage": context_stats,
        "coverage_gaps": gaps,
        "executive_summary": build_executive_summary(published),
        "attack_paths": build_attack_paths(published),
        "compliance": build_compliance_posture(published),
        "findings": [item.model_dump(mode="json") for item in published],
    }
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(
        f"{len(assets)} assets, {len(findings)} findings, "
        f"{len(gaps)} coverage gaps -> {args.output}"
    )

    if args.expect:
        expected = {item.strip() for item in args.expect.split(",") if item.strip()}
        missing, unexpected = check_expectations(findings, expected)
        if missing:
            print(f"MISSING expected detections: {sorted(missing)}", file=sys.stderr)
        if unexpected:
            print(f"Additional detections (not an error): {sorted(unexpected)}")
        return 1 if missing else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
