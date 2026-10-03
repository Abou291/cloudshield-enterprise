from __future__ import annotations

import shlex
from typing import Literal

from pydantic import BaseModel, Field

from app.core.domain import Finding


class RemediationStep(BaseModel):
    title: str
    description: str
    command: str | None = None
    command_type: Literal["aws-cli", "terraform", "manual"] = "manual"
    destructive: bool = False


class RemediationPlan(BaseModel):
    rule_id: str
    fingerprint: str
    mode: Literal["guided"] = "guided"
    automatic_execution: bool = False
    requires_human_approval: bool = True
    impact: str
    verification: str
    rollback: str
    steps: list[RemediationStep] = Field(min_length=1)


def _q(value: str) -> str:
    return shlex.quote(value)


def build_remediation_plan(finding: Finding) -> RemediationPlan:
    """Return deterministic, reviewable guidance. Never executes cloud changes."""
    rid = finding.rule_id
    resource = finding.resource_id

    if rid == "NET-001":
        group_id = resource.split(":", 1)[0]
        evidence = finding.evidence
        cidr = str(evidence.get("cidr", evidence.get("cidr_ip", "0.0.0.0/0")))
        protocol = str(evidence.get("protocol", "tcp"))
        from_port = evidence.get("from_port")
        to_port = evidence.get("to_port", from_port)
        port_args = ""
        if isinstance(from_port, int):
            port_args = f" --port {from_port}" if from_port == to_port else f" --from-port {from_port} --to-port {to_port}"
        command = (
            "aws ec2 revoke-security-group-ingress"
            f" --group-id {_q(group_id)} --protocol {_q(protocol)}{port_args}"
            f" --cidr {_q(cidr)}"
        )
        return RemediationPlan(
            rule_id=rid,
            fingerprint=finding.fingerprint,
            impact="Removes the detected world-accessible ingress rule. Validate legitimate administrator or application access first.",
            verification=f"Rescan the account and verify that {group_id} no longer permits world access on the affected port.",
            rollback="Re-add the previous ingress rule only from an approved CIDR if legitimate access was interrupted.",
            steps=[
                RemediationStep(
                    title="Review affected ingress",
                    description="Confirm the rule is not required for a documented public service.",
                ),
                RemediationStep(
                    title="Revoke world-accessible ingress",
                    description="Run only after review. Prefer a change request or infrastructure-as-code workflow in production.",
                    command=command,
                    command_type="aws-cli",
                    destructive=True,
                ),
            ],
        )

    if rid == "S3-001":
        bucket = resource.removeprefix("arn:aws:s3:::")
        command = (
            "aws s3api put-public-access-block"
            f" --bucket {_q(bucket)}"
            " --public-access-block-configuration"
            " BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        )
        return RemediationPlan(
            rule_id=rid,
            fingerprint=finding.fingerprint,
            impact="Blocks public ACLs and public bucket policies. Public websites or intentional public distribution can be affected.",
            verification=f"Run aws s3api get-public-access-block --bucket {_q(bucket)} and rescan CloudShield.",
            rollback="Restore only the explicitly documented public-access settings after security review.",
            steps=[
                RemediationStep(
                    title="Confirm public access is unintended",
                    description="Check application ownership and whether CloudFront or another controlled distribution path is used.",
                ),
                RemediationStep(
                    title="Enable S3 Block Public Access",
                    description="Apply all four S3 public-access-block controls after approval.",
                    command=command,
                    command_type="aws-cli",
                    destructive=True,
                ),
            ],
        )

    if rid == "IAM-003":
        username = resource.rsplit("/", 1)[-1]
        return RemediationPlan(
            rule_id=rid,
            fingerprint=finding.fingerprint,
            impact="Rotating or disabling an access key can break workloads that still depend on it.",
            verification=f"Confirm the user {_q(username)} has no old active key and rescan CloudShield.",
            rollback="If a workload fails, restore service with a newly issued least-privilege credential; do not reactivate an untrusted key.",
            steps=[
                RemediationStep(
                    title="Identify key usage",
                    description="Use IAM credential reports and CloudTrail to confirm whether the key is still required.",
                ),
                RemediationStep(
                    title="Rotate safely",
                    description="Create a replacement only if needed, update the workload, verify it, then deactivate and delete the old key.",
                ),
            ],
        )

    return RemediationPlan(
        rule_id=rid,
        fingerprint=finding.fingerprint,
        impact="The exact production impact depends on this resource and its consumers.",
        verification="Apply the reviewed change in a controlled environment, then rescan CloudShield and confirm the finding is resolved.",
        rollback="Keep the previous infrastructure-as-code revision or configuration so the approved change can be reverted.",
        steps=[
            RemediationStep(
                title="Review recommendation",
                description=finding.recommendation,
            ),
            RemediationStep(
                title="Apply through change control",
                description="Prefer Terraform/CloudFormation or a reviewed change request. CloudShield does not execute this change automatically.",
            ),
        ],
    )
