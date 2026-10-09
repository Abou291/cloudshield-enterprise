"""Rule-based detectors over normalised events.

Every detector is a pure function so it can be tested without AWS. Detectors are
deliberately conservative: they describe an observed API fact and its usual meaning, and
never claim that an intrusion happened.
"""

from collections import defaultdict
from collections.abc import Callable, Iterable
from datetime import timedelta
from typing import Any

from app.monitoring.events import Alert, SecurityEvent

FAILED_LOGIN_THRESHOLD = 5
FAILED_LOGIN_WINDOW = timedelta(minutes=10)
ACCESS_DENIED_THRESHOLD = 20
ACCESS_DENIED_WINDOW = timedelta(minutes=10)
MASS_LAUNCH_COUNT = 10
BASELINE_MAX_IPS = 20

DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "Client.UnauthorizedOperation",
}

TAMPERING_EVENTS = {
    "StopLogging": "CloudTrail logging was stopped",
    "DeleteTrail": "A CloudTrail trail was deleted",
    "UpdateTrail": "A CloudTrail trail was modified",
    "PutEventSelectors": "CloudTrail event selectors were changed",
    "DeleteDetector": "A GuardDuty detector was deleted",
    "UpdateDetector": "A GuardDuty detector was modified",
    "DisableOrganizationAdminAccount": "A delegated security administrator was removed",
    "DisableSecurityHub": "Security Hub was disabled",
    "StopConfigurationRecorder": "AWS Config recording was stopped",
    "DeleteConfigurationRecorder": "The AWS Config recorder was deleted",
    "DeleteFlowLogs": "VPC flow logs were deleted",
}

ADMIN_POLICY_EVENTS = {"AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"}
PERSISTENCE_EVENTS = {
    "CreateUser": "An IAM user was created",
    "CreateLoginProfile": "A console password was created for an IAM user",
    "UpdateLoginProfile": "A console password was changed for an IAM user",
    "UpdateAssumeRolePolicy": "A role trust policy was changed",
}
INLINE_POLICY_EVENTS = {"PutUserPolicy", "PutRolePolicy", "PutGroupPolicy", "CreatePolicyVersion"}

GPU_OR_HUGE_PREFIXES = ("p3", "p4", "p5", "g4", "g5", "g6", "inf", "trn")
HUGE_SUFFIXES = (
    ".8xlarge",
    ".12xlarge",
    ".16xlarge",
    ".24xlarge",
    ".32xlarge",
    ".48xlarge",
    ".metal",
)


def _ok(event: SecurityEvent) -> bool:
    return event.error_code is None


def _alert(
    event: SecurityEvent,
    rule_id: str,
    title: str,
    severity: str,
    summary: str,
    *,
    dedupe: str | None = None,
    details: dict[str, Any] | None = None,
) -> Alert:
    return Alert(
        rule_id=rule_id,
        title=title,
        severity=severity,
        occurred_at=event.time,
        principal=event.principal_key,
        source_ip=event.source_ip,
        region=event.region,
        summary=summary,
        dedupe_key=dedupe or event.event_id,
        event_ids=(event.event_id,),
        details=details or {},
    )


def detect_root_activity(events: Iterable[SecurityEvent]) -> list[Alert]:
    alerts = []
    for event in events:
        if event.principal_type != "Root":
            continue
        if event.name == "ConsoleLogin" and event.console_login == "Success":
            alerts.append(
                _alert(
                    event,
                    "DET-001",
                    "Root account console login",
                    "critical",
                    "The AWS root user signed in to the console.",
                )
            )
        elif event.name != "ConsoleLogin":
            alerts.append(
                _alert(
                    event,
                    "DET-001",
                    "Root account activity",
                    "high",
                    f"The AWS root user called {event.name}.",
                )
            )
    return alerts


def detect_console_login_without_mfa(events: Iterable[SecurityEvent]) -> list[Alert]:
    return [
        _alert(
            event,
            "DET-002",
            "Console login without MFA",
            "high",
            f"IAM user {event.principal_name or 'unknown'} signed in without MFA.",
        )
        for event in events
        if event.name == "ConsoleLogin"
        and event.principal_type == "IAMUser"
        and event.console_login == "Success"
        and event.mfa_used is False
    ]


def detect_failed_login_bursts(events: Iterable[SecurityEvent]) -> list[Alert]:
    logins = sorted(
        (
            e
            for e in events
            if e.name == "ConsoleLogin" and e.console_login in {"Success", "Failure"}
        ),
        key=lambda e: e.time,
    )
    failures: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
    for event in logins:
        if event.console_login == "Failure":
            failures[(event.principal_name, event.source_ip)].append(event)

    alerts = []
    for (user, ip), items in failures.items():
        start = 0
        for end, last in enumerate(items):
            while last.time - items[start].time > FAILED_LOGIN_WINDOW:
                start += 1
            window = items[start : end + 1]
            if len(window) < FAILED_LOGIN_THRESHOLD:
                continue
            success_after = any(
                e.console_login == "Success"
                and e.principal_name == user
                and e.source_ip == ip
                and e.time >= window[-1].time
                for e in logins
            )
            alerts.append(
                Alert(
                    rule_id="DET-003",
                    title=(
                        "Repeated failed console logins followed by a success"
                        if success_after
                        else "Repeated failed console logins"
                    ),
                    severity="critical" if success_after else "medium",
                    occurred_at=window[-1].time,
                    principal=user or "unknown",
                    source_ip=ip,
                    region=window[-1].region,
                    summary=(
                        f"{len(window)} failed console logins for {user or 'unknown'} from {ip} "
                        f"within {int(FAILED_LOGIN_WINDOW.total_seconds() // 60)} minutes"
                        + (", then a successful login." if success_after else ".")
                    ),
                    dedupe_key=f"{user}|{ip}|{items[0].time.strftime('%Y%m%d%H')}",
                    event_ids=tuple(e.event_id for e in window),
                    details={"failures": len(window), "success_after": success_after},
                )
            )
            break
    return alerts


def detect_security_tampering(events: Iterable[SecurityEvent]) -> list[Alert]:
    return [
        _alert(
            event,
            "DET-004",
            "Security control changed or disabled",
            "critical",
            f"{TAMPERING_EVENTS[event.name]} by {event.principal_key}.",
            details={"event": event.name},
        )
        for event in events
        if event.name in TAMPERING_EVENTS and _ok(event)
    ]


def detect_iam_persistence(events: Iterable[SecurityEvent]) -> list[Alert]:
    alerts = []
    for event in events:
        if not _ok(event):
            continue
        if event.name in ADMIN_POLICY_EVENTS and str(event.params.get("policyArn", "")).endswith(
            "/AdministratorAccess"
        ):
            target = event.params.get("userName") or event.params.get("roleName") or "a principal"
            alerts.append(
                _alert(
                    event,
                    "DET-005",
                    "AdministratorAccess granted",
                    "critical",
                    f"AdministratorAccess was attached to {target} by {event.principal_key}.",
                    details={"target": str(target)},
                )
            )
        elif event.name in PERSISTENCE_EVENTS:
            alerts.append(
                _alert(
                    event,
                    "DET-005",
                    "IAM persistence change",
                    "high",
                    f"{PERSISTENCE_EVENTS[event.name]} by {event.principal_key}.",
                    details={"event": event.name},
                )
            )
        elif event.name == "CreateAccessKey":
            target = event.params.get("userName")
            if target and target != event.principal_name:
                alerts.append(
                    _alert(
                        event,
                        "DET-005",
                        "Access key created for another user",
                        "high",
                        f"{event.principal_key} created an access key for {target}.",
                        details={"target": str(target)},
                    )
                )
        elif event.name in INLINE_POLICY_EVENTS:
            alerts.append(
                _alert(
                    event,
                    "DET-005",
                    "IAM policy written",
                    "medium",
                    f"{event.name} by {event.principal_key}.",
                    details={"event": event.name},
                )
            )
    return alerts


def _launch_profile(event: SecurityEvent) -> tuple[int, str]:
    items = event.params.get("instancesSet", {}).get("items", [])
    count = 0
    if isinstance(items, list):
        for item in items:
            if isinstance(item, dict):
                value = item.get("maxCount", item.get("minCount", 1))
                count += value if isinstance(value, int) else 1
    instance_type = str(event.params.get("instanceType", ""))
    return count, instance_type


def detect_mass_or_gpu_launch(events: Iterable[SecurityEvent]) -> list[Alert]:
    alerts = []
    for event in events:
        if event.name != "RunInstances" or not _ok(event):
            continue
        count, instance_type = _launch_profile(event)
        heavy = instance_type.startswith(GPU_OR_HUGE_PREFIXES) or instance_type.endswith(
            HUGE_SUFFIXES
        )
        if count >= MASS_LAUNCH_COUNT or heavy:
            alerts.append(
                _alert(
                    event,
                    "DET-006",
                    "Unusual compute launch",
                    "high",
                    (
                        f"{count or 'Several'} instance(s) of type {instance_type or 'unknown'} "
                        f"launched by {event.principal_key}. Mass or GPU launches are a common "
                        "sign of cryptocurrency mining with stolen credentials."
                    ),
                    details={"count": count, "instance_type": instance_type},
                )
            )
    return alerts


def _opens_world(permissions: object) -> bool:
    items = permissions.get("items", []) if isinstance(permissions, dict) else []
    for permission in items if isinstance(items, list) else []:
        if not isinstance(permission, dict):
            continue
        for key, field_name in (("ipRanges", "cidrIp"), ("ipv6Ranges", "cidrIpv6")):
            ranges = permission.get(key, {})
            ranges = ranges.get("items", []) if isinstance(ranges, dict) else []
            if any(
                isinstance(r, dict) and r.get(field_name) in {"0.0.0.0/0", "::/0"} for r in ranges
            ):
                return True
    return False


def detect_exposure_changes(events: Iterable[SecurityEvent]) -> list[Alert]:
    alerts = []
    for event in events:
        if not _ok(event):
            continue
        name, params = event.name, event.params
        if name == "AuthorizeSecurityGroupIngress" and _opens_world(params.get("ipPermissions")):
            alerts.append(
                _alert(
                    event,
                    "DET-007",
                    "Security group opened to the Internet",
                    "high",
                    f"{event.principal_key} opened a security group to 0.0.0.0/0 or ::/0.",
                )
            )
        elif name == "ModifySnapshotAttribute" and _shares_with_all(
            params.get("createVolumePermission")
        ):
            alerts.append(
                _alert(
                    event,
                    "DET-007",
                    "EBS snapshot shared publicly",
                    "critical",
                    f"{event.principal_key} made an EBS snapshot restorable by any AWS account.",
                )
            )
        elif name == "ModifyDBSnapshotAttribute" and "all" in str(params.get("valuesToAdd", "")):
            alerts.append(
                _alert(
                    event,
                    "DET-007",
                    "RDS snapshot shared publicly",
                    "critical",
                    f"{event.principal_key} made an RDS snapshot public.",
                )
            )
        elif name in {"PutPublicAccessBlock", "PutAccountPublicAccessBlock"} and _weakens_block(
            params
        ):
            alerts.append(
                _alert(
                    event,
                    "DET-007",
                    "S3 Block Public Access weakened",
                    "high",
                    f"{event.principal_key} turned off part of S3 Block Public Access.",
                )
            )
        elif name in {"DeletePublicAccessBlock", "DeleteBucketPublicAccessBlock"}:
            alerts.append(
                _alert(
                    event,
                    "DET-007",
                    "S3 Block Public Access removed",
                    "high",
                    f"{event.principal_key} removed an S3 Block Public Access configuration.",
                )
            )
        elif name == "ModifyDBInstance" and params.get("publiclyAccessible") is True:
            alerts.append(
                _alert(
                    event,
                    "DET-007",
                    "RDS instance made public",
                    "high",
                    f"{event.principal_key} made an RDS instance publicly accessible.",
                )
            )
    return alerts


def _shares_with_all(permission: object) -> bool:
    add = permission.get("add", {}) if isinstance(permission, dict) else {}
    items = add.get("items", []) if isinstance(add, dict) else []
    return any(isinstance(i, dict) and i.get("group") == "all" for i in items)


def _weakens_block(params: dict[str, Any]) -> bool:
    configuration = params.get("PublicAccessBlockConfiguration")
    if not isinstance(configuration, dict):
        return False
    return any(value is False for value in configuration.values())


def detect_access_denied_bursts(events: Iterable[SecurityEvent]) -> list[Alert]:
    denied: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in sorted(events, key=lambda e: e.time):
        if event.error_code in DENIED_CODES:
            denied[event.principal_key].append(event)
    alerts = []
    for principal, items in denied.items():
        start = 0
        for end, last in enumerate(items):
            while last.time - items[start].time > ACCESS_DENIED_WINDOW:
                start += 1
            window = items[start : end + 1]
            if len(window) < ACCESS_DENIED_THRESHOLD:
                continue
            alerts.append(
                Alert(
                    rule_id="DET-009",
                    title="Burst of denied API calls",
                    severity="medium",
                    occurred_at=window[-1].time,
                    principal=principal,
                    source_ip=window[-1].source_ip,
                    region=window[-1].region,
                    summary=(
                        f"{len(window)} denied API calls by {principal} within "
                        f"{int(ACCESS_DENIED_WINDOW.total_seconds() // 60)} minutes: a possible "
                        "permission probe, or a broken automation."
                    ),
                    dedupe_key=f"{principal}|{items[0].time.strftime('%Y%m%d%H')}",
                    event_ids=tuple(e.event_id for e in window[:50]),
                    details={"denied_calls": len(window)},
                )
            )
            break
    return alerts


def detect_new_login_sources(
    events: Iterable[SecurityEvent], baseline: dict[str, list[str]]
) -> tuple[list[Alert], dict[str, list[str]]]:
    """Alert when a user known from earlier logins signs in from an unseen IP address.

    The first login ever seen for a user only teaches the baseline. Addresses are not
    geolocated: a new address can be a new network, a VPN or a mobile connection.
    """
    learned = {user: list(ips) for user, ips in baseline.items()}
    alerts = []
    logins = sorted(
        (
            e
            for e in events
            if e.name == "ConsoleLogin"
            and e.console_login == "Success"
            and e.principal_type == "IAMUser"
            and e.principal_name
            and e.source_ip
        ),
        key=lambda e: e.time,
    )
    for event in logins:
        known = learned.setdefault(event.principal_name, [])
        if event.source_ip in known:
            continue
        if known:
            alerts.append(
                _alert(
                    event,
                    "DET-008",
                    "Console login from a new address",
                    "medium",
                    (
                        f"{event.principal_name} signed in from {event.source_ip}, an address not "
                        "seen in previous logins."
                    ),
                    dedupe=f"{event.principal_name}|{event.source_ip}",
                )
            )
        known.append(event.source_ip)
        del known[:-BASELINE_MAX_IPS]
    return alerts, learned


Detector = Callable[[Iterable[SecurityEvent]], list[Alert]]

STATELESS_DETECTORS: tuple[Detector, ...] = (
    detect_root_activity,
    detect_console_login_without_mfa,
    detect_failed_login_bursts,
    detect_security_tampering,
    detect_iam_persistence,
    detect_mass_or_gpu_launch,
    detect_exposure_changes,
    detect_access_denied_bursts,
)


def run_detectors(
    events: list[SecurityEvent], baseline: dict[str, list[str]] | None = None
) -> tuple[list[Alert], dict[str, list[str]]]:
    alerts: list[Alert] = []
    for detector in STATELESS_DETECTORS:
        alerts.extend(detector(events))
    login_alerts, learned = detect_new_login_sources(events, baseline or {})
    alerts.extend(login_alerts)
    return alerts, learned
