# Continuous monitoring

AegisShield can watch an AWS account between scans and raise alerts on suspicious
behaviour. It is **read-only** and detective: it never blocks, changes or deletes anything.

## What it does

Every cycle (default 15 minutes) the monitor:

1. reads recent CloudTrail management events (`LookupEvents`, home region + `us-east-1`,
   where IAM and console sign-in events are recorded);
2. ingests recent GuardDuty findings, if GuardDuty is enabled;
3. runs the behaviour detectors below;
4. stores each alert once (deduplicated by a stable alert id, so overlapping windows and
   restarts never create duplicates);
5. sends only the *new* alerts to the webhook, if configured.

| Id | Detects | Severity |
|----|---------|----------|
| DET-001 | Root account login or any root API activity | critical / high |
| DET-002 | Console login without MFA | high |
| DET-003 | Burst of failed console logins (5 in 10 min) | high |
| DET-004 | Logging/detection tampering (StopLogging, DeleteTrail, GuardDuty/Config changes...) | critical |
| DET-005 | IAM persistence (access keys, users, admin policy attached, inline policies) | high |
| DET-006 | Mass or GPU/very large instance launch (cost abuse, crypto-mining pattern) | high |
| DET-007 | Exposure changes (world-open security group, public snapshot, weakened public access block) | high |
| DET-009 | Burst of AccessDenied errors (20 in 10 min, permission probing) | medium |
| DET-008 | Console login from an address not seen before for that user | medium |
| GD-FINDING | Any GuardDuty finding (severity mapped from the GuardDuty score) | by score |

## Limits you should know

- CloudTrail `LookupEvents` shows management events only, with a delay of up to about
  15 minutes, and is rate limited. This is *near-real-time*, not real-time.
- Data events (S3 object reads, for example) are not covered.
- DET-008 compares IP addresses only; it does not geolocate. A VPN or mobile network can
  cause a legitimate alert. The first login of a user only teaches the baseline.
- If every source fails in a cycle the monitor reports `error`, keeps its cursor and retries;
  partial failures are reported as `partial` with the failing source listed.
- If the schedule is missed for three intervals the health screen shows `stale`.
- These detectors are heuristics validated on synthetic events in unit tests. They have not
  yet been validated against a live account generating the behaviours.

## Running it

Set an AWS connection (as for scans), then either use the *Run now* button (Monitoring panel)
or run the background worker:

```bash
python -m app.monitoring.worker            # loops every CLOUDSHIELD_MONITOR_INTERVAL_SECONDS
docker compose --profile monitoring up monitor
```

Settings:

| Variable | Default | Meaning |
|----------|---------|---------|
| `CLOUDSHIELD_MONITOR_INTERVAL_SECONDS` | 900 | Cycle interval (60-86400) |
| `CLOUDSHIELD_MONITOR_WEBHOOK_URL` | unset | HTTPS webhook (Slack/Teams/Discord-compatible JSON `{"text": ..., "alerts": [...]}`) |

Webhooks must use HTTPS (plain HTTP only for localhost). A failing webhook never stops
monitoring; the alert stays stored and unnotified.

## API

- `GET /api/v1/monitoring/status` - health, last run, open alerts, collection gaps
- `GET /api/v1/monitoring/alerts?status=open|acknowledged`
- `POST /api/v1/monitoring/alerts/{id}/ack` (operator)
- `POST /api/v1/monitoring/run` (operator) - run one cycle now
- `POST /api/v1/monitoring/test-webhook` (operator)

## Permissions

The read-only role (`infra/aws/aegisshield-readonly-role.yaml`) adds
`cloudtrail:LookupEvents`, `guardduty:ListFindings` and `guardduty:GetFindings`.
Update the CloudFormation stack for the monitor to see these sources.
