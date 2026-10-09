"""Glue between a configured AWS connection and a MonitorService."""

from collections.abc import Callable
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.config import AwsConnection, Settings
from app.monitoring.notify import validate_webhook_url
from app.monitoring.service import MonitorService
from app.monitoring.sources import (
    fetch_cloudtrail_events,
    fetch_guardduty_alerts,
    monitored_regions,
)
from app.scanners.aws import AwsInventoryProvider


def provider_for(connection: AwsConnection) -> AwsInventoryProvider:
    return AwsInventoryProvider(
        connection.region,
        connection.role_arn,
        connection.external_id,
        connection.account_id,
        connection.profile_name,
        connection.scan_all_regions,
    )


def build_service(
    db: Session,
    tenant_id: str,
    connection: AwsConnection,
    settings: Settings,
    provider_factory: Callable[[AwsConnection], AwsInventoryProvider] = provider_for,
) -> MonitorService:
    provider = provider_factory(connection)
    regions = monitored_regions(connection.region)

    def client(service: str, region: str):
        return provider.client(service, region)

    def events(start: datetime, end: datetime):
        return fetch_cloudtrail_events(client, regions, start, end)

    def alerts(since: datetime):
        return fetch_guardduty_alerts(client, connection.region, since)

    webhook = settings.monitor_webhook_url
    if webhook:
        validate_webhook_url(webhook)
    return MonitorService(db, tenant_id, events, alerts, webhook)
