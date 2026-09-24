from app.core.config import AwsConnection
from app.services.desktop_connection import DesktopConnectionStore


def test_desktop_connection_persists_only_role_metadata(tmp_path):
    path = tmp_path / "connection.json"
    connection = AwsConnection(
        role_arn="arn:aws:iam::123456789012:role/aegisshield-readonly",
        external_id="unique-external-id",
        account_id="123456789012",
        region="eu-west-3",
        profile_name="company-sso",
    )

    store = DesktopConnectionStore(path)
    store.save(connection)

    assert store.get() == connection
    persisted = path.read_text(encoding="utf-8")
    assert "AccessKey" not in persisted
    assert "SecretAccessKey" not in persisted
    assert "company-sso" in persisted


def test_desktop_connection_missing_file_is_not_configured(tmp_path):
    assert DesktopConnectionStore(tmp_path / "missing.json").get() is None


def test_blank_profile_uses_default_credential_chain():
    connection = AwsConnection(
        role_arn="arn:aws:iam::123456789012:role/aegisshield-readonly",
        external_id="unique-external-id",
        account_id="123456789012",
        region="eu-west-3",
        profile_name="",
    )
    assert connection.profile_name is None
