"""Offline packaging check using synthetic data; never reads a user's credentials."""

from datetime import UTC, datetime, timedelta

from botocore.credentials import LoginProvider, LoginTokenLoader


def check_aws_login_runtime() -> None:
    session_name = "arn:aws:iam::123456789012:user/packaging-test"
    cache: dict = {}
    LoginTokenLoader(cache).save_token(session_name, {
        "accessToken": {
            "accessKeyId": "synthetic-access-key",
            "secretAccessKey": "synthetic-secret",
            "sessionToken": "synthetic-session-token",
            "accountId": "123456789012",
            "expiresAt": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
        },
        "refreshToken": "synthetic-refresh",
        "dpopKey": "synthetic-dpop",
        "clientId": "synthetic-client",
    })

    def no_network(*args, **kwargs):
        raise RuntimeError("The offline login check must never contact AWS")

    provider = LoginProvider(
        load_config=lambda: {"profiles": {"check": {"login_session": session_name}}},
        client_creator=no_network,
        profile_name="check",
        token_cache=cache,
    )
    credentials = provider.load().get_frozen_credentials()
    if credentials.access_key != "synthetic-access-key":
        raise RuntimeError("AWS login provider did not load the isolated test cache")
