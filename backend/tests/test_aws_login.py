from botocore.exceptions import LoginTokenLoadError, MissingDependencyException

from app.services.aws_login_check import check_aws_login_runtime
from app.services.diagnostics import classify_aws_error


def test_aws_login_runtime_loads_isolated_cache():
    check_aws_login_runtime()


def test_missing_crt_has_actionable_diagnostic():
    code, message = classify_aws_error(MissingDependencyException(msg="private detail"))
    assert code == "AWS_LOGIN_COMPONENT_MISSING"
    assert "private detail" not in message


def test_missing_login_cache_requests_reauthentication():
    code, message = classify_aws_error(LoginTokenLoadError(error_msg="private detail"))
    assert code == "AWS_LOGIN_REQUIRED"
    assert "aws login" in message
    assert "private detail" not in message
