"""Private loopback entry point used by the packaged desktop application."""

import os
import sys

import uvicorn


def main() -> None:
    """Start AegisShield only on loopback; never expose a desktop install to a LAN."""
    if "--check-aws-login" in sys.argv:
        from app.services.aws_login_check import check_aws_login_runtime

        check_aws_login_runtime()
        print("AWS login runtime: CRT and isolated credential provider OK")
        return

    from app.main import app

    port = int(os.environ.get("AEGISSHIELD_PORT", "8765"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
