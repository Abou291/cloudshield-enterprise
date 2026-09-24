"""Private loopback entry point used by the packaged desktop application."""

import os

import uvicorn

from app.main import app


def main() -> None:
    """Start AegisShield only on loopback; never expose a desktop install to a LAN."""
    port = int(os.environ.get("AEGISSHIELD_PORT", "8765"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


if __name__ == "__main__":
    main()
