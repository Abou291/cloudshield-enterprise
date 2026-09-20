"""Server-selected tenant identity. API keys are random tokens, not user passwords."""

import hashlib
import hmac
from typing import Annotated

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.core.config import get_settings

bearer = HTTPBearer(auto_error=False)


class Principal(BaseModel):
    tenant_id: str
    subject: str
    role: str
    demo: bool = False


def authenticate(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    settings = get_settings()
    if settings.demo_mode:
        return Principal(tenant_id="demo", subject="local-demo", role="operator", demo=True)
    if credentials:
        digest = hashlib.sha256(credentials.credentials.encode()).hexdigest()
        for key in settings.api_keys:
            if hmac.compare_digest(digest, key.key_sha256):
                return Principal(tenant_id=key.tenant_id, subject=key.subject, role=key.role)
    raise HTTPException(401, "Valid API token required", headers={"WWW-Authenticate": "Bearer"})


Identity = Annotated[Principal, Depends(authenticate)]


def require_operator(principal: Identity) -> Principal:
    if principal.role != "operator":
        raise HTTPException(403, "Operator role required")
    return principal


Operator = Annotated[Principal, Depends(require_operator)]
