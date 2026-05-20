"""
API dependencies shared across routes.

Authentication validates the ``Authorization: Bearer <key>`` header against
the operator API key (``SRV_API_KEY`` environment variable).  An absent or
incorrect key yields 401 so that only authorised operators can query the
honeypot management API.

Note: This is the *operator-facing* auth layer.  The attacker-facing
``HoneypotAuth`` in ``core/auth.py`` is intentionally permissive (all
requests are observed, never blocked).
"""

from __future__ import annotations

import hmac
import os
import secrets

from fastapi import Header, HTTPException

# Resolve once at import time; crashes loudly if not set.
# The honeypot MUST have an operator key — no silent no-auth mode.
_OPERATOR_API_KEY: str = os.environ.get("SRV_API_KEY", "")


async def require_auth(authorization: str | None = Header(None)) -> str:
    """Require a valid ``Authorization: Bearer <key>`` header.

    Validates the provided key against ``SRV_API_KEY`` using a
    constant-time comparison to prevent timing side-channels.

    Raises:
        HTTPException(401): When the header is missing or the key is invalid.
    """
    if not _OPERATOR_API_KEY:
        # Key is not configured — fail closed.
        raise HTTPException(
            status_code=503,
            detail="Operator API key not configured.",
        )

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization header required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Extract Bearer token (accept both "Bearer <key>" and raw key).
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() == "bearer":
        provided_key = token.strip()
    else:
        provided_key = authorization.strip()

    # Constant-time comparison prevents timing oracle attacks.
    if not provided_key or not hmac.compare_digest(
        provided_key.encode(), _OPERATOR_API_KEY.encode()
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return provided_key
