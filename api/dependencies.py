"""
API dependencies shared across routes.
"""

from __future__ import annotations

from fastapi import Header, HTTPException


async def require_auth(authorization: str | None = Header(None)) -> str:
    """Require authentication header."""
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")
    return authorization
