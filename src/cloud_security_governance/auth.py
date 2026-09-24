"""Constant-time bearer-token authentication and role authorization."""

from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from enum import StrEnum

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer


class Role(StrEnum):
    READER = "reader"
    OPERATOR = "operator"


@dataclass(frozen=True)
class Principal:
    subject: str
    role: Role


class TokenAuthenticator:
    """Authenticate opaque tokens sourced only from deployment secrets."""

    def __init__(self, reader_token: str | None = None, operator_token: str | None = None) -> None:
        resolved_reader = reader_token or os.getenv("API_READER_TOKEN")
        resolved_operator = operator_token or os.getenv("API_OPERATOR_TOKEN")
        configured = [token for token in (resolved_reader, resolved_operator) if token]
        if any(len(token) < 32 for token in configured):
            raise ValueError("API tokens must contain at least 32 characters")
        if resolved_reader and hmac.compare_digest(resolved_reader, resolved_operator or ""):
            raise ValueError("Reader and operator API tokens must be different")
        self._tokens = tuple(
            item
            for item in (
                (
                    resolved_reader,
                    Principal("api-reader", Role.READER),
                ),
                (
                    resolved_operator,
                    Principal("api-operator", Role.OPERATOR),
                ),
            )
            if item[0]
        )

    def authenticate(self, token: str) -> Principal:
        for expected, principal in self._tokens:
            if hmac.compare_digest(token.encode(), expected.encode()):
                return principal
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )


bearer = HTTPBearer(auto_error=False)


def authenticated_principal(
    request: Request, credentials: HTTPAuthorizationCredentials | None
) -> Principal:
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return request.app.state.authenticator.authenticate(credentials.credentials)


def authorize(principal: Principal, *roles: Role) -> Principal:
    if principal.role not in roles:
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return principal
