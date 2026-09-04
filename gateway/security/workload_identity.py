from typing import Any

import jwt

from gateway.security.identity import (
    IdentityContext,
)
from gateway.security.workload_registry import (
    UnknownWorkloadKeyError,
    get_workload_registration,
    load_registered_public_key,
)


class WorkloadAuthenticationError(Exception):
    pass


def parse_requested_scopes(
    claims: dict[str, Any],
) -> frozenset[str]:
    raw_scope = claims.get("scope", "")

    if isinstance(raw_scope, str):
        return frozenset(
            scope
            for scope in raw_scope.split()
            if scope
        )

    if isinstance(raw_scope, list):
        return frozenset(
            str(scope)
            for scope in raw_scope
            if scope
        )

    raise WorkloadAuthenticationError(
        "INVALID_SCOPE_FORMAT"
    )


def authenticate_workload(
    *,
    token: str,
    expected_issuer: str,
    expected_audience: str,
) -> IdentityContext:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.InvalidTokenError as error:
        raise WorkloadAuthenticationError(
            "INVALID_WORKLOAD_TOKEN"
        ) from error

    key_id = header.get("kid")

    if not isinstance(key_id, str) or not key_id:
        raise WorkloadAuthenticationError(
            "MISSING_WORKLOAD_KEY_ID"
        )

    try:
        registration = get_workload_registration(
            key_id
        )
    except UnknownWorkloadKeyError as error:
        raise WorkloadAuthenticationError(
            "UNKNOWN_WORKLOAD_KEY"
        ) from error

    public_key = load_registered_public_key(
        registration
    )

    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=expected_audience,
            issuer=expected_issuer,
            options={
                "require": [
                    "sub",
                    "iss",
                    "aud",
                    "iat",
                    "exp",
                    "jti",
                ]
            },
        )
    except jwt.ExpiredSignatureError as error:
        raise WorkloadAuthenticationError(
            "WORKLOAD_TOKEN_EXPIRED"
        ) from error
    except jwt.InvalidAudienceError as error:
        raise WorkloadAuthenticationError(
            "INVALID_WORKLOAD_AUDIENCE"
        ) from error
    except jwt.InvalidIssuerError as error:
        raise WorkloadAuthenticationError(
            "INVALID_WORKLOAD_ISSUER"
        ) from error
    except jwt.InvalidSignatureError as error:
        raise WorkloadAuthenticationError(
            "INVALID_WORKLOAD_SIGNATURE"
        ) from error
    except jwt.InvalidTokenError as error:
        raise WorkloadAuthenticationError(
            "INVALID_WORKLOAD_TOKEN"
        ) from error

    token_workload_id = claims["sub"]

    if token_workload_id != registration.workload_id:
        raise WorkloadAuthenticationError(
            "WORKLOAD_IDENTITY_MISMATCH"
        )

    requested_scopes = parse_requested_scopes(
        claims
    )

    unauthorized_scopes = (
        requested_scopes
        - registration.allowed_scopes
    )

    if unauthorized_scopes:
        raise WorkloadAuthenticationError(
            "WORKLOAD_SCOPE_ESCALATION"
        )

    return IdentityContext(
        workload_id=registration.workload_id,
        issuer=claims["iss"],
        audience=claims["aud"],
        key_id=registration.key_id,
        token_id=claims["jti"],
        issued_at=claims["iat"],
        expires_at=claims["exp"],
        scopes=tuple(sorted(requested_scopes)),
    )