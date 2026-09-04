import os

import jwt
from fastapi import HTTPException


PUBLIC_KEY_PATH = os.environ["WORKLOAD_PUBLIC_KEY_PATH"]

EXPECTED_ISSUER = "agent-security-poc"
EXPECTED_AUDIENCE = "policy-gateway"

# Gateway-controlled mapping:
# cryptographic key ID -> authenticated workload identity
WORKLOAD_BY_KEY_ID = {
    "crm-agent-key-v1": "crm-agent"
}


with open(PUBLIC_KEY_PATH, "r", encoding="utf-8") as key_file:
    PUBLIC_KEY = key_file.read()


def authenticate_workload(authorization: str | None) -> str:

    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="MISSING_WORKLOAD_TOKEN"
        )

    scheme, separator, token = authorization.partition(" ")

    if (
        separator != " "
        or scheme.lower() != "bearer"
        or not token
    ):
        raise HTTPException(
            status_code=401,
            detail="INVALID_AUTHORIZATION_HEADER"
        )

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=401,
            detail="INVALID_WORKLOAD_TOKEN"
        ) from exc

    key_id = header.get("kid")
    authenticated_agent = WORKLOAD_BY_KEY_ID.get(key_id)

    if authenticated_agent is None:
        raise HTTPException(
            status_code=401,
            detail="UNKNOWN_WORKLOAD_KEY"
        )

    try:
        claims = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            issuer=EXPECTED_ISSUER,
            audience=EXPECTED_AUDIENCE,
            options={
                "require": [
                    "sub",
                    "iss",
                    "aud",
                    "iat",
                    "exp",
                    "jti"
                ]
            }
        )

    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=401,
            detail="EXPIRED_WORKLOAD_TOKEN"
        ) from exc

    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=401,
            detail="INVALID_WORKLOAD_TOKEN"
        ) from exc

    # The gateway key registry is authoritative.
    # A signed sub claim cannot override the identity assigned to the key.
    if claims["sub"] != authenticated_agent:
        raise HTTPException(
            status_code=401,
            detail="WORKLOAD_IDENTITY_MISMATCH"
        )

    return authenticated_agent