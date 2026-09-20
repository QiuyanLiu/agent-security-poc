import os
import threading
import time
from pathlib import Path
from typing import Any

import requests
import jwt
from fastapi import FastAPI, Header, HTTPException, Response

from salesforce_credentials import request_salesforce_token


app = FastAPI(
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

GATEWAY_PUBLIC_KEY_PATH = os.environ.get(
    "GATEWAY_PUBLIC_KEY_PATH",
    "/run/secrets/gateway-broker-public.pem",
)

EXPECTED_KEY_ID = os.environ.get(
    "BROKER_EXPECTED_KEY_ID",
    "gateway-broker-key-v1",
)

EXPECTED_SUBJECT = os.environ.get(
    "BROKER_EXPECTED_SUBJECT",
    "salesforce-gateway",
)

EXPECTED_ISSUER = os.environ.get(
    "BROKER_EXPECTED_ISSUER",
    "agent-security-gateway",
)

EXPECTED_AUDIENCE = os.environ.get(
    "BROKER_EXPECTED_AUDIENCE",
    "credential-broker",
)

_used_jti: dict[str, int] = {}
_jti_lock = threading.Lock()

TEST_MODE = os.environ.get(
    "TEST_MODE",
    "false",
).lower() == "true"

_salesforce_token_request_count = 0
_counter_lock = threading.Lock()


def authenticate_gateway(
    authorization: str | None,
) -> dict[str, Any]:
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing gateway token",
        )

    scheme, separator, token = authorization.partition(" ")

    if (
        separator != " "
        or scheme.lower() != "bearer"
        or not token
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header",
        )

    try:
        header = jwt.get_unverified_header(token)

        if header.get("alg") != "RS256":
            raise jwt.InvalidTokenError(
                "Unexpected JWT algorithm"
            )

        if header.get("kid") != EXPECTED_KEY_ID:
            raise jwt.InvalidTokenError(
                "Unexpected JWT key ID"
            )

        public_key = Path(
            GATEWAY_PUBLIC_KEY_PATH
        ).read_text(encoding="utf-8")

        claims = jwt.decode(
            token,
            public_key,
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
                    "jti",
                    "scope",
                ]
            },
        )

    except jwt.PyJWTError as error:
        raise HTTPException(
            status_code=401,
            detail="Invalid gateway token",
        ) from error

    if claims.get("sub") != EXPECTED_SUBJECT:
        raise HTTPException(
            status_code=403,
            detail="Gateway identity not allowed",
        )

    if claims.get("scope") != "salesforce:token":
        raise HTTPException(
            status_code=403,
            detail="Token scope not allowed",
        )

    jti = claims["jti"]
    expiration = claims["exp"]
    now = int(time.time())

    if not isinstance(jti, str) or not isinstance(expiration, int):
        raise HTTPException(
            status_code=401,
            detail="Invalid gateway token claims",
        )

    with _jti_lock:
        expired_entries = [
            stored_jti
            for stored_jti, stored_expiration
            in _used_jti.items()
            if stored_expiration <= now
        ]

        for stored_jti in expired_entries:
            del _used_jti[stored_jti]

        if jti in _used_jti:
            raise HTTPException(
                status_code=401,
                detail="Gateway token replay detected",
            )

        _used_jti[jti] = expiration

    return claims


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.get("/__test__/request-count")
def get_request_count() -> dict[str, int]:
    if not TEST_MODE:
        raise HTTPException(status_code=404)

    with _counter_lock:
        return {
            "request_count": _salesforce_token_request_count
        }


@app.post("/token/salesforce")
def issue_salesforce_token(
    response: Response,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    authenticate_gateway(authorization)

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"

    global _salesforce_token_request_count

    with _counter_lock:
        _salesforce_token_request_count += 1

    try:
        return request_salesforce_token()
    except requests.RequestException as error:
        raise HTTPException(
            status_code=502,
            detail="Salesforce token request failed",
        ) from error
