import os
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
import requests
from mcp.server import MCPServer


GATEWAY_URL = os.environ.get(
    "GATEWAY_URL",
    "http://gateway:8080",
)

PRIVATE_KEY_PATH = os.environ.get(
    "WORKLOAD_PRIVATE_KEY_PATH",
    "secrets/crm-agent-private.pem",
)

WORKLOAD_ID = os.environ["WORKLOAD_ID"]
WORKLOAD_KEY_ID = os.environ["WORKLOAD_KEY_ID"]

WORKLOAD_ISSUER = os.environ.get(
    "WORKLOAD_ISSUER",
    "agent-security-poc",
)

WORKLOAD_AUDIENCE = os.environ.get(
    "WORKLOAD_AUDIENCE",
    "agent-security-gateway",
)

WORKLOAD_TOKEN_TTL_SECONDS = int(
    os.environ.get(
        "WORKLOAD_TOKEN_TTL_SECONDS",
        "60",
    )
)

mcp = MCPServer("Salesforce Security POC")


def load_private_key() -> str:
    return Path(PRIVATE_KEY_PATH).read_text(encoding="utf-8")


def create_workload_token(scope: str) -> str:
    now = int(time.time())

    claims = {
        "sub": WORKLOAD_ID,
        "iss": WORKLOAD_ISSUER,
        "aud": WORKLOAD_AUDIENCE,
        "iat": now,
        "exp": now + WORKLOAD_TOKEN_TTL_SECONDS,
        "jti": str(uuid.uuid4()),
        "scope": scope,
    }

    return jwt.encode(
        claims,
        load_private_key(),
        algorithm="RS256",
        headers={
            "kid": WORKLOAD_KEY_ID,
            "typ": "JWT",
        },
    )


def call_gateway(
    request: dict[str, Any],
    required_scope: str,
) -> dict[str, Any]:
    token = create_workload_token(required_scope)

    response = requests.post(
        f"{GATEWAY_URL}/execute",
        json=request,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        timeout=15,
    )

    response.raise_for_status()
    return response.json()


@mcp.tool()
def get_account(account_id: str) -> dict[str, Any]:
    """Retrieve a Salesforce Account by its Account ID."""

    return call_gateway(
        request={
            "action": "get_account",
            "account_id": account_id,
        },
        required_scope="account:read",
    )


@mcp.tool()
def update_account_description(
    account_id: str,
    description: str,
) -> dict[str, Any]:
    """Update the description of a Salesforce Account."""

    return call_gateway(
        request={
            "action": "update_account_description",
            "account_id": account_id,
            "description": description,
        },
        required_scope="account:write",
    )


if __name__ == "__main__":
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=8000,
        json_response=True,
        stateless_http=True,
    )