import os
import re
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import jwt
import requests

from gateway.models.execution import BusinessRequest
from gateway.policy import PolicyDecision
from gateway.security.identity import IdentityContext


SF_DOMAIN = os.environ["SF_DOMAIN"].rstrip("/")

CREDENTIAL_BROKER_URL = os.environ.get(
    "CREDENTIAL_BROKER_URL",
    "http://credential_broker:8090",
).rstrip("/")

BROKER_PRIVATE_KEY_PATH = os.environ.get(
    "BROKER_PRIVATE_KEY_PATH",
    "/run/secrets/gateway-broker-private.pem",
)

BROKER_WORKLOAD_ID = os.environ.get(
    "BROKER_WORKLOAD_ID",
    "salesforce-gateway",
)

BROKER_KEY_ID = os.environ.get(
    "BROKER_KEY_ID",
    "gateway-broker-key-v1",
)

BROKER_TOKEN_ISSUER = os.environ.get(
    "BROKER_TOKEN_ISSUER",
    "agent-security-gateway",
)

BROKER_TOKEN_AUDIENCE = os.environ.get(
    "BROKER_TOKEN_AUDIENCE",
    "credential-broker",
)

BROKER_TOKEN_TTL_SECONDS = 30
BROKER_REQUEST_TIMEOUT_SECONDS = 5

def validate_credential_broker_url(url: str) -> str:
    normalized_url = url.rstrip("/")
    parsed = urlsplit(normalized_url)

    if parsed.scheme != "http":
        raise RuntimeError(
            "CREDENTIAL_BROKER_URL must use HTTP "
            "inside the private Docker network"
        )

    if parsed.hostname != "credential_broker":
        raise RuntimeError(
            "CREDENTIAL_BROKER_URL must use the "
            "credential_broker service"
        )

    if parsed.port != 8090:
        raise RuntimeError(
            "CREDENTIAL_BROKER_URL must use port 8090"
        )

    if parsed.username or parsed.password:
        raise RuntimeError(
            "CREDENTIAL_BROKER_URL must not contain credentials"
        )

    if parsed.path not in ("", "/"):
        raise RuntimeError(
            "CREDENTIAL_BROKER_URL must not contain a path"
        )

    if parsed.query or parsed.fragment:
        raise RuntimeError(
            "CREDENTIAL_BROKER_URL must not contain "
            "a query or fragment"
        )

    return normalized_url

def create_broker_workload_token() -> str:
    now = int(time.time())

    claims = {
        "sub": BROKER_WORKLOAD_ID,
        "iss": BROKER_TOKEN_ISSUER,
        "aud": BROKER_TOKEN_AUDIENCE,
        "iat": now,
        "exp": now + BROKER_TOKEN_TTL_SECONDS,
        "jti": str(uuid.uuid4()),
        "scope": "salesforce:token",
    }

    private_key = Path(
        BROKER_PRIVATE_KEY_PATH
    ).read_text(encoding="utf-8")

    return jwt.encode(
        claims,
        private_key,
        algorithm="RS256",
        headers={
            "kid": BROKER_KEY_ID,
            "typ": "JWT",
        },
    )

CREDENTIAL_BROKER_URL = validate_credential_broker_url(
    CREDENTIAL_BROKER_URL
)

raw_api_version = os.environ.get(
    "SF_API_VERSION",
    "67.0",
)

SF_API_VERSION = (
    raw_api_version
    if raw_api_version.startswith("v")
    else f"v{raw_api_version}"
)

REQUEST_TIMEOUT_SECONDS = 10

SALESFORCE_ID_PATTERN = re.compile(
    r"^[A-Za-z0-9]{15}(?:[A-Za-z0-9]{3})?$"
)

SALESFORCE_OBJECT_PREFIXES = {
    "Account": "001",
    "Opportunity": "006",
}


def validate_salesforce_base_url(
    url: str,
    *,
    setting_name: str,
) -> str:
    normalized_url = url.rstrip("/")
    parsed = urlsplit(normalized_url)

    if parsed.scheme != "https":
        raise RuntimeError(
            f"{setting_name} must use HTTPS"
        )

    if not parsed.hostname:
        raise RuntimeError(
            f"{setting_name} must contain a hostname"
        )

    if parsed.username or parsed.password:
        raise RuntimeError(
            f"{setting_name} must not contain credentials"
        )

    if parsed.port not in (None, 443):
        raise RuntimeError(
            f"{setting_name} must use port 443"
        )

    if parsed.path not in ("", "/"):
        raise RuntimeError(
            f"{setting_name} must not contain a path"
        )

    if parsed.query or parsed.fragment:
        raise RuntimeError(
            f"{setting_name} must not contain a query "
            "or fragment"
        )

    return normalized_url


SF_DOMAIN = validate_salesforce_base_url(
    SF_DOMAIN,
    setting_name="SF_DOMAIN",
)

SF_DOMAIN_HOST = urlsplit(SF_DOMAIN).hostname

if not re.fullmatch(
    r"v[0-9]{2,3}\.[0-9]+",
    SF_API_VERSION,
):
    raise RuntimeError(
        "SF_API_VERSION has an invalid format"
    )


def validate_salesforce_instance_url(
    instance_url: str,
) -> str:
    normalized_url = validate_salesforce_base_url(
        instance_url,
        setting_name="Salesforce instance_url",
    )

    instance_host = urlsplit(
        normalized_url
    ).hostname

    if instance_host != SF_DOMAIN_HOST:
        raise RuntimeError(
            "Salesforce instance_url host is not "
            "the configured Salesforce host"
        )

    return normalized_url


def validate_record_id(
    *,
    object_name: str,
    record_id: str,
) -> None:
    expected_prefix = (
        SALESFORCE_OBJECT_PREFIXES.get(
            object_name
        )
    )

    if expected_prefix is None:
        raise ValueError(
            "Salesforce object is not allowed"
        )

    if not SALESFORCE_ID_PATTERN.fullmatch(
        record_id
    ):
        raise ValueError(
            "Invalid Salesforce record ID"
        )

    if not record_id.startswith(
        expected_prefix
    ):
        raise ValueError(
            f"Record ID is not valid for "
            f"{object_name}"
        )


def build_salesforce_record_url(
    *,
    instance_url: str,
    object_name: str,
    record_id: str,
) -> str:
    trusted_instance_url = (
        validate_salesforce_instance_url(
            instance_url
        )
    )

    validate_record_id(
        object_name=object_name,
        record_id=record_id,
    )

    encoded_record_id = quote(
        record_id,
        safe="",
    )

    url = (
        f"{trusted_instance_url}/services/data/"
        f"{SF_API_VERSION}/sobjects/"
        f"{object_name}/{encoded_record_id}"
    )

    parsed_url = urlsplit(url)
    parsed_instance = urlsplit(
        trusted_instance_url
    )

    if (
        parsed_url.scheme
        != parsed_instance.scheme
        or parsed_url.hostname
        != parsed_instance.hostname
        or parsed_url.port
        != parsed_instance.port
    ):
        raise RuntimeError(
            "Salesforce outbound origin mismatch"
        )

    return url


def reject_redirect(
    response: requests.Response,
) -> None:
    if 300 <= response.status_code < 400:
        raise RuntimeError(
            "Salesforce redirects are not allowed"
        )

def get_salesforce_access_token() -> tuple[str, str]:
    broker_token = create_broker_workload_token()

    response = requests.post(
        f"{CREDENTIAL_BROKER_URL}/token/salesforce",
        headers={
            "Authorization": f"Bearer {broker_token}",
            "Accept": "application/json",
        },
        timeout=BROKER_REQUEST_TIMEOUT_SECONDS,
        allow_redirects=False,
    )

    reject_redirect(response)
    response.raise_for_status()

    token_response = response.json()

    access_token = token_response.get("access_token")
    raw_instance_url = token_response.get("instance_url")

    if not isinstance(access_token, str) or not access_token:
        raise RuntimeError(
            "Credential broker returned an invalid access token"
        )

    if not isinstance(raw_instance_url, str):
        raise RuntimeError(
            "Credential broker returned an invalid instance_url"
        )

    instance_url = validate_salesforce_instance_url(
        raw_instance_url
    )

    return access_token, instance_url

def build_authorization_headers(
    access_token: str,
) -> dict[str, str]:
    return {
        "Authorization": (
            f"Bearer {access_token}"
        ),
        "Content-Type": "application/json",
    }

def get_account(
    request: BusinessRequest,
    access_token: str,
    instance_url: str,
) -> dict[str, Any]:
    if request.account_id is None:
        raise ValueError("Missing account_id")

    url = build_salesforce_record_url(
        instance_url=instance_url,
        object_name="Account",
        record_id=request.account_id,
    )

    response = requests.get(
        url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
        allow_redirects=False,
    )

    reject_redirect(response)
    response.raise_for_status()

    return response.json()


def update_account_description(
    request: BusinessRequest,
    access_token: str,
    instance_url: str,
) -> dict[str, Any]:
    if request.account_id is None:
        raise ValueError("Missing account_id")

    if request.description is None:
        raise ValueError("Missing description")

    url = build_salesforce_record_url(
        instance_url=instance_url,
        object_name="Account",
        record_id=request.account_id,
    )

    response = requests.patch(
        url,
        headers=build_authorization_headers(
            access_token
        ),
        json={
            "Description": request.description,
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
        allow_redirects=False,
    )

    reject_redirect(response)
    response.raise_for_status()

    return {
        "updated": True,
        "account_id": request.account_id,
    }


def update_opportunity(
    request: BusinessRequest,
    access_token: str,
    instance_url: str,
) -> dict[str, Any]:
    if request.opportunity_id is None:
        raise ValueError("Missing opportunity_id")

    if request.stage_name is None:
        raise ValueError("Missing stage_name")

    url = build_salesforce_record_url(
        instance_url=instance_url,
        object_name="Opportunity",
        record_id=request.opportunity_id,
    )

    response = requests.patch(
        url,
        headers=build_authorization_headers(
            access_token
        ),
        json={
            "StageName": request.stage_name,
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
        allow_redirects=False,
    )

    reject_redirect(response)
    response.raise_for_status()

    return {
        "updated": True,
        "opportunity_id": request.opportunity_id,
    }


def execute_salesforce_action(
    *,
    identity: IdentityContext,
    request: BusinessRequest,
    decision: PolicyDecision,
) -> dict[str, Any]:
    if decision.effect != "ALLOW":
        raise RuntimeError(
            "Salesforce adapter called without "
            "an ALLOW decision"
        )

    access_token, instance_url = (
        get_salesforce_access_token()
    )

    if request.action == "get_account":
        return get_account(
            request=request,
            access_token=access_token,
            instance_url=instance_url,
        )

    if request.action == (
        "update_account_description"
    ):
        return update_account_description(
            request=request,
            access_token=access_token,
            instance_url=instance_url,
        )

    if request.action == "update_opportunity":
        return update_opportunity(
            request=request,
            access_token=access_token,
            instance_url=instance_url,
        )

    raise ValueError(
        "Unsupported Salesforce action"
    )
