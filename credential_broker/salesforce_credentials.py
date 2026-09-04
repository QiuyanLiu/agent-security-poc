import os
from typing import Any
from urllib.parse import urlsplit

import requests


SF_DOMAIN = os.environ["SF_DOMAIN"].rstrip("/")
SF_CLIENT_ID = os.environ["SF_CLIENT_ID"]
SF_CLIENT_SECRET = os.environ["SF_CLIENT_SECRET"]

REQUEST_TIMEOUT_SECONDS = 10


def validate_salesforce_base_url(url: str) -> str:
    normalized_url = url.rstrip("/")
    parsed = urlsplit(normalized_url)

    if parsed.scheme != "https":
        raise RuntimeError("SF_DOMAIN must use HTTPS")

    if not parsed.hostname:
        raise RuntimeError(
            "SF_DOMAIN must contain a hostname"
        )

    if parsed.username or parsed.password:
        raise RuntimeError(
            "SF_DOMAIN must not contain credentials"
        )

    if parsed.port not in (None, 443):
        raise RuntimeError(
            "SF_DOMAIN must use port 443"
        )

    if parsed.path not in ("", "/"):
        raise RuntimeError(
            "SF_DOMAIN must not contain a path"
        )

    if parsed.query or parsed.fragment:
        raise RuntimeError(
            "SF_DOMAIN must not contain a query or fragment"
        )

    return normalized_url


SF_DOMAIN = validate_salesforce_base_url(SF_DOMAIN)
SF_DOMAIN_HOST = urlsplit(SF_DOMAIN).hostname


def validate_instance_url(instance_url: str) -> str:
    normalized_url = validate_salesforce_base_url(
        instance_url
    )

    if urlsplit(normalized_url).hostname != SF_DOMAIN_HOST:
        raise RuntimeError(
            "Salesforce instance_url host mismatch"
        )

    return normalized_url


def request_salesforce_token() -> dict[str, Any]:
    response = requests.post(
        f"{SF_DOMAIN}/services/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": SF_CLIENT_ID,
            "client_secret": SF_CLIENT_SECRET,
        },
        timeout=REQUEST_TIMEOUT_SECONDS,
        allow_redirects=False,
    )

    if 300 <= response.status_code < 400:
        raise RuntimeError(
            "Salesforce redirects are not allowed"
        )

    response.raise_for_status()
    payload = response.json()

    access_token = payload.get("access_token")
    raw_instance_url = payload.get(
        "instance_url",
        SF_DOMAIN,
    )

    if not isinstance(access_token, str) or not access_token:
        raise RuntimeError(
            "Salesforce returned an invalid access token"
        )

    if not isinstance(raw_instance_url, str):
        raise RuntimeError(
            "Salesforce returned an invalid instance_url"
        )

    result: dict[str, Any] = {
        "access_token": access_token,
        "instance_url": validate_instance_url(
            raw_instance_url
        ),
        "token_type": "Bearer",
    }

    expires_in = payload.get("expires_in")

    if isinstance(expires_in, int):
        result["expires_in"] = expires_in

    return result