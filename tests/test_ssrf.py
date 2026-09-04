from unittest.mock import Mock

import pytest
import requests

import gateway.salesforce as salesforce


@pytest.mark.parametrize(
    ("malicious_url", "expected_message"),
    [
        (
            "http://example.my.salesforce.com",
            "must use HTTPS",
        ),
        (
            "https://user:password@example.my.salesforce.com",
            "must not contain credentials",
        ),
        (
            "https://example.my.salesforce.com:8443",
            "must use port 443",
        ),
        (
            "https://example.my.salesforce.com/services/data",
            "must not contain a path",
        ),
        (
            "https://example.my.salesforce.com?target=attacker",
            "must not contain a query or fragment",
        ),
        (
            "https://example.my.salesforce.com#fragment",
            "must not contain a query or fragment",
        ),
    ],
)
def test_salesforce_base_url_rejects_unsafe_configuration(
    malicious_url: str,
    expected_message: str,
) -> None:
    with pytest.raises(
        RuntimeError,
        match=expected_message,
    ):
        salesforce.validate_salesforce_base_url(
            malicious_url,
            setting_name="Test URL",
        )


@pytest.mark.parametrize(
    "malicious_instance_url",
    [
        "http://169.254.169.254",
        "https://169.254.169.254",
        "https://127.0.0.1",
        "https://localhost",
        "https://attacker.example",
        "https://gateway",
        "https://user:password@attacker.example",
        "https://attacker.example/services/data",
        "https://attacker.example?target=internal",
        "https://attacker.example#fragment",
    ],
)
def test_instance_url_rejects_ssrf_destinations(
    malicious_instance_url: str,
) -> None:
    with pytest.raises(RuntimeError):
        salesforce.validate_salesforce_instance_url(
            malicious_instance_url
        )


def test_instance_url_accepts_configured_salesforce_origin() -> None:
    result = salesforce.validate_salesforce_instance_url(
        salesforce.SF_DOMAIN
    )

    assert result == salesforce.SF_DOMAIN


def test_instance_url_allows_only_trailing_slash_normalization() -> None:
    result = salesforce.validate_salesforce_instance_url(
        f"{salesforce.SF_DOMAIN}/"
    )

    assert result == salesforce.SF_DOMAIN


def test_redirect_helper_rejects_all_redirect_statuses() -> None:
    for status_code in (300, 301, 302, 303, 307, 308, 399):
        response = requests.Response()
        response.status_code = status_code

        with pytest.raises(
            RuntimeError,
            match="Salesforce redirects are not allowed",
        ):
            salesforce.reject_redirect(response)


def test_non_redirect_response_is_accepted() -> None:
    response = requests.Response()
    response.status_code = 200

    salesforce.reject_redirect(response)

def test_malicious_broker_instance_url_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_response = Mock()
    fake_response.status_code = 200
    fake_response.raise_for_status.return_value = None
    fake_response.json.return_value = {
        "access_token": "fake-access-token",
        "instance_url": (
            "http://169.254.169.254/latest/meta-data"
        ),
    }

    monkeypatch.setattr(
        salesforce,
        "create_broker_workload_token",
        Mock(return_value="fake-broker-token"),
    )

    monkeypatch.setattr(
        salesforce.requests,
        "post",
        Mock(return_value=fake_response),
    )

    with pytest.raises(RuntimeError):
        salesforce.get_salesforce_access_token()

def test_broker_redirect_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_response = Mock()
    fake_response.status_code = 302
    fake_response.headers = {
        "Location": "https://attacker.example",
    }

    post_mock = Mock(return_value=fake_response)

    monkeypatch.setattr(
        salesforce,
        "create_broker_workload_token",
        Mock(return_value="fake-broker-token"),
    )

    monkeypatch.setattr(
        salesforce.requests,
        "post",
        post_mock,
    )

    with pytest.raises(
        RuntimeError,
        match="Salesforce redirects are not allowed",
    ):
        salesforce.get_salesforce_access_token()

    assert (
        post_mock.call_args.kwargs["allow_redirects"]
        is False
    )