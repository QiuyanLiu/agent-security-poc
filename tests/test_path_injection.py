import pytest
from pydantic import ValidationError

from gateway.models.execution import BusinessRequest

from gateway.salesforce import (
    SF_DOMAIN,
    build_salesforce_record_url,
)

@pytest.mark.parametrize(
    "malicious_id",
    [
        "../Opportunity/006gL0000123456",
        "001gL00001hyL9GQAU/Contacts",
        "001gL00001hyL9GQAU?fields=Id",
        "%2e%2e%2fOpportunity",
        "//attacker.example/path",
        "https://attacker.example",
        r"..\Opportunity\006gL0000123456",
        "001gL00001hyL9GQAU#fragment",
        "001gL00001hyL9GQAU%00",
    ],
)
def test_account_id_rejects_path_injection(
    malicious_id: str,
) -> None:
    with pytest.raises(ValidationError):
        BusinessRequest(
            action="get_account",
            account_id=malicious_id,
        )


def test_account_id_rejects_opportunity_id() -> None:
    with pytest.raises(ValidationError):
        BusinessRequest(
            action="get_account",
            account_id="006gL0000123456",
        )


def test_valid_account_id_is_accepted() -> None:
    request = BusinessRequest(
        action="get_account",
        account_id="001gL00001hyL9GQAU",
    )

    assert request.account_id == "001gL00001hyL9GQAU"

def test_account_url_uses_trusted_origin() -> None:
    url = build_salesforce_record_url(
        instance_url=SF_DOMAIN,
        object_name="Account",
        record_id="001gL00001hyL9GQAU",
    )

    assert url.startswith(
        f"{SF_DOMAIN}/services/data/"
    )

    assert url.endswith(
        "/sobjects/Account/001gL00001hyL9GQAU"
    )

def test_unknown_object_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="Salesforce object is not allowed",
    ):
        build_salesforce_record_url(
            instance_url=SF_DOMAIN,
            object_name="User",
            record_id="005gL0000123456",
        )