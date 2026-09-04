from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    StringConstraints,
    field_validator,
    model_validator,
)


BusinessAction = Literal[
    "get_account",
    "update_account_description",
    "update_opportunity",
]


SalesforceId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=15,
        max_length=18,
        pattern=r"^[A-Za-z0-9]+$",
    ),
]


class BusinessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: BusinessAction

    account_id: SalesforceId | None = None
    description: str | None = None

    opportunity_id: SalesforceId | None = None
    stage_name: str | None = None

    @field_validator("account_id")
    @classmethod
    def validate_account_id(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("001"):
            raise ValueError("account_id must be a Salesforce Account ID")
        return value

    @field_validator("opportunity_id")
    @classmethod
    def validate_opportunity_id(cls, value: str | None) -> str | None:
        if value is not None and not value.startswith("006"):
            raise ValueError(
                "opportunity_id must be a Salesforce Opportunity ID"
            )
        return value

    @model_validator(mode="after")
    def validate_action_arguments(self) -> "BusinessRequest":
        if self.action == "get_account":
            if self.account_id is None:
                raise ValueError(
                    "account_id is required for get_account"
                )

            if any(
                value is not None
                for value in (
                    self.description,
                    self.opportunity_id,
                    self.stage_name,
                )
            ):
                raise ValueError(
                    "get_account accepts only account_id"
                )

        elif self.action == "update_account_description":
            if self.account_id is None:
                raise ValueError(
                    "account_id is required for "
                    "update_account_description"
                )

            if self.description is None:
                raise ValueError(
                    "description is required for "
                    "update_account_description"
                )

            if any(
                value is not None
                for value in (
                    self.opportunity_id,
                    self.stage_name,
                )
            ):
                raise ValueError(
                    "update_account_description accepts only "
                    "account_id and description"
                )

        elif self.action == "update_opportunity":
            if self.opportunity_id is None:
                raise ValueError(
                    "opportunity_id is required for "
                    "update_opportunity"
                )

            if self.stage_name is None:
                raise ValueError(
                    "stage_name is required for "
                    "update_opportunity"
                )

            if any(
                value is not None
                for value in (
                    self.account_id,
                    self.description,
                )
            ):
                raise ValueError(
                    "update_opportunity accepts only "
                    "opportunity_id and stage_name"
                )

        return self