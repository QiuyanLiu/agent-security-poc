from dataclasses import dataclass
from typing import Literal

from gateway.models.execution import BusinessRequest
from gateway.security.identity import IdentityContext


PolicyEffect = Literal["ALLOW", "DENY"]


@dataclass(frozen=True)
class PolicyDecision:
    effect: PolicyEffect
    reason: str
    required_scope: str | None = None


REQUIRED_SCOPE_BY_ACTION = {
    "get_account": "account:read",
    "update_account_description": "account:write",
    "update_opportunity": "opportunity:write",
}


ALLOWED_ACTIONS_BY_WORKLOAD = {
    "crm-agent": frozenset(
        {
            "get_account",
            "update_account_description",
            "update_opportunity",
        }
    ),
    "reporting-agent": frozenset(
        {
            "get_account",
        }
    ),
}


def evaluate_policy(
    *,
    identity: IdentityContext,
    request: BusinessRequest,
) -> PolicyDecision:
    allowed_actions = ALLOWED_ACTIONS_BY_WORKLOAD.get(
        identity.workload_id
    )

    if allowed_actions is None:
        return PolicyDecision(
            effect="DENY",
            reason="WORKLOAD_NOT_ALLOWED",
        )

    if request.action not in allowed_actions:
        return PolicyDecision(
            effect="DENY",
            reason="ACTION_NOT_ALLOWED_FOR_WORKLOAD",
        )

    required_scope = REQUIRED_SCOPE_BY_ACTION.get(
        request.action
    )

    if required_scope is None:
        return PolicyDecision(
            effect="DENY",
            reason="ACTION_NOT_ALLOWED",
        )

    if required_scope not in identity.scopes:
        return PolicyDecision(
            effect="DENY",
            reason="INSUFFICIENT_SCOPE",
            required_scope=required_scope,
        )

    if (
        request.action == "update_account_description"
        and request.description is None
    ):
        return PolicyDecision(
            effect="DENY",
            reason="DESCRIPTION_REQUIRED",
            required_scope=required_scope,
        )

    if request.action == "update_opportunity":
        if request.opportunity_id is None:
            return PolicyDecision(
                effect="DENY",
                reason="OPPORTUNITY_ID_REQUIRED",
                required_scope=required_scope,
            )

        if request.stage_name is None:
            return PolicyDecision(
                effect="DENY",
                reason="STAGE_NAME_REQUIRED",
                required_scope=required_scope,
            )

    return PolicyDecision(
        effect="ALLOW",
        reason="POLICY_ALLOWED",
        required_scope=required_scope,
    )