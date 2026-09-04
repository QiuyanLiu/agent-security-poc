from time import perf_counter

from fastapi import Depends, FastAPI, HTTPException

from gateway.audit import new_request_id, write_audit
from gateway.models.execution import BusinessRequest
from gateway.policy import evaluate_policy
from gateway.salesforce import execute_salesforce_action
from gateway.security.dependencies import get_workload_identity
from gateway.security.identity import IdentityContext


app = FastAPI()


@app.post("/execute")
async def execute(
    request: BusinessRequest,
    identity: IdentityContext = Depends(
        get_workload_identity
    ),
):
    request_id = new_request_id()
    started_at = perf_counter()

    request_arguments = request.model_dump(
        exclude_none=True
    )
    request_arguments.pop("action", None)

    audit_metadata = {
        "argument_names": sorted(
            request_arguments.keys()
        )
    }

    decision = evaluate_policy(
        identity=identity,
        request=request,
    )

    if decision.effect == "DENY":
        duration_ms = (
            perf_counter() - started_at
        ) * 1000

        write_audit(
            request_id=request_id,
            user="workload-identity",
            agent=identity.workload_id,
            tool=request.action,
            decision="DENY",
            outcome="BLOCKED",
            duration_ms=duration_ms,
            reason=decision.reason,
            metadata=audit_metadata,
        )

        raise HTTPException(
            status_code=403,
            detail={
                "code": decision.reason,
                "message": "Request denied by policy",
                "request_id": request_id,
            },
        )

    try:
        result = execute_salesforce_action(
            identity=identity,
            request=request,
            decision=decision,
        )

    except Exception as error:
        duration_ms = (
            perf_counter() - started_at
        ) * 1000

        write_audit(
            request_id=request_id,
            user="workload-identity",
            agent=identity.workload_id,
            tool=request.action,
            decision="ALLOW",
            outcome="ERROR",
            duration_ms=duration_ms,
            reason=type(error).__name__,
            metadata=audit_metadata,
        )

        raise

    duration_ms = (
        perf_counter() - started_at
    ) * 1000

    write_audit(
        request_id=request_id,
        user="workload-identity",
        agent=identity.workload_id,
        tool=request.action,
        decision="ALLOW",
        outcome="SUCCESS",
        duration_ms=duration_ms,
        reason=None,
        metadata=audit_metadata,
    )

    return {
        "request_id": request_id,
        "status": "SUCCESS",
        "result": result,
    }