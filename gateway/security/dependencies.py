from fastapi import Header, HTTPException, status

from gateway.security.identity import IdentityContext
from gateway.security.workload_identity import (
    WorkloadAuthenticationError,
    authenticate_workload,
)
from gateway.settings import settings

def get_workload_identity(
    authorization: str | None = Header(default=None),
) -> IdentityContext:
    if authorization is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "MISSING_WORKLOAD_TOKEN",
                "message": (
                    "Authorization header is required"
                ),
            },
        )

    scheme, separator, token = authorization.partition(
        " "
    )

    if (
        separator == ""
        or scheme.lower() != "bearer"
        or not token
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "INVALID_AUTHORIZATION_HEADER",
                "message": "Expected Bearer token",
            },
        )

    try:
        return authenticate_workload(
            token=token,
            expected_issuer=(
                settings.workload_jwt_issuer
            ),
            expected_audience=(
                settings.workload_jwt_audience
            ),
        )
    except WorkloadAuthenticationError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": str(error),
                "message": (
                    "Workload authentication failed"
                ),
            },
        ) from error