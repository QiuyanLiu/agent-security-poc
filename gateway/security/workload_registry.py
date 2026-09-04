from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet


@dataclass(frozen=True)
class WorkloadRegistration:
    workload_id: str
    key_id: str
    public_key_path: str
    allowed_scopes: FrozenSet[str]


WORKLOAD_REGISTRY = {
    "crm-agent-key-v1": WorkloadRegistration(
        workload_id="crm-agent",
        key_id="crm-agent-key-v1",
        public_key_path=(
            "/run/secrets/crm-agent-public.pem"
        ),
        allowed_scopes=frozenset(
            {
                "account:read",
                "account:write",
            }
        ),
    ),
    (
        "reporting-agent-key-v1"
    ): WorkloadRegistration(
        workload_id="reporting-agent",
        key_id="reporting-agent-key-v1",
        public_key_path=(
            "/run/secrets/"
            "reporting-agent-public.pem"
        ),
        allowed_scopes=frozenset(
            {
                "account:read",
            }
        ),
    ),
}


class UnknownWorkloadKeyError(Exception):
    pass


def get_workload_registration(
    key_id: str,
) -> WorkloadRegistration:
    registration = WORKLOAD_REGISTRY.get(key_id)

    if registration is None:
        raise UnknownWorkloadKeyError(
            "UNKNOWN_WORKLOAD_KEY"
        )

    return registration


def load_registered_public_key(
    registration: WorkloadRegistration,
) -> str:
    return Path(
        registration.public_key_path
    ).read_text(encoding="utf-8")