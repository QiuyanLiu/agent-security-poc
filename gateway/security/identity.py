from dataclasses import dataclass
from typing import Tuple


@dataclass(frozen=True)
class IdentityContext:
    workload_id: str
    issuer: str
    audience: str
    key_id: str | None
    token_id: str | None
    issued_at: int
    expires_at: int
    scopes: Tuple[str, ...]