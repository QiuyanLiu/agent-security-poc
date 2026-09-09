#!/usr/bin/env python3
"""Run the security eval cases against the Docker Compose POC.

The HTTP cases execute from the appropriate Agent container because the
Gateway is intentionally not published to the host. The credential-isolation
case is evaluated directly with ``docker compose exec``.
"""

from __future__ import annotations

import argparse
import json, os, sys, time, uuid
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ROOT / "evals" / "security-eval-cases.yaml"
DEFAULT_GATEWAY_URL = "http://gateway:8080"
DEFAULT_SERVICE_BY_ACTOR = {
    "crm-agent": "agent",
    "reporting-agent": "reporting_agent",
}
SENSITIVE_PATTERN = re.compile(
    r"(?i)(SF_CLIENT_SECRET|SALESFORCE_ACCESS_TOKEN|"
    r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|Bearer\s+[A-Za-z0-9._~+/=-]+)"
)


@dataclass
class Result:
    case_id: str
    status: str
    details: list[str] = field(default_factory=list)


def compose(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=check,
    )


def load_cases(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        data = yaml.safe_load(stream)
    if not isinstance(data, list):
        raise ValueError("The eval file must contain a YAML list")
    return data


def service_for(case: dict[str, Any]) -> str:
    actor = str(case.get("actor", ""))
    env_name = "EVAL_SERVICE_" + actor.upper().replace("-", "_")
    return os.getenv(env_name, DEFAULT_SERVICE_BY_ACTOR.get(actor, actor))


def run_gateway_request(case: dict[str, Any], gateway_url: str) -> Result:
    service = service_for(case)
    payload = {
        "gateway_url": gateway_url,
        "authentication": case.get("authentication", {"mode": "none"}),
        "request": case.get("request", {}),
    }

    # This program runs inside the Agent image, which already has requests,
    # PyJWT and its own workload private key installed/mounted.
    remote_program = r'''
import json, os, sys, time, uuid
import jwt, requests

cfg = json.loads(sys.stdin.read())
auth = cfg.get("authentication", {})
mode = auth.get("mode", "none")
headers = {"Content-Type": "application/json"}

if mode != "none":
    claims_cfg = auth.get("claims", {})
    now = int(time.time())
    expiration = claims_cfg.get("expiration", "valid")
    exp = now - 60 if expiration == "expired" else now + int(
        os.getenv("WORKLOAD_TOKEN_TTL_SECONDS", "60")
    )
    subject = claims_cfg.get(
        "sub", auth.get("workload", os.environ["WORKLOAD_ID"])
    )
    scopes = claims_cfg.get(
        "scope",
        auth.get("scopes", []),
    )

    if isinstance(scopes, list):
        scopes = " ".join(scopes)
    token_claims = {
        "sub": subject,
        "iss": os.environ["WORKLOAD_ISSUER"],
        "aud": os.environ["WORKLOAD_AUDIENCE"],
        "iat": now,
        "nbf": now - 1,
        "exp": exp,
        "jti": str(uuid.uuid4()),
        "scope": scopes,
    }
    with open(os.environ["WORKLOAD_PRIVATE_KEY_PATH"], "rb") as key_file:
        private_key = key_file.read()
    token = jwt.encode(
        token_claims,
        private_key,
        algorithm="RS256",
        headers={"kid": os.environ["WORKLOAD_KEY_ID"], "typ": "JWT"},
    )
    headers["Authorization"] = "Bearer " + token

request_cfg = cfg.get("request", {})
try:
    response = requests.request(
        method=request_cfg.get("method", "POST"),
        url=cfg["gateway_url"].rstrip("/") + request_cfg.get("path", "/execute"),
        headers=headers,
        json=request_cfg.get("body"),
        timeout=10,
        allow_redirects=False,
    )
    try:
        body = response.json()
    except ValueError:
        body = {"raw_text": response.text[:4000]}
    print(json.dumps({"http_status": response.status_code, "body": body}))
except Exception as exc:
    print(json.dumps({"transport_error": type(exc).__name__, "message": str(exc)}))
    sys.exit(2)
'''

    process = subprocess.run(
        ["docker", "compose", "exec", "-T", service, "python", "-c", remote_program],
        cwd=ROOT,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
    )
    if process.returncode != 0:
        detail = (process.stderr or process.stdout).strip()
        return Result(str(case["id"]), "ERROR", [detail or "Container request failed"])

    try:
        actual = json.loads(process.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return Result(str(case["id"]), "ERROR", ["Invalid runner output"])

    if "transport_error" in actual:
        return Result(
            str(case["id"]), "ERROR",
            [f"{actual['transport_error']}: {actual.get('message', '')}"],
        )

    expected = case.get("expected", {})
    failures: list[str] = []
    notes: list[str] = []
    actual_status = actual.get("http_status")
    body = actual.get("body")
    body_text = json.dumps(body, sort_keys=True)

    if "http_status" in expected and actual_status != expected["http_status"]:
        failures.append(
            f"HTTP status expected {expected['http_status']}, got {actual_status}"
        )
    for key in ("error_code", "error_type"):
        if key in expected and str(expected[key]) not in body_text:
            failures.append(f"Expected {key} {expected[key]!r} was not in response")

    if expected.get("secret_in_response") is False and SENSITIVE_PATTERN.search(body_text):
        failures.append("Potential secret marker found in response")

    # These require audit/Salesforce instrumentation and cannot be proven from
    # an HTTP response alone. Keep them visible instead of silently passing.
    non_http_assertions = [
        key for key in (
            "gateway_decision", "outcome", "approval_required",
            "policy_evaluated", "salesforce_called", "outbound_request_sent",
            "secret_in_logs",
        ) if key in expected
    ]
    if non_http_assertions:
        notes.append("not verified: " + ", ".join(non_http_assertions))

    if not any(key in expected for key in ("http_status", "error_code", "error_type")):
        notes.append("no executable HTTP assertion defined")
        return Result(str(case["id"]), "SKIP", notes)

    details = [
        f"HTTP {actual_status}",
        f"Response: {json.dumps(body, ensure_ascii=False)}",
        *failures,
        *notes,
    ]
    return Result(str(case["id"]), "FAIL" if failures else "PASS", details)


def path_exists(service: str, path: str) -> bool:
    result = compose("exec", "-T", service, "sh", "-c", "test -e \"$1\"", "sh", path)
    return result.returncode == 0


def run_container_assertion(case: dict[str, Any]) -> Result:
    service = str(case.get("target_service") or service_for(case))
    checks = case.get("checks", {})
    failures: list[str] = []

    env_result = compose("exec", "-T", service, "env")
    if env_result.returncode != 0:
        return Result(str(case["id"]), "ERROR", [(env_result.stderr or env_result.stdout).strip()])
    environment_names = {
        line.partition("=")[0] for line in env_result.stdout.splitlines() if "=" in line
    }
    for name in checks.get("environment_variables_absent", []):
        if name in environment_names:
            failures.append(f"Environment variable is present: {name}")

    for group in ("filesystem_paths_absent", "peer_private_keys_absent"):
        for path in checks.get(group, []):
            if path_exists(service, str(path)):
                failures.append(f"Forbidden path exists: {path}")

    details = failures or ["No forbidden credential variables or files were found"]
    details.append("audit-log secret scan not verified")
    return Result(str(case["id"]), "FAIL" if failures else "PASS", details)


def run_case(case: dict[str, Any], gateway_url: str) -> Result:
    test_type = case.get("test_type")
    if test_type == "gateway_request":
        return run_gateway_request(case, gateway_url)
    if test_type == "container_assertion":
        return run_container_assertion(case)
    return Result(str(case.get("id", "UNKNOWN")), "SKIP", [f"Unknown test_type: {test_type}"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--gateway-url", default=os.getenv("EVAL_GATEWAY_URL", DEFAULT_GATEWAY_URL))
    parser.add_argument("--case", action="append", dest="selected", help="Run only this case ID")
    args = parser.parse_args()

    try:
        cases = load_cases(args.cases)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"Cannot load eval cases: {exc}", file=sys.stderr)
        return 2

    if args.selected:
        selected = set(args.selected)
        cases = [case for case in cases if case.get("id") in selected]
        missing = selected - {str(case.get("id")) for case in cases}
        if missing:
            print("Unknown case IDs: " + ", ".join(sorted(missing)), file=sys.stderr)
            return 2

    ps = compose("ps", "--status", "running", "--services")
    if ps.returncode != 0:
        print((ps.stderr or ps.stdout).strip(), file=sys.stderr)
        return 2
    running = set(ps.stdout.split())
    required = {service_for(case) for case in cases}
    unavailable = sorted(required - running)
    if unavailable:
        print("Required Compose services are not running: " + ", ".join(unavailable), file=sys.stderr)
        print("Start them with: docker compose up -d --build", file=sys.stderr)
        return 2

    results = [run_case(case, args.gateway_url) for case in cases]
    print("\nSecurity eval results")
    print("=" * 72)
    for result in results:
        print(f"{result.status:5}  {result.case_id}")
        for detail in result.details:
            print(f"       - {detail}")

    counts = {status: sum(r.status == status for r in results) for status in ("PASS", "FAIL", "ERROR", "SKIP")}
    print("=" * 72)
    print("  ".join(f"{name}: {count}" for name, count in counts.items()))
    return 1 if counts["FAIL"] or counts["ERROR"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
