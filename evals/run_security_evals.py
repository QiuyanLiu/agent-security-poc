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
AUDIT_FILE = ROOT / "logs" / "audit.jsonl"
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

def extract_request_id(body: Any) -> str | None:
    """Extract a request ID from success or FastAPI error responses."""
    if not isinstance(body, dict):
        return None

    request_id = body.get("request_id")
    if isinstance(request_id, str):
        return request_id

    detail = body.get("detail")
    if isinstance(detail, dict):
        request_id = detail.get("request_id")
        if isinstance(request_id, str):
            return request_id

    return None


def audit_file_offset() -> int:
    """Return the audit-file size before executing a test case."""
    try:
        return AUDIT_FILE.stat().st_size
    except FileNotFoundError:
        return 0


def read_new_audit_entries(offset: int) -> tuple[str, list[dict[str, Any]]]:
    """Read audit entries appended after the test case started."""
    if not AUDIT_FILE.exists():
        return "", []

    # Handle log truncation or replacement.
    if AUDIT_FILE.stat().st_size < offset:
        offset = 0

    with AUDIT_FILE.open(encoding="utf-8") as stream:
        stream.seek(offset)
        text = stream.read()

    events: list[dict[str, Any]] = []

    for line in text.splitlines():
        if not line.strip():
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if isinstance(event, dict):
            events.append(event)

    return text, events

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

    expected = case.get("expected", {})
    failures: list[str] = []
    notes: list[str] = []
    verified: list[str] = []

    check_broker = "credential_broker_called" in expected
    expected_broker_called = expected.get("credential_broker_called")
    broker_count_before = None

    if check_broker:
        if type(expected_broker_called) is not bool:
            return Result(
                str(case["id"]),
                "FAIL",
                ["credential_broker_called must be a YAML boolean"],
            )

        try:
            broker_count_before = get_credential_broker_request_count()
        except Exception:
            return Result(
                str(case["id"]),
                "FAIL",
                ["Cannot read Broker counter before request; test aborted"],
            )
    
    audit_offset = audit_file_offset()
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

    if check_broker:
        try:
            broker_count_after = get_credential_broker_request_count()
        except Exception:
            failures.append(
                "Cannot read Broker counter after request"
            )
        else:
            delta = broker_count_after - broker_count_before

            if delta < 0:
                failures.append(
                    "Broker counter decreased; possible restart/reset"
                )
            elif expected_broker_called is False:
                if delta != 0:
                    failures.append(
                        f"Broker counter increased: "
                        f"{broker_count_before} -> {broker_count_after}"
                    )
                else:
                    verified.append(
                        f"Broker request count unchanged: "
                        f"{broker_count_before} -> {broker_count_after}"
                    )
            elif delta == 0:
                failures.append(
                    "Expected a Broker call, but counter did not increase"
                )
            else:
                verified.append(
                    f"Broker request count increased by {delta}"
                )

    actual_status = actual.get("http_status")
    body = actual.get("body")
    body_text = json.dumps(body, sort_keys=True)
    request_id = extract_request_id(body)

    new_audit_text, new_audit_events = read_new_audit_entries(
        audit_offset
    )

    if "http_status" in expected:
        expected_status = expected["http_status"]

        if actual_status != expected_status:
            failures.append(
                f"HTTP status expected {expected_status}, got {actual_status}"
            )
        else:
            verified.append(
                f"HTTP status verified: {actual_status}"
            )

    for key in ("error_code", "error_type"):
        if key not in expected:
            continue

        if str(expected[key]) not in body_text:
            failures.append(
                f"Expected {key} {expected[key]!r} was not in response"
            )
        else:
            verified.append(
                f"Response {key} verified: {expected[key]}"
            )

    expected_response = expected.get("response", {})

    if expected_response:
        if not isinstance(body, dict):
            failures.append(
                "Cannot verify response fields: response body is not an object"
            )
        else:
            for key, expected_value in expected_response.items():
                actual_value = body.get(key)

                if actual_value != expected_value:
                    failures.append(
                        f"Response field {key!r}: expected "
                        f"{expected_value!r}, got {actual_value!r}"
                    )
                else:
                    verified.append(
                        f"Response {key} verified: {actual_value!r}"
                    )

    if expected.get("secret_in_response") is False:
        if SENSITIVE_PATTERN.search(body_text):
            failures.append(
                "Potential secret marker found in response"
            )
        else:
            verified.append(
                "No secret detected in response"
            )

    expected_audit = expected.get("audit")

    if expected_audit:
        if request_id is None:
            failures.append(
                "Cannot correlate audit event: response has no request_id"
            )
        else:
            matching_events = [
                event
                for event in new_audit_events
                if event.get("request_id") == request_id
            ]

            if not matching_events:
                failures.append(
                    f"No audit event found for request_id {request_id}"
                )
            elif len(matching_events) > 1:
                failures.append(
                    f"Expected one audit event for request_id {request_id}, "
                    f"found {len(matching_events)}"
                )
            else:
                audit_event = matching_events[0]

                verified.append(
                    f"Audit event correlated by request_id: {request_id}"
                )

                for key, expected_value in expected_audit.items():
                    actual_value = audit_event.get(key)

                    if actual_value != expected_value:
                        failures.append(
                            f"Audit field {key!r}: expected "
                            f"{expected_value!r}, got {actual_value!r}"
                        )
                    else:
                        verified.append(
                            f"Audit {key} verified: {actual_value}"
                        )

    if expected.get("secret_in_logs") is False:
        if SENSITIVE_PATTERN.search(new_audit_text):
            failures.append(
                "Potential secret marker found in new audit entries"
            )
        else:
            verified.append(
                "No secret detected in new audit entries"
            )

    unsupported_assertions = [
        key
        for key in (
            "gateway_decision",
            "outcome",
            "approval_required",
            "policy_evaluated",
            "salesforce_called",
            "outbound_request_sent",
        )
        if key in expected
    ]

    if unsupported_assertions:
        notes.append(
            "not verified: " + ", ".join(unsupported_assertions)
        )

    if not any(
        key in expected
        for key in (
            "http_status",
            "error_code",
            "error_type",
            "response",
            "audit",
            "credential_broker_called",
        )
    ):
        notes.append("no executable assertion defined")
        return Result(str(case["id"]), "SKIP", notes)

    details = [
        *verified,
        f"Response: {json.dumps(body, ensure_ascii=False)}",
        *failures,
        *notes,
    ]

    return Result(
        str(case["id"]),
        "FAIL" if failures else "PASS",
        details,
    )


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

def get_credential_broker_request_count() -> int:
    program = r'''
import requests

response = requests.get(
    "http://credential_broker:8090/__test__/request-count",
    timeout=5,
)
response.raise_for_status()

payload = response.json()
request_count = payload.get("request_count")

if type(request_count) is not int or request_count < 0:
    raise RuntimeError(
        "Credential Broker request_count is not an integer"
    )

print(request_count)
'''

    completed = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "gateway",
            "python",
            "-c",
            program,
        ],
        capture_output=True,
        text=True,
        timeout=15,
        cwd=ROOT,
    )

    if completed.returncode != 0:
        details = (
            completed.stderr.strip()
            or completed.stdout.strip()
            or "unknown error"
        )
        raise RuntimeError(
            "Unable to read Credential Broker request count: "
            f"{details}"
        )

    output = completed.stdout.strip()

    try:
        return int(output)
    except ValueError as error:
        raise RuntimeError(
            "Invalid Credential Broker request count: "
            f"{output!r}"
        ) from error

if __name__ == "__main__":
    raise SystemExit(main())
