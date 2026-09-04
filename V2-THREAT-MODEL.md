# V2 — Compromised Agent Threat Model

## Attacker assumption
Assume the Agent container is fully compromised through prompt injection
or malicious tool output.

## Protected assets
- Salesforce client secret
- Salesforce access token
- Customer data
- Approval records
- Gateway policy configuration
- Audit logs

## Security invariants
1. The Agent never receives Salesforce credentials.
2. The Agent cannot connect directly to Salesforce.
3. The Agent can communicate only with the Policy Gateway.
4. Every tool request is independently authorized.
5. Approval is bound to user, tool, resource, arguments and expiration.
6. Logs contain no secrets and cannot be modified by the Agent.

## Required attack tests
1. Read Gateway environment variables.
2. Connect directly to Salesforce.
3. Access an unauthorized external domain.
4. Bypass the Policy Gateway.
5. Reuse an approval with modified arguments.
6. Alter or delete audit logs.