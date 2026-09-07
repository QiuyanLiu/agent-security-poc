# AI Agent Security Architecture Review

## Secure AI agents before they access critical enterprise systems

AI agents connected to Salesforce, CRM platforms, MCP servers, or enterprise APIs introduce new security risks. A prompt injection, compromised tool, or excessive permission can expose credentials, bypass approval controls, modify sensitive records, or allow access to unintended systems.

The **AI Agent Security Architecture Review** helps organisations identify these risks before production deployment and define a practical, prioritised remediation plan.

## Who this is for

This review is designed for mid-sized and regulated organisations that:

- are building or piloting AI agents connected to Salesforce, CRM, MCP, or internal APIs;
- need to protect customer data and application credentials;
- must demonstrate traceability, least privilege, and human oversight;
- want an independent review before moving an agent into production.

## Risks assessed

- Agent or workload impersonation
- Excessive permissions and scope escalation
- Credential exposure or reuse
- Prompt-injection-driven tool abuse
- Missing human approval for sensitive actions
- Server-Side Request Forgery (SSRF) and uncontrolled outbound access
- Path and argument injection
- Incomplete or unsafe audit logging
- Weak network and runtime isolation

## Review scope

The engagement typically includes:

1. A discovery interview covering the use case, data, identities, tools, and target systems.
2. A review of trust boundaries and end-to-end request flows.
3. An assessment of workload identity, token audience, scopes, and credential handling.
4. A review of tool permissions, policy enforcement, and human-in-the-loop controls.
5. A targeted analysis of realistic attack scenarios.
6. A prioritised remediation workshop with technical and business stakeholders.

The review assesses the architecture and selected implementation evidence. It is not a formal penetration test, compliance certification, or exhaustive source-code audit.

## Deliverables

- Current-state security architecture diagram
- Trust-boundary and identity-flow analysis
- Prioritised risk register
- Security control matrix
- Target-state architecture recommendations
- Practical remediation roadmap
- Executive summary for decision-makers

## Engagement options

### Discovery workshop

- 90-minute working session
- Initial architecture and risk assessment
- Summary of priority questions and next actions
- Indicative fee: **EUR 600–900**, depending on preparation and scope

### Full architecture review

- Typical duration: **5–10 working days**
- Indicative fee: **EUR 3,000–6,000**, confirmed after discovery

These ranges are initial commercial hypotheses and may be adjusted to the system complexity, number of integrations, and evidence available.

## Demonstrated approach

The review methodology is supported by a working Zero-Trust Agent Security proof of concept covering:

- sandboxed, read-only agent containers;
- isolated Docker network segments;
- short-lived RS256 workload identity tokens;
- per-agent authorisation and scope enforcement;
- credential isolation through a trusted broker;
- policy enforcement and human approval;
- strict argument and Salesforce resource validation;
- SSRF, path-injection, impersonation, and privilege-escalation tests;
- sanitised audit evidence.

[View the Zero-Trust Agent Security POC](GITHUB_REPOSITORY_URL)

## Next step

Book a 20-minute introductory call to discuss your agent use case, current architecture, and production-readiness concerns.

**Friend Agent**  
[friend-agent.com](https://www.friend-agent.com/)  
[contact@friend-agent.com](mailto:contact@friend-agent.com)
