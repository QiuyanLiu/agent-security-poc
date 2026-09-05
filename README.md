flowchart TD
    U["MCP Client"] --> I["MCP Ingress"]
    I --> A["Sandboxed Agent"]
    A --> G["Policy Gateway"]
    G --> B["Credential Broker"]
    B --> S["Salesforce"]
    G --> L["Audit Logs"]