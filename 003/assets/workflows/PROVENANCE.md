# Workflow fixture provenance

These workflow fixtures were authored for Gym 003 against the official n8n
1.65.0 source and its built-in Form Trigger, Webhook, HTTP Request, and Respond
to Webhook nodes. They contain no community nodes or downloaded executable
content.

The fixtures use only built-in node types defined by the official n8n 1.65.0 source:
<https://github.com/n8n-io/n8n/tree/n8n%401.65.0/packages/nodes-base/nodes>.
No third-party workflow bundle or community node was downloaded.

The fixed expression verifier is implemented in reviewed Python code rather
than copied from third-party proof-of-concept repositories. Its behavior is
derived from n8n's official CVE-2025-68613 fix, which binds function expressions
to an empty context and blocks the `mainModule` property.
