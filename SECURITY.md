# Security Policy

AgentGuard is a local-first security control for AI-agent tool access. Security reports are taken
seriously, especially issues that could bypass policy decisions, leak secrets into audit output, or
execute tools that should have been denied.

## Supported Versions

AgentGuard is currently pre-1.0. Security fixes target the latest `main` branch until versioned
releases are introduced.

## Reporting A Vulnerability

Do not open a public issue for a vulnerability that could help an attacker bypass AgentGuard.

For now, report privately through GitHub's private vulnerability reporting if enabled on the
repository. If private reporting is not enabled, contact the maintainer directly and include:

- a concise description of the vulnerability;
- affected command or module;
- reproduction steps using local files only when possible;
- expected decision versus actual decision;
- whether secrets or tool execution are exposed.

## Security Scope

In scope:

- policy bypasses;
- unsafe MCP proxy forwarding;
- audit records containing unredacted secrets;
- crashes caused by malformed local MCP or JSONL input;
- path, environment variable, or network-host checks that fail open.

Out of scope:

- hosted dashboard vulnerabilities, because AgentGuard has no hosted service yet;
- vulnerabilities in third-party MCP servers that AgentGuard only launches as explicit argv;
- social-engineering reports without a technical bypass;
- denial of service from intentionally unbounded local disk usage outside AgentGuard's inputs.

## Secure Defaults

AgentGuard should remain dependency-light, fail closed for unsafe tool calls, avoid `shell=True`,
bound streamed MCP messages, redact secret-like output, and keep audit records local unless a user
explicitly exports them.
