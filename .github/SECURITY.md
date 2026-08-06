# Security Policy

AgentGuard is prerelease security software. It is not production-certified and must be deployed behind independent identity, secret-management, network, process, and operating-system controls.

## Supported versions

Security fixes are evaluated for the current `main` branch and the latest maintained prerelease. Older prereleases and the v0.1 compatibility surface may receive fixes only when the issue affects the maintained code path.

## Report a vulnerability

Do not open a public issue.

Use GitHub private vulnerability reporting when it is available. Otherwise contact the repository owner through a verified private channel.

Include:

- affected version or commit;
- reproduction steps or a minimal proof of concept;
- expected and observed behavior;
- security impact and realistic attack conditions;
- suggested remediation, when known.

Do not include live credentials, private keys, personal data, customer data, or production secrets. Use synthetic test data.

## Response expectations

There is no commercial support or response-time SLA. Reports will be triaged according to reproducibility, exploitability, affected trust boundary, and potential impact. Public disclosure should occur only after a remediation and release plan is agreed.

## Deployment responsibility

AgentGuard does not replace process isolation, network egress controls, secret-manager policy, identity proofing, centralized transactional state, or an independent audit/checkpoint store.
