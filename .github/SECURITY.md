# Security Policy

AgentGuard is prerelease security software. It is not production-certified and must be deployed behind independent identity, secret-management, network, process, and operating-system controls.

## Supported versions

Security fixes are evaluated for the current `main` branch and the latest maintained prerelease. Older prereleases and the v0.1 compatibility surface may receive fixes only when the issue affects the maintained code path.

## Report a vulnerability

Do not open a public issue containing vulnerability details.

Use GitHub private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Select **Advisories**.
3. Select **Report a vulnerability** and submit the report privately.

If the private-reporting button is unavailable, open a minimal public issue titled `Private security contact request` without technical details, affected versions, reproduction steps, names, credentials, or evidence. The maintainer will provide a private channel before any sensitive information is shared.

Include in the private report:

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
