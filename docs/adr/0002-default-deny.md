# ADR 0002: Default deny

Policy v2 has no permissive default. Unknown actions, capabilities, provenance and effect projections fail closed or require explicit approval according to documented policy defaults.

Phase 0 alignment: the legacy v1 policy model previously defaulted `default_action` to `allow` when
the key was absent, which was fail-open in a project whose stated posture is default-deny. The v1
loader and the `Policy` dataclass now default to `deny`, and every shipped v1 example policy and
policy pack carries an explicit `allowed_tools` allowlist so that no unmatched tool is authorized by
omission. Policy v2 is unchanged and remains structurally default-deny
(`PolicyDefaults.effect` is `Literal[Effect.DENY]`).
