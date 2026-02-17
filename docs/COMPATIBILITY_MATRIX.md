# COMPATIBILITY MATRIX

Protocol major version in this repository: v2.

| SDK | Capability | ActionEnvelope | VerificationResult | TrustBundle | Offline Verify | Reason-Code Parity Gate |
| --- | --- | --- | --- | --- | --- | --- |
| Go | Yes | Yes | Yes | Yes | Yes | Yes |
| TypeScript | Yes | Yes | Yes | Yes | Yes | Yes |
| Python | Yes | Yes | Yes | Yes | Yes | Yes |
| Java | Yes | Yes | Yes | Yes | Yes | Yes |

## Conformance requirement

Each SDK release must pass:
- core vector suite (`conformance/tests/vector_test.go`)
- multi-system deterministic suite (`conformance/tests/multisystem_workflow_test.go`)
- reason-code parity suite (`conformance/tests/sdk_parity_test.go`)

## Compatibility promise

Minor and patch releases preserve v2 verification semantics.
Breaking semantic changes require a new major protocol version and migration guide updates.
