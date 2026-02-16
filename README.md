# Ignyte Anchor Protocol

[![CI](https://github.com/Ignyte-Solutions/anchor/actions/workflows/ci.yml/badge.svg)](https://github.com/Ignyte-Solutions/anchor/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/Ignyte-Solutions/anchor/blob/master/LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.24.6-00ADD8)](https://go.dev/)
[![Protocol: v2](https://img.shields.io/badge/protocol-v2-0ea5e9.svg)](https://github.com/Ignyte-Solutions/anchor/tree/master/spec)
[![Security Policy](https://img.shields.io/badge/security-policy-16a34a.svg)](https://github.com/Ignyte-Solutions/anchor/blob/master/SECURITY.md)
[![Contributing](https://img.shields.io/badge/contributions-welcome-0891b2.svg)](https://github.com/Ignyte-Solutions/anchor/blob/master/CONTRIBUTING.md)

Open protocol for deterministic, offline verification of AI agent authorization.

Ignyte Anchor Protocol is the verification substrate. It lets any host platform verify signed delegated permissions locally, without relying on a central authorization API at decision time.

## Why this exists

Most agent authorization systems return an allow/deny decision from a centralized service. That is useful, but it does not give verifiers implementation-independent proof they can validate locally.

Ignyte Anchor Protocol is designed around this model:

- Issuers sign capabilities.
- Agents submit signed actions.
- Verifiers evaluate both artifacts locally with deterministic rules.
- Trust policy remains fully local to the verifier.

## Core guarantees

- Local and offline verifiability for `CapabilityV2 + ActionEnvelopeV2`.
- Deterministic verification outcomes for identical inputs and trust policy.
- Machine-readable reason codes for integration and audit pipelines.
- No payment or network dependency for protocol verification.

## Repository structure

- `core/`: canonicalization, hashing, signing, verification logic
- `spec/`: JSON schemas and reason-code registry
- `sdk/`: Go, TypeScript, Python, and Java SDK surface
- `conformance/`: vectors, fixtures, and parity tests
- `examples/`: integration examples for local verification
- `docs/`: normative spec, threat model, trust model, governance
- `examples/README.md`: runnable example catalog

## Quick start

Prerequisites:

- Go `1.24.6+`
- Git

Run protocol and conformance tests:

```bash
go test ./...
```

Run the local verification example:

```bash
go run ./examples/local-verify
```

Run the trust bundle fallback example:

```bash
go run ./examples/trust-bundle-fallback
```

## v2 protocol artifacts

- Capability schema: `spec/schemas/capability-v2.schema.json`
- Action envelope schema: `spec/schemas/action-envelope-v2.schema.json`
- Trust bundle schema: `spec/schemas/trust-bundle-v1.schema.json`
- Reason codes: `spec/reason-codes/reason-codes-v2.json`

## SDK status

| SDK | Path | Local verification |
| --- | --- | --- |
| Go | `sdk/go` | Yes |
| TypeScript | `sdk/typescript` | Yes |
| Python | `sdk/python` | Yes |
| Java | `sdk/java` | Yes |

Conformance and compatibility references:

- `docs/CONFORMANCE.md`
- `docs/COMPATIBILITY_MATRIX.md`

## Documentation

- Protocol specification: `docs/SPEC.md`
- Threat model: `docs/THREAT_MODEL.md`
- Trust model: `docs/TRUST_MODEL.md`
- Integration patterns: `docs/INTEGRATION_PATTERNS.md`
- Security practices: `docs/SECURITY_BEST_PRACTICES.md`
- Versioning policy: `docs/VERSIONING.md`
- Governance model: `docs/GOVERNANCE.md`
- Migration v1 to v2: `docs/MIGRATION_V1_TO_V2.md`
- Proof sketch and invariants: `docs/PROOF_SKETCH.md`

## Release and compatibility policy

This repository uses semantic versioning for protocol and SDK artifacts. Breaking protocol changes are versioned explicitly and require migration guidance and conformance updates.

See:

- `docs/VERSIONING.md`
- `docs/COMPATIBILITY_MATRIX.md`
- `docs/SECURITY_DISCLOSURE.md`

## Security

If you discover a vulnerability, do not open a public issue.

Follow:

- `SECURITY.md`

## Contributing

Contributions are welcome. Start with:

- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `SUPPORT.md`

## License

Apache-2.0. See `LICENSE`.
