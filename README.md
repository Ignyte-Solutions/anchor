# Ignyte Anchor Protocol

Ignyte Anchor Protocol is an open, locally verifiable delegated-authority protocol for autonomous systems.

## Core guarantees

- Verification is deterministic and offline-capable.
- No network calls are required to verify `CapabilityV2 + ActionEnvelopeV2`.
- Trust policy is local (verifier-selected issuer trust set).
- Protocol verification is always free and open.

## Repository layout

- `core/`: canonicalization, crypto helpers, v2 signing + verification
- `spec/`: JSON schemas and reason-code registry
- `conformance/`: vectors + automated checks
- `sdk/`: language SDKs (Go/TypeScript/Python/Java)
- `examples/`: local verification examples
- `docs/`: deep protocol and security documentation

## Quick start

```bash
go test ./...
```

## Versioning

Protocol artifacts use semantic versioning and normative docs in this repository are source-of-truth for v2.

## License

Apache-2.0. See `LICENSE`.
