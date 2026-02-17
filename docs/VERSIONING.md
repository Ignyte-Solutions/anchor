# VERSIONING

- Protocol major version increments for breaking schema/semantic changes.
- Protocol minor version increments for backward-compatible additions.
- SDKs must publish compatibility matrix against protocol versions.

`Capability`/`ActionEnvelope` in this repository currently implement protocol major version 2.

## SDK Compatibility Matrix

| SDK | Protocol v2 object model | Offline verifier |
| --- | --- | --- |
| Go | Supported | Native (`sdk/go`, backed by versioned core) |
| TypeScript | Supported | Supported (pluggable crypto provider) |
| Python | Supported | Supported (pluggable crypto provider) |
| Java | Supported | Supported (pluggable crypto provider) |

Detailed release gates and language status: `docs/COMPATIBILITY_MATRIX.md`.
