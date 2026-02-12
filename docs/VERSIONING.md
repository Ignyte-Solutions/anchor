# VERSIONING

- Protocol major version increments for breaking schema/semantic changes.
- Protocol minor version increments for backward-compatible additions.
- SDKs must publish compatibility matrix against protocol versions.

`CapabilityV2`/`ActionEnvelopeV2` define protocol major version 2.

## SDK Compatibility Matrix

| SDK | Protocol v2 object model | Offline verifier |
| --- | --- | --- |
| Go | Supported | Native (`core/v2` wrapper) |
| TypeScript | Supported | Supported (pluggable crypto provider) |
| Python | Supported | Supported (pluggable crypto provider) |
| Java | Supported | Supported (pluggable crypto provider) |
