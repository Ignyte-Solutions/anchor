# SDKs

This repository includes protocol SDKs for:

- Go
- TypeScript
- Python
- Java

Each SDK includes:
- Hosted API transport helper client.
- Offline/local verifier surface that enforces audience binding, delegation depth, policy hash checks, constraint checks, challenge policy, replay signals, and deterministic reason-code output.

For non-Go SDKs, signature and key-identity math are intentionally injected through pluggable crypto interfaces so host applications can bind to approved crypto providers without changing verifier semantics.
