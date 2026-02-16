# Examples

Runnable examples for local, deterministic protocol verification.

## `local-verify`

Path: `examples/local-verify`

What it demonstrates:

- Capability signing
- Action envelope signing
- Trust bundle signing and local key resolution
- Offline verification with deterministic results
- Deny paths for replay, audience mismatch, and challenge-required flows

Run:

```bash
go run ./examples/local-verify
```

## `trust-bundle-fallback`

Path: `examples/trust-bundle-fallback`

What it demonstrates:

- Trust bundle fetch-and-validate flow
- Cache fallback when fetch fails
- Local issuer key resolution from cached trust bundle

Run:

```bash
go run ./examples/trust-bundle-fallback
```
