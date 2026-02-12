# TRUST_MODEL

## Principle

Protocol validity and trust acceptance are separate.

- Validity: cryptographic correctness of artifacts.
- Trust: local policy decision about accepted issuers.

## Trust sources

- Static issuer allowlists
- Signed trust bundles
- Local revocation overlays

## Registry relationship

Registry metadata can assist trust decisions but does not automatically grant trust.

## Offline operation

Verifiers must continue operating with cached signed trust bundles until bundle expiry.
