# SECURITY DISCLOSURE

Version: 1.0

## Reporting

Report vulnerabilities privately to the maintainers listed in repository governance.

Required report details:
- affected protocol artifact (`spec`, `core/v2`, `sdk/<lang>`)
- exploit prerequisites
- deterministic reproduction steps
- expected vs actual verifier behavior

## Response targets
- Initial acknowledgement: within 3 business days.
- Triage status update: within 7 business days.
- Patch and advisory timeline: risk-based, coordinated with maintainers.

## Coordination policy
- No public issue disclosure before maintainer acknowledgment.
- Security fixes must include conformance vectors when verifier semantics are affected.
- Security patch releases must increment semantic version and include migration notes if behavior changes.

## Scope boundaries
In scope:
- signature verification bypasses
- audience/policy/delegation enforcement bypasses
- replay or key-window validation bypasses
- trust-bundle signature or expiry validation bypasses

Out of scope:
- vulnerability claims requiring non-standard verifier modifications
- host application misconfiguration outside protocol interfaces
