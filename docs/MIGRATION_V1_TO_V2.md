# MIGRATION_V1_TO_V2

## Breaking changes

- New required fields: `issuer_kid`, `audience`, `policy_hash`.
- New verifier output fields: `reason_codes`, `replay_status`, `policy_hash_seen`.
- Delegation and trust-bundle aware verification model.

## Migration steps

1. Upgrade issuers to emit v2 capabilities.
2. Upgrade agents to emit v2 action envelopes.
3. Deploy v2 local verifier with trust bundle support.
4. Validate with conformance vectors.
