# SECURITY_BEST_PRACTICES

1. Keep issuer signing keys in KMS/HSM or equivalent isolated signing systems.
2. Use short capability TTLs for sensitive scopes.
3. Enable replay cache for all production verifiers.
4. Pin trusted issuers by `issuer_id` and `issuer_kid`.
5. Rotate issuer keys with overlap windows and publish updated trust bundles.
6. Use challenge mode for high-risk destructive actions.
