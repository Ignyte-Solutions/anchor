package v2_test

import (
	"testing"
	"time"

	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor-protocol/core/crypto"
	"github.com/ignyte-solutions/ignyte-anchor-protocol/core/v2"
)

func TestSignAndVerifyTrustBundle(t *testing.T) {
	signerPublic, signerPrivate, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate signer keypair: %v", err)
	}
	issuedAt := time.Date(2026, 2, 13, 6, 0, 0, 0, time.UTC)
	bundle := v2.TrustBundle{
		BundleID:           "bundle-1",
		IssuedAt:           issuedAt,
		ExpiresAt:          issuedAt.Add(1 * time.Hour),
		SignerPublicKeyKID: "signer-k1",
		Issuers: []v2.TrustBundleIssuer{
			{
				IssuerID:      "issuer-1",
				IssuerKID:     "k1",
				PublicKey:     anchorcrypto.PublicKeyToBase64(signerPublic),
				ValidFrom:     issuedAt,
				ValidUntil:    issuedAt.Add(1 * time.Hour),
				AssuranceTier: "ORG_VERIFIED",
			},
		},
		RevocationPointers: []string{"https://revocations.example.com/list.json"},
	}
	if err := v2.SignTrustBundle(&bundle, signerPrivate); err != nil {
		t.Fatalf("sign bundle: %v", err)
	}
	valid, err := v2.VerifyTrustBundleSignature(bundle, signerPublic)
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if !valid {
		t.Fatal("expected trust bundle signature valid")
	}
}
