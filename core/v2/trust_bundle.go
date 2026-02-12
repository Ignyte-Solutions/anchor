package v2

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor-protocol/core/canonical"
	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor-protocol/core/crypto"
)

type trustBundleSignaturePayload struct {
	BundleID           string              `json:"bundle_id"`
	IssuedAt           string              `json:"issued_at"`
	ExpiresAt          string              `json:"expires_at"`
	Issuers            []TrustBundleIssuer `json:"issuers"`
	RevocationPointers []string            `json:"revocation_pointers"`
	SignerPublicKeyKID string              `json:"signer_public_key_kid"`
}

func SignTrustBundle(bundle *TrustBundle, signerPrivateKey ed25519.PrivateKey) error {
	if bundle == nil {
		return fmt.Errorf("trust bundle is required")
	}
	if bundle.BundleID == "" {
		return fmt.Errorf("bundle_id is required")
	}
	if bundle.IssuedAt.IsZero() || bundle.ExpiresAt.IsZero() {
		return fmt.Errorf("issued_at and expires_at are required")
	}
	if !bundle.ExpiresAt.After(bundle.IssuedAt) {
		return fmt.Errorf("expires_at must be after issued_at")
	}
	if len(bundle.Issuers) == 0 {
		return fmt.Errorf("issuers must not be empty")
	}
	if bundle.SignerPublicKeyKID == "" {
		return fmt.Errorf("signer_public_key_kid is required")
	}
	payload := trustBundleSignaturePayload{
		BundleID:           bundle.BundleID,
		IssuedAt:           bundle.IssuedAt.UTC().Format(timestampFormat),
		ExpiresAt:          bundle.ExpiresAt.UTC().Format(timestampFormat),
		Issuers:            bundle.Issuers,
		RevocationPointers: bundle.RevocationPointers,
		SignerPublicKeyKID: bundle.SignerPublicKeyKID,
	}
	data, err := canonical.Marshal(payload)
	if err != nil {
		return fmt.Errorf("canonical trust bundle signature payload: %w", err)
	}
	sig, err := anchorcrypto.SignBytes(signerPrivateKey, data)
	if err != nil {
		return err
	}
	bundle.Signature = sig
	return nil
}

func VerifyTrustBundleSignature(bundle TrustBundle, signerPublicKey ed25519.PublicKey) (bool, error) {
	if err := bundle.Validate(); err != nil {
		return false, err
	}
	payload := trustBundleSignaturePayload{
		BundleID:           bundle.BundleID,
		IssuedAt:           bundle.IssuedAt.UTC().Format(timestampFormat),
		ExpiresAt:          bundle.ExpiresAt.UTC().Format(timestampFormat),
		Issuers:            bundle.Issuers,
		RevocationPointers: bundle.RevocationPointers,
		SignerPublicKeyKID: bundle.SignerPublicKeyKID,
	}
	data, err := canonical.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("canonical trust bundle verify payload: %w", err)
	}
	return anchorcrypto.VerifySignature(signerPublicKey, data, bundle.Signature)
}

type TrustBundleKeyResolver struct {
	Bundle TrustBundle
}

func (r TrustBundleKeyResolver) Resolve(issuerID, issuerKID string, at time.Time) (ed25519.PublicKey, bool, error) {
	if at.After(r.Bundle.ExpiresAt) {
		return nil, false, fmt.Errorf("trust bundle expired")
	}
	for _, issuer := range r.Bundle.Issuers {
		if issuer.IssuerID != issuerID || issuer.IssuerKID != issuerKID {
			continue
		}
		if at.Before(issuer.ValidFrom) || at.After(issuer.ValidUntil) {
			return nil, false, nil
		}
		pk, err := anchorcrypto.PublicKeyFromBase64(issuer.PublicKey)
		if err != nil {
			return nil, false, err
		}
		return pk, true, nil
	}
	return nil, false, nil
}
