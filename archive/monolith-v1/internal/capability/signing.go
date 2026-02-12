package capability

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/ignyte-solutions/ignyte-anchor/internal/canonical"
	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor/internal/crypto"
	"github.com/ignyte-solutions/ignyte-anchor/internal/domain"
)

type idPayload struct {
	Version        int                          `json:"version"`
	IssuerID       string                       `json:"issuer_id"`
	AgentID        string                       `json:"agent_id"`
	AllowedActions []string                     `json:"allowed_actions"`
	Constraints    domain.CapabilityConstraints `json:"constraints"`
	IssuedAt       string                       `json:"issued_at"`
	ExpiresAt      string                       `json:"expires_at"`
	Nonce          string                       `json:"nonce"`
}

type signaturePayload struct {
	Version        int                          `json:"version"`
	CapabilityID   string                       `json:"capability_id"`
	IssuerID       string                       `json:"issuer_id"`
	AgentID        string                       `json:"agent_id"`
	AllowedActions []string                     `json:"allowed_actions"`
	Constraints    domain.CapabilityConstraints `json:"constraints"`
	IssuedAt       string                       `json:"issued_at"`
	ExpiresAt      string                       `json:"expires_at"`
	Nonce          string                       `json:"nonce"`
}

func ComputeID(capability domain.Capability) (string, error) {
	if err := capability.ValidateUnsigned(); err != nil {
		return "", err
	}
	payload := idPayload{
		Version:        capability.Version,
		IssuerID:       capability.IssuerID,
		AgentID:        capability.AgentID,
		AllowedActions: capability.AllowedActions,
		Constraints:    capability.Constraints,
		IssuedAt:       capability.IssuedAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		ExpiresAt:      capability.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		Nonce:          capability.Nonce,
	}
	canonicalJSON, err := canonical.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("canonical capability id payload: %w", err)
	}
	hash := sha256.Sum256(canonicalJSON)
	return hex.EncodeToString(hash[:]), nil
}

func Sign(capability *domain.Capability, privateKey ed25519.PrivateKey) error {
	if capability == nil {
		return fmt.Errorf("capability is required")
	}
	if err := capability.ValidateUnsigned(); err != nil {
		return err
	}
	capabilityID, err := ComputeID(*capability)
	if err != nil {
		return err
	}
	capability.CapabilityID = capabilityID
	signedPayload := signaturePayload{
		Version:        capability.Version,
		CapabilityID:   capability.CapabilityID,
		IssuerID:       capability.IssuerID,
		AgentID:        capability.AgentID,
		AllowedActions: capability.AllowedActions,
		Constraints:    capability.Constraints,
		IssuedAt:       capability.IssuedAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		ExpiresAt:      capability.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		Nonce:          capability.Nonce,
	}
	canonicalJSON, err := canonical.Marshal(signedPayload)
	if err != nil {
		return fmt.Errorf("canonical capability signature payload: %w", err)
	}
	signature, err := anchorcrypto.SignBytes(privateKey, canonicalJSON)
	if err != nil {
		return err
	}
	capability.Signature = signature
	return nil
}

func Verify(capability domain.Capability, issuerPublicKey ed25519.PublicKey) (bool, error) {
	if capability.Signature == "" {
		return false, fmt.Errorf("capability signature is required")
	}
	if capability.CapabilityID == "" {
		return false, fmt.Errorf("capability_id is required")
	}
	if err := capability.ValidateUnsigned(); err != nil {
		return false, err
	}
	recomputedID, err := ComputeID(capability)
	if err != nil {
		return false, err
	}
	if capability.CapabilityID != recomputedID {
		return false, nil
	}
	payload := signaturePayload{
		Version:        capability.Version,
		CapabilityID:   capability.CapabilityID,
		IssuerID:       capability.IssuerID,
		AgentID:        capability.AgentID,
		AllowedActions: capability.AllowedActions,
		Constraints:    capability.Constraints,
		IssuedAt:       capability.IssuedAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		ExpiresAt:      capability.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		Nonce:          capability.Nonce,
	}
	canonicalJSON, err := canonical.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("canonical capability verify payload: %w", err)
	}
	return anchorcrypto.VerifySignature(issuerPublicKey, canonicalJSON, capability.Signature)
}
