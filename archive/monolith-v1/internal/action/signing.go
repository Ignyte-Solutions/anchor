package action

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
	AgentID            string                    `json:"agent_id"`
	CapabilityID       string                    `json:"capability_id"`
	ActionType         string                    `json:"action_type"`
	ActionPayload      []byte                    `json:"action_payload"`
	ConstraintEvidence domain.ConstraintEvidence `json:"constraint_evidence"`
	Timestamp          string                    `json:"timestamp"`
}

type signaturePayload struct {
	ActionID           string                    `json:"action_id"`
	AgentID            string                    `json:"agent_id"`
	CapabilityID       string                    `json:"capability_id"`
	ActionType         string                    `json:"action_type"`
	ActionPayload      []byte                    `json:"action_payload"`
	ConstraintEvidence domain.ConstraintEvidence `json:"constraint_evidence"`
	Timestamp          string                    `json:"timestamp"`
}

func normalizeActionPayload(payload []byte) ([]byte, error) {
	canonicalPayload, err := canonical.MarshalRawJSON(payload)
	if err != nil {
		return nil, fmt.Errorf("canonical action payload: %w", err)
	}
	return canonicalPayload, nil
}

func ComputeID(envelope domain.ActionEnvelope) (string, error) {
	if err := envelope.ValidateUnsigned(); err != nil {
		return "", err
	}
	canonicalPayload, err := normalizeActionPayload(envelope.ActionPayload)
	if err != nil {
		return "", err
	}
	payload := idPayload{
		AgentID:            envelope.AgentID,
		CapabilityID:       envelope.CapabilityID,
		ActionType:         envelope.ActionType,
		ActionPayload:      canonicalPayload,
		ConstraintEvidence: envelope.ConstraintEvidence,
		Timestamp:          envelope.Timestamp.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
	}
	canonicalJSON, err := canonical.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("canonical action id payload: %w", err)
	}
	hash := sha256.Sum256(canonicalJSON)
	return hex.EncodeToString(hash[:]), nil
}

func Sign(envelope *domain.ActionEnvelope, privateKey ed25519.PrivateKey) error {
	if envelope == nil {
		return fmt.Errorf("action envelope is required")
	}
	if err := envelope.ValidateUnsigned(); err != nil {
		return err
	}
	canonicalPayload, err := normalizeActionPayload(envelope.ActionPayload)
	if err != nil {
		return err
	}
	envelope.ActionPayload = canonicalPayload
	actionID, err := ComputeID(*envelope)
	if err != nil {
		return err
	}
	envelope.ActionID = actionID
	payload := signaturePayload{
		ActionID:           envelope.ActionID,
		AgentID:            envelope.AgentID,
		CapabilityID:       envelope.CapabilityID,
		ActionType:         envelope.ActionType,
		ActionPayload:      envelope.ActionPayload,
		ConstraintEvidence: envelope.ConstraintEvidence,
		Timestamp:          envelope.Timestamp.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
	}
	canonicalJSON, err := canonical.Marshal(payload)
	if err != nil {
		return fmt.Errorf("canonical action signature payload: %w", err)
	}
	signature, err := anchorcrypto.SignBytes(privateKey, canonicalJSON)
	if err != nil {
		return err
	}
	envelope.AgentSignature = signature
	return nil
}

func Verify(envelope domain.ActionEnvelope, agentPublicKey ed25519.PublicKey) (bool, error) {
	if envelope.AgentSignature == "" {
		return false, fmt.Errorf("agent_signature is required")
	}
	if envelope.ActionID == "" {
		return false, fmt.Errorf("action_id is required")
	}
	if err := envelope.ValidateUnsigned(); err != nil {
		return false, err
	}
	canonicalPayload, err := normalizeActionPayload(envelope.ActionPayload)
	if err != nil {
		return false, err
	}
	envelope.ActionPayload = canonicalPayload
	recomputedID, err := ComputeID(envelope)
	if err != nil {
		return false, err
	}
	if envelope.ActionID != recomputedID {
		return false, nil
	}
	payload := signaturePayload{
		ActionID:           envelope.ActionID,
		AgentID:            envelope.AgentID,
		CapabilityID:       envelope.CapabilityID,
		ActionType:         envelope.ActionType,
		ActionPayload:      envelope.ActionPayload,
		ConstraintEvidence: envelope.ConstraintEvidence,
		Timestamp:          envelope.Timestamp.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
	}
	canonicalJSON, err := canonical.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("canonical action verify payload: %w", err)
	}
	return anchorcrypto.VerifySignature(agentPublicKey, canonicalJSON, envelope.AgentSignature)
}
