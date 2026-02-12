package runtime

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor/internal/action"
	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor/internal/crypto"
	"github.com/ignyte-solutions/ignyte-anchor/internal/domain"
)

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now().UTC()
}

type Runtime struct {
	agentPrivateKey ed25519.PrivateKey
	agentPublicKey  ed25519.PublicKey
	agentID         string
	clock           Clock
}

type ActionRequest struct {
	CapabilityID       string                    `json:"capability_id"`
	ActionType         string                    `json:"action_type"`
	ActionPayload      json.RawMessage           `json:"action_payload"`
	ConstraintEvidence domain.ConstraintEvidence `json:"constraint_evidence"`
}

func New(agentPrivateKey ed25519.PrivateKey, clock Clock) (*Runtime, error) {
	if len(agentPrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("agent private key must be %d bytes", ed25519.PrivateKeySize)
	}
	if clock == nil {
		return nil, fmt.Errorf("clock is required")
	}
	agentPublicKey := agentPrivateKey.Public().(ed25519.PublicKey)
	agentID, err := anchorcrypto.DeriveIDFromPublicKey(agentPublicKey)
	if err != nil {
		return nil, err
	}
	return &Runtime{
		agentPrivateKey: agentPrivateKey,
		agentPublicKey:  agentPublicKey,
		agentID:         agentID,
		clock:           clock,
	}, nil
}

func (r *Runtime) Agent() (domain.Agent, error) {
	if r == nil {
		return domain.Agent{}, fmt.Errorf("runtime is required")
	}
	return domain.Agent{
		AgentID:   r.agentID,
		PublicKey: anchorcrypto.PublicKeyToBase64(r.agentPublicKey),
	}, nil
}

func (r *Runtime) CreateActionEnvelope(request ActionRequest) (domain.ActionEnvelope, error) {
	if r == nil {
		return domain.ActionEnvelope{}, fmt.Errorf("runtime is required")
	}
	if request.CapabilityID == "" {
		return domain.ActionEnvelope{}, fmt.Errorf("capability_id is required")
	}
	if request.ActionType == "" {
		return domain.ActionEnvelope{}, fmt.Errorf("action_type is required")
	}
	if len(request.ActionPayload) == 0 {
		return domain.ActionEnvelope{}, fmt.Errorf("action_payload is required")
	}
	if !json.Valid(request.ActionPayload) {
		return domain.ActionEnvelope{}, fmt.Errorf("action_payload must be valid JSON")
	}
	if err := request.ConstraintEvidence.Validate(); err != nil {
		return domain.ActionEnvelope{}, err
	}
	envelope := domain.ActionEnvelope{
		AgentID:            r.agentID,
		CapabilityID:       request.CapabilityID,
		ActionType:         request.ActionType,
		ActionPayload:      request.ActionPayload,
		ConstraintEvidence: request.ConstraintEvidence,
		Timestamp:          r.clock.Now().UTC(),
	}
	if err := action.Sign(&envelope, r.agentPrivateKey); err != nil {
		return domain.ActionEnvelope{}, err
	}
	return envelope, nil
}
