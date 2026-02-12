package action_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor/internal/action"
	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor/internal/crypto"
	"github.com/ignyte-solutions/ignyte-anchor/internal/domain"
)

func TestSignAndVerify(t *testing.T) {
	agentPublicKey, agentPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent key pair: %v", err)
	}
	agentID, err := anchorcrypto.DeriveIDFromPublicKey(agentPublicKey)
	if err != nil {
		t.Fatalf("derive agent id: %v", err)
	}

	actionEnvelope := domain.ActionEnvelope{
		AgentID:      agentID,
		CapabilityID: "capability-id",
		ActionType:   "s3:PutObject",
		ActionPayload: json.RawMessage(`{
			"bucket":"example-bucket",
			"key":"demo.txt",
			"bytes": 512
		}`),
		ConstraintEvidence: domain.ConstraintEvidence{
			ResourceUsage: map[string]int64{"s3:objects": 1},
			SpendUsage:    map[string]int64{"usd_cents": 1},
			RateUsage:     map[string]int64{"requests_per_minute": 1},
			Environment:   "prod",
			APIScope:      "aws:s3",
		},
		Timestamp: time.Date(2026, 2, 12, 17, 15, 0, 0, time.UTC),
	}

	if err = action.Sign(&actionEnvelope, agentPrivateKey); err != nil {
		t.Fatalf("sign action envelope: %v", err)
	}
	if actionEnvelope.ActionID == "" {
		t.Fatal("expected action_id to be populated")
	}
	if actionEnvelope.AgentSignature == "" {
		t.Fatal("expected agent_signature to be populated")
	}

	ok, err := action.Verify(actionEnvelope, agentPublicKey)
	if err != nil {
		t.Fatalf("verify action envelope: %v", err)
	}
	if !ok {
		t.Fatal("expected action envelope verification to pass")
	}
}

func TestVerifyRejectsTamperedActionPayload(t *testing.T) {
	agentPublicKey, agentPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent key pair: %v", err)
	}
	agentID, err := anchorcrypto.DeriveIDFromPublicKey(agentPublicKey)
	if err != nil {
		t.Fatalf("derive agent id: %v", err)
	}
	envelope := domain.ActionEnvelope{
		AgentID:      agentID,
		CapabilityID: "capability-id",
		ActionType:   "s3:PutObject",
		ActionPayload: json.RawMessage(`{
			"bucket":"example-bucket",
			"key":"demo.txt",
			"bytes": 512
		}`),
		ConstraintEvidence: domain.ConstraintEvidence{
			ResourceUsage: map[string]int64{"s3:objects": 1},
			SpendUsage:    map[string]int64{"usd_cents": 1},
			RateUsage:     map[string]int64{"requests_per_minute": 1},
			Environment:   "prod",
			APIScope:      "aws:s3",
		},
		Timestamp: time.Date(2026, 2, 12, 17, 15, 0, 0, time.UTC),
	}
	if err = action.Sign(&envelope, agentPrivateKey); err != nil {
		t.Fatalf("sign action envelope: %v", err)
	}
	envelope.ActionPayload = json.RawMessage(`{"bucket":"example-bucket","key":"demo.txt","bytes":2048}`)

	ok, err := action.Verify(envelope, agentPublicKey)
	if err != nil {
		t.Fatalf("verify action envelope: %v", err)
	}
	if ok {
		t.Fatal("expected tampered action verification to fail")
	}
}
