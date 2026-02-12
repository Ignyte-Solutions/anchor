package capability_test

import (
	"testing"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor/internal/capability"
	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor/internal/crypto"
	"github.com/ignyte-solutions/ignyte-anchor/internal/domain"
)

func TestSignAndVerify(t *testing.T) {
	issuerPublicKey, issuerPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate issuer key pair: %v", err)
	}
	agentPublicKey, _, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent key pair: %v", err)
	}
	issuerID, err := anchorcrypto.DeriveIDFromPublicKey(issuerPublicKey)
	if err != nil {
		t.Fatalf("derive issuer id: %v", err)
	}
	agentID, err := anchorcrypto.DeriveIDFromPublicKey(agentPublicKey)
	if err != nil {
		t.Fatalf("derive agent id: %v", err)
	}

	capabilityToken := domain.Capability{
		Version:        domain.CapabilityVersion,
		IssuerID:       issuerID,
		AgentID:        agentID,
		AllowedActions: []string{"ec2:DescribeInstances", "s3:PutObject"},
		Constraints: domain.CapabilityConstraints{
			ResourceLimits:         map[string]int64{"s3:objects": 5},
			SpendLimits:            map[string]int64{"usd_cents": 500},
			APIScopes:              []string{"aws:s3"},
			RateLimits:             map[string]int64{"requests_per_minute": 60},
			EnvironmentConstraints: []string{"prod"},
		},
		IssuedAt:  time.Date(2026, 2, 12, 17, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 2, 12, 18, 0, 0, 0, time.UTC),
		Nonce:     "test-nonce",
	}
	if err = capability.Sign(&capabilityToken, issuerPrivateKey); err != nil {
		t.Fatalf("sign capability: %v", err)
	}
	if capabilityToken.CapabilityID == "" {
		t.Fatal("expected capability_id to be populated")
	}
	if capabilityToken.Signature == "" {
		t.Fatal("expected signature to be populated")
	}

	ok, err := capability.Verify(capabilityToken, issuerPublicKey)
	if err != nil {
		t.Fatalf("verify capability: %v", err)
	}
	if !ok {
		t.Fatal("expected capability signature to verify")
	}
}

func TestVerifyRejectsTamperedCapability(t *testing.T) {
	issuerPublicKey, issuerPrivateKey, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate issuer key pair: %v", err)
	}
	agentPublicKey, _, err := anchorcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate agent key pair: %v", err)
	}
	issuerID, err := anchorcrypto.DeriveIDFromPublicKey(issuerPublicKey)
	if err != nil {
		t.Fatalf("derive issuer id: %v", err)
	}
	agentID, err := anchorcrypto.DeriveIDFromPublicKey(agentPublicKey)
	if err != nil {
		t.Fatalf("derive agent id: %v", err)
	}

	capabilityToken := domain.Capability{
		Version:        domain.CapabilityVersion,
		IssuerID:       issuerID,
		AgentID:        agentID,
		AllowedActions: []string{"s3:PutObject"},
		Constraints: domain.CapabilityConstraints{
			ResourceLimits:         map[string]int64{"s3:objects": 5},
			SpendLimits:            map[string]int64{"usd_cents": 500},
			APIScopes:              []string{"aws:s3"},
			RateLimits:             map[string]int64{"requests_per_minute": 60},
			EnvironmentConstraints: []string{"prod"},
		},
		IssuedAt:  time.Date(2026, 2, 12, 17, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 2, 12, 18, 0, 0, 0, time.UTC),
		Nonce:     "test-nonce",
	}
	if err = capability.Sign(&capabilityToken, issuerPrivateKey); err != nil {
		t.Fatalf("sign capability: %v", err)
	}

	capabilityToken.AllowedActions = []string{"ec2:TerminateInstances"}
	ok, err := capability.Verify(capabilityToken, issuerPublicKey)
	if err != nil {
		t.Fatalf("verify capability: %v", err)
	}
	if ok {
		t.Fatal("expected tampered capability verification to fail")
	}
}
