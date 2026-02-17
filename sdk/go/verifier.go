package protocolgo

import (
	"crypto/ed25519"
	"time"
)

type OfflineVerifyInput struct {
	Capability         Capability
	Action             ActionEnvelope
	IssuerPublicKey    ed25519.PublicKey
	AgentPublicKey     ed25519.PublicKey
	ReferenceTime      time.Time
	ExpectedAudience   string
	ExpectedPolicyHash string
	KeyResolver        IssuerKeyResolver
	RevocationList     RevocationChecker
	ReplayCache        ReplayCache
	ReplayWindow       time.Duration
	ChallengePolicy    ChallengePolicy
	PolicyEvaluator    PolicyEvaluator
	Transparency       TransparencyVerifier
}

func OfflineVerify(input OfflineVerifyInput) VerificationResult {
	engine := NewEngine()
	return engine.Verify(VerifyRequest{
		Capability:         input.Capability,
		Action:             input.Action,
		IssuerPublicKey:    input.IssuerPublicKey,
		AgentPublicKey:     input.AgentPublicKey,
		ReferenceTime:      input.ReferenceTime.UTC(),
		ExpectedAudience:   input.ExpectedAudience,
		ExpectedPolicyHash: input.ExpectedPolicyHash,
		KeyResolver:        input.KeyResolver,
		RevocationList:     input.RevocationList,
		ReplayCache:        input.ReplayCache,
		ReplayWindow:       input.ReplayWindow,
		ChallengePolicy:    input.ChallengePolicy,
		PolicyEvaluator:    input.PolicyEvaluator,
		Transparency:       input.Transparency,
	})
}
