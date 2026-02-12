package protocolgo

import (
	"crypto/ed25519"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor-protocol/core/v2"
)

type OfflineVerifyInput struct {
	Capability         v2.Capability
	Action             v2.ActionEnvelope
	AgentPublicKey     ed25519.PublicKey
	ExpectedAudience   string
	ExpectedPolicyHash string
	KeyResolver        v2.IssuerKeyResolver
	ReplayCache        v2.ReplayCache
	ReplayWindow       time.Duration
	ChallengePolicy    v2.ChallengePolicy
	PolicyEvaluator    v2.PolicyEvaluator
	Transparency       v2.TransparencyVerifier
}

func OfflineVerify(input OfflineVerifyInput) v2.VerificationResult {
	engine := v2.NewEngine()
	return engine.Verify(v2.VerifyRequest{
		Capability:         input.Capability,
		Action:             input.Action,
		AgentPublicKey:     input.AgentPublicKey,
		ReferenceTime:      input.Action.Timestamp,
		ExpectedAudience:   input.ExpectedAudience,
		ExpectedPolicyHash: input.ExpectedPolicyHash,
		KeyResolver:        input.KeyResolver,
		ReplayCache:        input.ReplayCache,
		ReplayWindow:       input.ReplayWindow,
		ChallengePolicy:    input.ChallengePolicy,
		PolicyEvaluator:    input.PolicyEvaluator,
		Transparency:       input.Transparency,
	})
}
