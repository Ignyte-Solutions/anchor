package protocolgo

import (
	"crypto/ed25519"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor-protocol/core/v2"
)

type OfflineVerifyInput struct {
	Capability         v2.Capability
	Action             v2.ActionEnvelope
	IssuerPublicKey    ed25519.PublicKey
	AgentPublicKey     ed25519.PublicKey
	ReferenceTime      time.Time
	ExpectedAudience   string
	ExpectedPolicyHash string
	KeyResolver        v2.IssuerKeyResolver
	RevocationList     v2.RevocationChecker
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
