package verifier

import (
	"crypto/ed25519"
	"fmt"
	"sort"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor/internal/action"
	"github.com/ignyte-solutions/ignyte-anchor/internal/capability"
	anchorcrypto "github.com/ignyte-solutions/ignyte-anchor/internal/crypto"
	"github.com/ignyte-solutions/ignyte-anchor/internal/domain"
)

type RevocationChecker interface {
	IsRevoked(capabilityID string) bool
}

type StaticRevocationList struct {
	Revoked map[string]struct{}
}

func (l StaticRevocationList) IsRevoked(capabilityID string) bool {
	if l.Revoked == nil {
		return false
	}
	_, ok := l.Revoked[capabilityID]
	return ok
}

type VerifyRequest struct {
	Capability      domain.Capability
	Action          domain.ActionEnvelope
	IssuerPublicKey ed25519.PublicKey
	AgentPublicKey  ed25519.PublicKey
	ReferenceTime   time.Time
	RevocationList  RevocationChecker
}

type Engine struct{}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) Verify(request VerifyRequest) domain.VerificationResult {
	reasons := make([]string, 0)
	if request.ReferenceTime.IsZero() {
		reasons = append(reasons, "reference_time is required")
		return domain.VerificationResult{Decision: domain.DecisionRejected, Reasons: reasons}
	}

	issuerID, err := anchorcrypto.DeriveIDFromPublicKey(request.IssuerPublicKey)
	if err != nil {
		reasons = append(reasons, fmt.Sprintf("invalid issuer public key: %v", err))
	} else if issuerID != request.Capability.IssuerID {
		reasons = append(reasons, "issuer_id does not match issuer public key")
	}

	capabilitySignatureValid, capabilityErr := capability.Verify(request.Capability, request.IssuerPublicKey)
	if capabilityErr != nil {
		reasons = append(reasons, fmt.Sprintf("capability verification error: %v", capabilityErr))
	} else if !capabilitySignatureValid {
		reasons = append(reasons, "capability signature is invalid")
	}

	referenceTime := request.ReferenceTime.UTC()
	if referenceTime.Before(request.Capability.IssuedAt.UTC()) {
		reasons = append(reasons, "capability is not valid yet")
	}
	if referenceTime.After(request.Capability.ExpiresAt.UTC()) {
		reasons = append(reasons, "capability is expired")
	}

	agentIDFromKey, agentIDErr := anchorcrypto.DeriveIDFromPublicKey(request.AgentPublicKey)
	if agentIDErr != nil {
		reasons = append(reasons, fmt.Sprintf("invalid agent public key: %v", agentIDErr))
	} else {
		if agentIDFromKey != request.Capability.AgentID {
			reasons = append(reasons, "capability agent_id does not match agent public key")
		}
		if request.Action.AgentID != agentIDFromKey {
			reasons = append(reasons, "action agent_id does not match agent public key")
		}
	}

	actionSignatureValid, actionErr := action.Verify(request.Action, request.AgentPublicKey)
	if actionErr != nil {
		reasons = append(reasons, fmt.Sprintf("action verification error: %v", actionErr))
	} else if !actionSignatureValid {
		reasons = append(reasons, "action signature is invalid")
	}

	if request.Action.CapabilityID != request.Capability.CapabilityID {
		reasons = append(reasons, "action capability_id does not match capability")
	}
	if !contains(request.Capability.AllowedActions, request.Action.ActionType) {
		reasons = append(reasons, "action_type is not allowed by capability")
	}

	reasons = append(reasons, verifyConstraints(request.Capability.Constraints, request.Action.ConstraintEvidence)...)

	if request.RevocationList != nil && request.RevocationList.IsRevoked(request.Capability.CapabilityID) {
		reasons = append(reasons, "capability is revoked")
	}

	if len(reasons) > 0 {
		return domain.VerificationResult{Decision: domain.DecisionRejected, Reasons: reasons}
	}
	return domain.VerificationResult{Decision: domain.DecisionAuthorized, Reasons: []string{}}
}

func verifyConstraints(constraints domain.CapabilityConstraints, evidence domain.ConstraintEvidence) []string {
	reasons := make([]string, 0)
	if len(constraints.APIScopes) > 0 && !contains(constraints.APIScopes, evidence.APIScope) {
		reasons = append(reasons, "api_scope is not allowed by capability constraints")
	}
	if len(constraints.EnvironmentConstraints) > 0 && !contains(constraints.EnvironmentConstraints, evidence.Environment) {
		reasons = append(reasons, "environment is not allowed by capability constraints")
	}
	resourceKeys := sortedKeys(evidence.ResourceUsage)
	for _, key := range resourceKeys {
		value := evidence.ResourceUsage[key]
		limit, ok := constraints.ResourceLimits[key]
		if !ok {
			reasons = append(reasons, fmt.Sprintf("resource usage for %s is not permitted", key))
			continue
		}
		if value > limit {
			reasons = append(reasons, fmt.Sprintf("resource usage for %s exceeds limit", key))
		}
	}
	spendKeys := sortedKeys(evidence.SpendUsage)
	for _, key := range spendKeys {
		value := evidence.SpendUsage[key]
		limit, ok := constraints.SpendLimits[key]
		if !ok {
			reasons = append(reasons, fmt.Sprintf("spend usage for %s is not permitted", key))
			continue
		}
		if value > limit {
			reasons = append(reasons, fmt.Sprintf("spend usage for %s exceeds limit", key))
		}
	}
	rateKeys := sortedKeys(evidence.RateUsage)
	for _, key := range rateKeys {
		value := evidence.RateUsage[key]
		limit, ok := constraints.RateLimits[key]
		if !ok {
			reasons = append(reasons, fmt.Sprintf("rate usage for %s is not permitted", key))
			continue
		}
		if value > limit {
			reasons = append(reasons, fmt.Sprintf("rate usage for %s exceeds limit", key))
		}
	}
	return reasons
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func sortedKeys(input map[string]int64) []string {
	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
