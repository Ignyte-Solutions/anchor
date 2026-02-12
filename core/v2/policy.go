package v2

import "fmt"

type PolicyEvaluator interface {
	Evaluate(capability Capability, action ActionEnvelope) ([]ReasonCode, []string)
}

type NoopPolicyEvaluator struct{}

func (NoopPolicyEvaluator) Evaluate(_ Capability, _ ActionEnvelope) ([]ReasonCode, []string) {
	return nil, nil
}

type TransparencyVerifier interface {
	Verify(transparencyRef, capabilityID string) error
}

type NoopTransparencyVerifier struct{}

func (NoopTransparencyVerifier) Verify(_ string, _ string) error { return nil }

type FuncPolicyEvaluator func(capability Capability, action ActionEnvelope) ([]ReasonCode, []string)

func (f FuncPolicyEvaluator) Evaluate(capability Capability, action ActionEnvelope) ([]ReasonCode, []string) {
	if f == nil {
		return nil, nil
	}
	return f(capability, action)
}

type FuncTransparencyVerifier func(transparencyRef, capabilityID string) error

func (f FuncTransparencyVerifier) Verify(transparencyRef, capabilityID string) error {
	if f == nil {
		return nil
	}
	return f(transparencyRef, capabilityID)
}

func normalizePolicyResults(codes []ReasonCode, reasons []string) ([]ReasonCode, []string) {
	if len(codes) == 0 && len(reasons) == 0 {
		return nil, nil
	}
	if len(codes) == 0 && len(reasons) > 0 {
		outCodes := make([]ReasonCode, 0, len(reasons))
		outReasons := make([]string, 0, len(reasons))
		for _, reason := range reasons {
			outCodes = append(outCodes, ReasonCodePolicyHookRejected)
			outReasons = append(outReasons, reason)
		}
		return outCodes, outReasons
	}
	if len(codes) > 0 && len(reasons) == 0 {
		outCodes := make([]ReasonCode, 0, len(codes))
		outReasons := make([]string, 0, len(codes))
		for _, code := range codes {
			outCodes = append(outCodes, code)
			outReasons = append(outReasons, fmt.Sprintf("policy hook rejected (%s)", code))
		}
		return outCodes, outReasons
	}
	if len(codes) != len(reasons) {
		maxLen := len(codes)
		if len(reasons) > maxLen {
			maxLen = len(reasons)
		}
		outCodes := make([]ReasonCode, 0, maxLen)
		outReasons := make([]string, 0, maxLen)
		for i := 0; i < maxLen; i++ {
			code := ReasonCodePolicyHookRejected
			reason := "policy hook rejected"
			if i < len(codes) {
				code = codes[i]
			}
			if i < len(reasons) && reasons[i] != "" {
				reason = reasons[i]
			}
			outCodes = append(outCodes, code)
			outReasons = append(outReasons, reason)
		}
		return outCodes, outReasons
	}
	outCodes := append([]ReasonCode(nil), codes...)
	outReasons := append([]string(nil), reasons...)
	return outCodes, outReasons
}
