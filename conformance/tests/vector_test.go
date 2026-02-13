package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type conformanceVector struct {
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	ExpectedDecision    string   `json:"expected_decision"`
	ExpectedReasonCodes []string `json:"expected_reason_codes"`
}

func TestVectorsAreWellFormed(t *testing.T) {
	paths, err := filepath.Glob("../vectors/*.json")
	if err != nil {
		t.Fatalf("glob vectors: %v", err)
	}
	if len(paths) < 10 {
		t.Fatalf("expected at least 10 conformance vectors, got %d", len(paths))
	}

	registryBytes, err := os.ReadFile("../../spec/reason-codes/reason-codes-v2.json")
	if err != nil {
		t.Fatalf("read reason code registry: %v", err)
	}
	var registry reasonCodeRegistry
	if err := json.Unmarshal(registryBytes, &registry); err != nil {
		t.Fatalf("parse reason code registry: %v", err)
	}
	knownCodes := make(map[string]struct{}, len(registry.ReasonCodes))
	for _, code := range registry.ReasonCodes {
		knownCodes[code] = struct{}{}
	}

	seenNames := map[string]struct{}{}
	for _, path := range paths {
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatalf("read vector %s: %v", path, readErr)
		}
		var v conformanceVector
		if unmarshalErr := json.Unmarshal(content, &v); unmarshalErr != nil {
			t.Fatalf("parse vector %s: %v", path, unmarshalErr)
		}
		if v.Name == "" {
			t.Fatalf("vector %s missing name", path)
		}
		if _, exists := seenNames[v.Name]; exists {
			t.Fatalf("vector %s has duplicate name %q", path, v.Name)
		}
		seenNames[v.Name] = struct{}{}
		if v.ExpectedDecision == "" {
			t.Fatalf("vector %s missing expected_decision", path)
		}
		switch strings.ToUpper(strings.TrimSpace(v.ExpectedDecision)) {
		case "AUTHORIZED":
			if len(v.ExpectedReasonCodes) > 0 {
				t.Fatalf("vector %s is AUTHORIZED but has reason codes", path)
			}
		case "REJECTED":
			if len(v.ExpectedReasonCodes) == 0 {
				t.Fatalf("vector %s is REJECTED but has no expected reason codes", path)
			}
		default:
			t.Fatalf("vector %s has unsupported expected_decision %q", path, v.ExpectedDecision)
		}
		for _, code := range v.ExpectedReasonCodes {
			code = strings.TrimSpace(code)
			if code == "" {
				t.Fatalf("vector %s contains empty expected reason code", path)
			}
			if _, ok := knownCodes[code]; !ok {
				t.Fatalf("vector %s contains unknown reason code %q", path, code)
			}
		}
	}
}
