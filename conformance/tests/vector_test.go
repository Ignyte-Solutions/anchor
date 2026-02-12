package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
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
	if len(paths) == 0 {
		t.Fatal("expected at least one conformance vector")
	}
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
		if v.ExpectedDecision == "" {
			t.Fatalf("vector %s missing expected_decision", path)
		}
	}
}
