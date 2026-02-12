package tests

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type reasonCodeRegistry struct {
	Version     int      `json:"version"`
	ReasonCodes []string `json:"reason_codes"`
}

func TestReasonCodeParityAcrossSDKs(t *testing.T) {
	registryBytes, err := os.ReadFile("../../spec/reason-codes/reason-codes-v2.json")
	if err != nil {
		t.Fatalf("read reason code registry: %v", err)
	}
	var registry reasonCodeRegistry
	if err := json.Unmarshal(registryBytes, &registry); err != nil {
		t.Fatalf("parse reason code registry: %v", err)
	}
	if registry.Version != 2 {
		t.Fatalf("expected reason code registry version 2, got %d", registry.Version)
	}
	if len(registry.ReasonCodes) == 0 {
		t.Fatal("expected non-empty reason code registry")
	}

	sdkFiles := map[string]string{
		"typescript": "../../sdk/typescript/verifier.ts",
		"python":     "../../sdk/python/verifier.py",
		"java":       "../../sdk/java/IgnyteAnchorLocalVerifier.java",
	}

	for sdkName, sdkPath := range sdkFiles {
		contentBytes, err := os.ReadFile(sdkPath)
		if err != nil {
			t.Fatalf("read %s verifier: %v", sdkName, err)
		}
		content := string(contentBytes)
		for _, code := range registry.ReasonCodes {
			if !strings.Contains(content, code) {
				t.Fatalf("%s verifier missing reason code %s", sdkName, code)
			}
		}
	}
}
