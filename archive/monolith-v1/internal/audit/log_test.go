package audit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor/internal/audit"
)

func TestAppendBuildsHashChainAcrossReopen(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	log, err := audit.Open(logPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}

	entry1, err := log.Append(audit.EventCapabilityIssued, map[string]any{"id": "cap-1"}, time.Date(2026, 2, 12, 19, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("append first entry: %v", err)
	}
	entry2, err := log.Append(audit.EventVerificationResult, map[string]any{"decision": "AUTHORIZED"}, time.Date(2026, 2, 12, 19, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("append second entry: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatalf("close audit log: %v", err)
	}

	reopened, err := audit.Open(logPath)
	if err != nil {
		t.Fatalf("reopen audit log: %v", err)
	}
	defer func() {
		_ = reopened.Close()
	}()

	entry3, err := reopened.Append(audit.EventActionExecuted, map[string]any{"action": "s3:PutObject"}, time.Date(2026, 2, 12, 19, 2, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("append third entry: %v", err)
	}

	if entry1.PreviousHash != "" {
		t.Fatalf("first entry should have empty previous hash, got %q", entry1.PreviousHash)
	}
	if entry2.PreviousHash != entry1.EntryHash {
		t.Fatalf("second entry previous hash mismatch\nwant=%s\ngot=%s", entry1.EntryHash, entry2.PreviousHash)
	}
	if entry3.PreviousHash != entry2.EntryHash {
		t.Fatalf("third entry previous hash mismatch\nwant=%s\ngot=%s", entry2.EntryHash, entry3.PreviousHash)
	}

	entries := readEntries(t, logPath)
	if len(entries) != 3 {
		t.Fatalf("expected 3 persisted entries, got %d", len(entries))
	}
}

func TestOpenRejectsMalformedExistingLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(logPath, []byte("not-json\n"), 0o600); err != nil {
		t.Fatalf("write malformed log: %v", err)
	}

	_, err := audit.Open(logPath)
	if err == nil {
		t.Fatal("expected parse error for malformed audit log")
	}
	if !strings.Contains(err.Error(), "parse audit log entry") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestAppendRejectsInvalidInputs(t *testing.T) {
	var nilLog *audit.Log
	_, err := nilLog.Append(audit.EventCapabilityIssued, map[string]any{"id": "cap-1"}, time.Now().UTC())
	if err == nil || !strings.Contains(err.Error(), "audit log is required") {
		t.Fatalf("expected nil log error, got %v", err)
	}

	logPath := filepath.Join(t.TempDir(), "audit.log")
	log, err := audit.Open(logPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer func() {
		_ = log.Close()
	}()

	if _, err = log.Append("", map[string]any{"id": "cap-1"}, time.Now().UTC()); err == nil {
		t.Fatal("expected empty event type error")
	}
	if _, err = log.Append(audit.EventCapabilityIssued, nil, time.Now().UTC()); err == nil {
		t.Fatal("expected nil payload error")
	}
	if _, err = log.Append(audit.EventCapabilityIssued, map[string]any{"id": "cap-1"}, time.Time{}); err == nil {
		t.Fatal("expected zero timestamp error")
	}
}

func readEntries(t *testing.T, path string) []audit.Entry {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	entries := make([]audit.Entry, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var entry audit.Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("decode persisted entry: %v", err)
		}
		entries = append(entries, entry)
	}
	return entries
}
