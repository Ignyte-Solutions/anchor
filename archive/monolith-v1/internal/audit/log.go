package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/ignyte-solutions/ignyte-anchor/internal/canonical"
)

const (
	EventCapabilityIssued   = "CAPABILITY_ISSUED"
	EventActionExecuted     = "ACTION_EXECUTED"
	EventVerificationResult = "VERIFICATION_RESULT"
)

type Entry struct {
	EventType    string          `json:"event_type"`
	Payload      json.RawMessage `json:"payload"`
	Timestamp    time.Time       `json:"timestamp"`
	PreviousHash string          `json:"previous_hash"`
	EntryHash    string          `json:"entry_hash"`
}

type appendPayload struct {
	EventType    string          `json:"event_type"`
	Payload      json.RawMessage `json:"payload"`
	Timestamp    string          `json:"timestamp"`
	PreviousHash string          `json:"previous_hash"`
}

type Log struct {
	path     string
	file     *os.File
	mu       sync.Mutex
	lastHash string
}

func Open(path string) (*Log, error) {
	if path == "" {
		return nil, fmt.Errorf("audit log path is required")
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	lastHash, err := scanLastHash(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &Log{path: path, file: file, lastHash: lastHash}, nil
}

func (l *Log) Append(eventType string, payload any, timestamp time.Time) (Entry, error) {
	if l == nil {
		return Entry{}, fmt.Errorf("audit log is required")
	}
	if eventType == "" {
		return Entry{}, fmt.Errorf("event type is required")
	}
	if payload == nil {
		return Entry{}, fmt.Errorf("payload is required")
	}
	if timestamp.IsZero() {
		return Entry{}, fmt.Errorf("timestamp is required")
	}
	canonicalPayload, err := canonical.Marshal(payload)
	if err != nil {
		return Entry{}, fmt.Errorf("canonical audit payload: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	base := appendPayload{
		EventType:    eventType,
		Payload:      json.RawMessage(canonicalPayload),
		Timestamp:    timestamp.UTC().Format("2006-01-02T15:04:05.000000000Z07:00"),
		PreviousHash: l.lastHash,
	}
	canonicalBase, err := canonical.Marshal(base)
	if err != nil {
		return Entry{}, fmt.Errorf("canonical audit entry: %w", err)
	}
	hash := sha256.Sum256(canonicalBase)
	entry := Entry{
		EventType:    eventType,
		Payload:      json.RawMessage(canonicalPayload),
		Timestamp:    timestamp.UTC(),
		PreviousHash: l.lastHash,
		EntryHash:    hex.EncodeToString(hash[:]),
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return Entry{}, fmt.Errorf("marshal audit entry: %w", err)
	}
	if _, err = l.file.Write(append(line, '\n')); err != nil {
		return Entry{}, fmt.Errorf("write audit entry: %w", err)
	}
	l.lastHash = entry.EntryHash
	return entry, nil
}

func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	return l.file.Close()
}

func scanLastHash(file *os.File) (string, error) {
	if _, err := file.Seek(0, 0); err != nil {
		return "", fmt.Errorf("seek audit log: %w", err)
	}
	scanner := bufio.NewScanner(file)
	lastHash := ""
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry Entry
		if err := json.Unmarshal(line, &entry); err != nil {
			return "", fmt.Errorf("parse audit log entry: %w", err)
		}
		lastHash = entry.EntryHash
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan audit log: %w", err)
	}
	if _, err := file.Seek(0, io.SeekEnd); err != nil {
		return "", fmt.Errorf("seek audit log end: %w", err)
	}
	return lastHash, nil
}
