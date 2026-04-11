package logger

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLogPromotesMaliciousMatchToBlock(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "kaliwall.log")
	tl, err := New(logPath)
	if err != nil {
		t.Fatalf("new logger: %v", err)
	}
	defer tl.Close()

	tl.SetMaliciousIPChecker(func(ip string) bool {
		return strings.TrimSpace(ip) == "203.0.113.33"
	})

	tl.Log("ALLOW", "203.0.113.33", "10.0.0.2", "tcp", "new connection")
	entries := tl.RecentEntries(1)
	if len(entries) != 1 {
		t.Fatalf("expected one entry, got %d", len(entries))
	}
	if entries[0].Action != "BLOCK" {
		t.Fatalf("expected BLOCK action, got %s", entries[0].Action)
	}
	if !strings.Contains(strings.ToLower(entries[0].Detail), "malicious ip feed match") {
		t.Fatalf("expected malicious feed marker in detail, got: %s", entries[0].Detail)
	}
}
