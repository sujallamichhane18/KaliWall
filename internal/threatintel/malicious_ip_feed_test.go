package threatintel

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaliciousIPFeedParsesIPsumAndCIDR(t *testing.T) {
	tmpDir := t.TempDir()
	feedPath := filepath.Join(tmpDir, "ipsum.txt")
	content := "# comment\n198.51.100.10\t7\n203.0.113.0/24\ninvalid-entry\n"
	if err := os.WriteFile(feedPath, []byte(content), 0o640); err != nil {
		t.Fatalf("write feed: %v", err)
	}

	feed, err := NewMaliciousIPFeed(feedPath)
	if err != nil {
		t.Fatalf("new feed: %v", err)
	}

	if !feed.IsMaliciousIP("198.51.100.10") {
		t.Fatalf("expected exact IP match")
	}
	if !feed.IsMaliciousIP("203.0.113.9") {
		t.Fatalf("expected CIDR match")
	}
	if feed.IsMaliciousIP("192.0.2.42") {
		t.Fatalf("unexpected match for non-listed IP")
	}
}

func TestMaliciousIPFeedReloadIfChanged(t *testing.T) {
	tmpDir := t.TempDir()
	feedPath := filepath.Join(tmpDir, "ipsum.txt")
	if err := os.WriteFile(feedPath, []byte("198.51.100.20\t6\n"), 0o640); err != nil {
		t.Fatalf("write feed: %v", err)
	}

	feed, err := NewMaliciousIPFeed(feedPath)
	if err != nil {
		t.Fatalf("new feed: %v", err)
	}

	if feed.IsMaliciousIP("203.0.113.50") {
		t.Fatalf("unexpected match before reload")
	}

	if err := os.WriteFile(feedPath, []byte("198.51.100.20\t6\n203.0.113.50\t9\n"), 0o640); err != nil {
		t.Fatalf("rewrite feed: %v", err)
	}

	changed, _, err := feed.ReloadIfChanged()
	if err != nil {
		t.Fatalf("reload if changed: %v", err)
	}
	if !changed {
		t.Fatalf("expected feed to reload after file update")
	}
	if !feed.IsMaliciousIP("203.0.113.50") {
		t.Fatalf("expected match after reload")
	}
}
