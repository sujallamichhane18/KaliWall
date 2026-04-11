package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddWebsiteBlockEnabledByDefault(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kaliwall.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	entry := s.AddWebsiteBlock("example.com", "test")
	if !entry.Enabled {
		t.Fatalf("expected added website block to be enabled")
	}

	blocks := s.ListWebsiteBlocks()
	if len(blocks) != 1 {
		t.Fatalf("expected 1 website block, got %d", len(blocks))
	}
	if !blocks[0].Enabled {
		t.Fatalf("expected persisted website block to be enabled")
	}
}

func TestOpenMigratesLegacyWebsiteBlocksEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kaliwall.json")
	legacy := `{
	  "blocked_ips": [],
	  "website_blocks": [
	    {
	      "domain": "legacy.example",
	      "reason": "legacy",
	      "created_at": "2026-01-01T00:00:00Z"
	    }
	  ],
	  "rules": [],
	  "settings": {}
	}`
	if err := os.WriteFile(path, []byte(legacy), 0644); err != nil {
		t.Fatalf("write legacy db: %v", err)
	}

	s, err := Open(path)
	if err != nil {
		t.Fatalf("open migrated store: %v", err)
	}

	blocks := s.ListWebsiteBlocks()
	if len(blocks) != 1 {
		t.Fatalf("expected 1 website block, got %d", len(blocks))
	}
	if !blocks[0].Enabled {
		t.Fatalf("expected legacy website block to be migrated to enabled")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read migrated db: %v", err)
	}
	if !strings.Contains(string(raw), `"enabled": true`) {
		t.Fatalf("expected migrated db file to persist enabled=true website block")
	}
}