package rules

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadProjectDPIRulesYAML(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to get caller path")
	}
	rulesPath := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", "..", "configs", "dpi-rules.yaml"))
	engine, err := LoadFromFile(rulesPath)
	if err != nil {
		t.Fatalf("failed to parse dpi rules yaml: %v", err)
	}
	if len(engine.Rules()) == 0 {
		t.Fatal("dpi rules loaded but empty")
	}
}
