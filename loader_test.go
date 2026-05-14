package hostlist

import (
	"testing"
)

func TestLoadAllWithNoSources(t *testing.T) {
	loader := NewLoader([]FilterSource{}, []FilterSource{}, []string{}, 0, "")
	result := loader.LoadAll()

	// Should return empty result but not block DNS queries
	if len(result.Blocked) != 0 {
		t.Errorf("expected no blocked domains, got %d", len(result.Blocked))
	}
	if len(result.Allowlist) != 0 {
		t.Errorf("expected no allowlist entries, got %d", len(result.Allowlist))
	}
	// SkipUpdate should be false to ensure DNS queries work
	if result.SkipUpdate {
		t.Error("SkipUpdate should be false to ensure DNS queries work even with no rules")
	}
}

func TestLoadAllWithInvalidURL(t *testing.T) {
	// This test simulates a scenario where URL loading fails
	// The loader should handle this gracefully and not block DNS queries
	loader := NewLoader(
		[]FilterSource{{URL: "http://invalid-url-that-does-not-exist.example.com/rules.txt"}},
		[]FilterSource{},
		[]string{},
		0,
		"",
	)

	result := loader.LoadAll()

	// Should return empty result but not block DNS queries
	if len(result.Blocked) != 0 {
		t.Errorf("expected no blocked domains when URL fails, got %d", len(result.Blocked))
	}
	// SkipUpdate should be false to ensure DNS queries work
	if result.SkipUpdate {
		t.Error("SkipUpdate should be false to ensure DNS queries work even when loading fails")
	}
}
