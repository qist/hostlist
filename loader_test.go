package hostlist

import (
	"io"
	"os"
	"path/filepath"
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

func TestHostlistLoadAllFallsBackToParentalDefaults(t *testing.T) {
	dir := t.TempDir()
	fallbackFile := filepath.Join(dir, "fallback.txt")
	if err := os.WriteFile(fallbackFile, []byte("||fallback.example^\n"), 0644); err != nil {
		t.Fatalf("write fallback file: %v", err)
	}

	h := &Hostlist{
		parentalEnabled: true,
		parentalLoader: NewLoader(
			[]FilterSource{{File: filepath.Join(dir, "missing.txt")}},
			nil,
			nil,
			0,
			"",
		),
		parentalFallbackLoader: NewLoader(
			[]FilterSource{{File: fallbackFile}},
			nil,
			nil,
			0,
			"",
		),
	}

	result := h.LoadAll()
	if got, want := len(result.Blocked), 1; got != want {
		t.Fatalf("expected %d blocked rule from parental fallback, got %d", want, got)
	}
	if got, want := result.Blocked[0], "fallback.example."; got != want {
		t.Fatalf("expected fallback rule %q, got %q", want, got)
	}
}

func TestHostlistLoadAllPrefersCustomParentalRules(t *testing.T) {
	dir := t.TempDir()
	customFile := filepath.Join(dir, "custom.txt")
	fallbackFile := filepath.Join(dir, "fallback.txt")
	if err := os.WriteFile(customFile, []byte("||custom.example^\n"), 0644); err != nil {
		t.Fatalf("write custom file: %v", err)
	}
	if err := os.WriteFile(fallbackFile, []byte("||fallback.example^\n"), 0644); err != nil {
		t.Fatalf("write fallback file: %v", err)
	}

	h := &Hostlist{
		parentalEnabled: true,
		parentalLoader: NewLoader(
			[]FilterSource{{File: customFile}},
			nil,
			nil,
			0,
			"",
		),
		parentalFallbackLoader: NewLoader(
			[]FilterSource{{File: fallbackFile}},
			nil,
			nil,
			0,
			"",
		),
	}

	result := h.LoadAll()
	if got, want := len(result.Blocked), 1; got != want {
		t.Fatalf("expected %d blocked rule from custom parental source, got %d", want, got)
	}
	if got, want := result.Blocked[0], "custom.example."; got != want {
		t.Fatalf("expected custom rule %q, got %q", want, got)
	}
}

func TestLoadAllDeduplicatesDuringMergeButKeepsLatestHostsIP(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "first.txt")
	second := filepath.Join(dir, "second.txt")
	if err := os.WriteFile(first, []byte("127.0.0.1 dup.example.com\n"), 0644); err != nil {
		t.Fatalf("write first file: %v", err)
	}
	if err := os.WriteFile(second, []byte("0.0.0.0 dup.example.com\n"), 0644); err != nil {
		t.Fatalf("write second file: %v", err)
	}

	loader := NewLoader(
		[]FilterSource{{File: first}, {File: second}},
		nil,
		nil,
		0,
		"",
	)

	result := loader.LoadAll()
	if got, want := len(result.BlockedExact), 1; got != want {
		t.Fatalf("expected %d exact rule after merge dedup, got %d: %#v", want, got, result.BlockedExact)
	}
	if result.IPMap == nil {
		t.Fatal("expected IPMap to be populated")
	}
	if got, want := result.IPMap["dup.example.com."], "0.0.0.0"; got != want {
		t.Fatalf("expected latest hosts IP %q, got %q", want, got)
	}
}

func TestMultiLineReaderStreamsUserRules(t *testing.T) {
	r := multiLineReader([]string{
		"||blocked.example^",
		"@@||allowed.example^",
		"127.0.0.1 exact.example",
	})

	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read multiline reader: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected multiline reader to produce data")
	}

	result := ParseRules(multiLineReader([]string{
		"||blocked.example^",
		"@@||allowed.example^",
		"127.0.0.1 exact.example",
	}))
	if got, want := result.Blocked[0], "blocked.example."; got != want {
		t.Fatalf("expected blocked rule %q, got %q", want, got)
	}
	if got, want := result.Allowlist[0], "allowed.example."; got != want {
		t.Fatalf("expected allow rule %q, got %q", want, got)
	}
	if got, want := result.BlockedExact[0], "exact.example."; got != want {
		t.Fatalf("expected exact rule %q, got %q", want, got)
	}
}

func TestMetadataExtractionScansLines(t *testing.T) {
	content := []byte("! Title: sample\r\n! Version: 2026.0526.1749\r\n! Last modified: 2026-05-26T17:49:00Z\r\n||example.org^\n")

	if got, want := extractVersionBytes(content), "2026.0526.1749"; got != want {
		t.Fatalf("expected version %q, got %q", want, got)
	}
	if got, want := extractLastModifiedBytes(content), "2026-05-26T17:49:00Z"; got != want {
		t.Fatalf("expected last modified %q, got %q", want, got)
	}
	if got, want := parseLastModifiedFromBytes(content), "Tue, 26 May 2026 17:49:00 UTC"; got != want {
		t.Fatalf("expected parsed last modified %q, got %q", want, got)
	}
}
