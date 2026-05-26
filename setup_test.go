package hostlist

import (
	"testing"

	"github.com/coredns/caddy"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input     string
		shouldErr bool
		mode      string
		blockType string
	}{
		{`hostlist {
			url https://example.com/filter.txt
		}`, false, "blacklist", "0.0.0.0"},
		{`hostlist {
			file /etc/coredns/blocklist.txt
		}`, false, "blacklist", "0.0.0.0"},
		{`hostlist {
			url https://example.com/filter.txt
			allowlist @@||youtube.com^
			allowlist @@||google.com^
		}`, false, "blacklist", "0.0.0.0"},
		{`hostlist {
			url https://example.com/filter.txt
			mode whitelist
		}`, false, "whitelist", "0.0.0.0"},
		{`hostlist {
			url https://example.com/filter.txt
			block_type empty
		}`, false, "blacklist", "empty"},
		{`hostlist {
			url https://example.com/filter.txt
			block_type nxdomain
		}`, false, "blacklist", "nxdomain"},
		{`hostlist {
			url https://example.com/filter.txt
			refresh 12h
		}`, false, "blacklist", "0.0.0.0"},
		{`hostlist {
			url https://example.com/filter.txt
			mode invalid
		}`, true, "", ""},
		{`hostlist {
			url https://example.com/filter.txt
			block_type invalid
		}`, true, "", ""},
		{`hostlist {
			unknown_directive foo
		}`, true, "", ""},
		{`hostlist`, true, "", ""},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		h, err := parse(c)
		if test.shouldErr && err == nil {
			t.Errorf("Test %d: expected error, got nil", i)
			continue
		}
		if !test.shouldErr && err != nil {
			t.Errorf("Test %d: expected no error, got: %v", i, err)
			continue
		}
		if !test.shouldErr {
			if h.mode != test.mode {
				t.Errorf("Test %d: expected mode %q, got %q", i, test.mode, h.mode)
			}
			if h.blockType != test.blockType {
				t.Errorf("Test %d: expected block_type %q, got %q", i, test.blockType, h.blockType)
			}
		}
	}
}

func TestParseDeduplicatesConfigRulesAndSources(t *testing.T) {
	c := caddy.NewTestController("dns", `hostlist {
		url https://example.com/filter.txt
		url https://example.com/filter.txt
		file /etc/coredns/blocklist.txt
		file /etc/coredns/blocklist.txt
		allowlist @@||youtube.com^ @@||youtube.com^
		blocklist ||ads.example.com^ ||ads.example.com^
		parental on
		parental on
	}`)
	h, err := parse(c)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if got, want := len(h.loader.sources), 2; got != want {
		t.Fatalf("expected %d unique sources, got %d: %#v", want, got, h.loader.sources)
	}
	if got, want := len(h.loader.userRules), 2; got != want {
		t.Fatalf("expected %d unique user rules, got %d: %#v", want, got, h.loader.userRules)
	}
	if h.parentalFallbackLoader == nil {
		t.Fatal("expected built-in parental fallback loader to be configured")
	}
	if got, want := len(h.parentalFallbackLoader.sources), len(defaultParentalSources); got != want {
		t.Fatalf("expected %d parental fallback sources, got %d", want, got)
	}
}

func TestParseParentalBlockCreatesDedicatedLoader(t *testing.T) {
	c := caddy.NewTestController("dns", `hostlist {
		refresh 6h
		cache_dir /var/lib/coredns/hostlist
		parental on
		parental {
			url https://example.com/parental.txt
			url https://example.com/parental.txt
		}
	}`)
	h, err := parse(c)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !h.parentalEnabled {
		t.Fatal("expected parental mode to be enabled")
	}
	if h.loader != nil {
		t.Fatal("expected no main loader when only parental rules are configured")
	}
	if h.parentalLoader == nil {
		t.Fatal("expected dedicated parental loader to be configured")
	}
	if got, want := len(h.parentalLoader.sources), 1; got != want {
		t.Fatalf("expected %d parental source, got %d", want, got)
	}
	if got, want := h.parentalLoader.interval.String(), "6h0m0s"; got != want {
		t.Fatalf("expected parental refresh %q, got %q", want, got)
	}
	if got, want := h.parentalLoader.cacheDir, "/var/lib/coredns/hostlist/parental"; got != want {
		t.Fatalf("expected parental cache dir %q, got %q", want, got)
	}
	if h.parentalFallbackLoader == nil {
		t.Fatal("expected built-in parental fallback loader to be configured")
	}
}

func TestParseParentalBlockEnablesParentalImplicitly(t *testing.T) {
	c := caddy.NewTestController("dns", `hostlist {
		parental {
			file /etc/coredns/parental.txt
		}
	}`)
	h, err := parse(c)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !h.parentalEnabled {
		t.Fatal("expected parental block to implicitly enable parental mode")
	}
	if h.parentalLoader == nil {
		t.Fatal("expected parental loader to be configured")
	}
}
