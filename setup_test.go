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
	if got, want := len(h.loader.sources), 5; got != want {
		t.Fatalf("expected %d unique sources, got %d: %#v", want, got, h.loader.sources)
	}
	if got, want := len(h.loader.userRules), 2; got != want {
		t.Fatalf("expected %d unique user rules, got %d: %#v", want, got, h.loader.userRules)
	}
}
