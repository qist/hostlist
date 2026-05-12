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
		}`, false, "blacklist", "nxdomain"},
		{`hostlist {
			file /etc/coredns/blocklist.txt
		}`, false, "blacklist", "nxdomain"},
		{`hostlist {
			url https://example.com/filter.txt
			allowlist @@||youtube.com^
			allowlist @@||google.com^
		}`, false, "blacklist", "nxdomain"},
		{`hostlist {
			url https://example.com/filter.txt
			mode whitelist
		}`, false, "whitelist", "nxdomain"},
		{`hostlist {
			url https://example.com/filter.txt
			block_type empty
		}`, false, "blacklist", "empty"},
		{`hostlist {
			url https://example.com/filter.txt
			refresh 12h
		}`, false, "blacklist", "nxdomain"},
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
