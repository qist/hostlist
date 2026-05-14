package hostlist

import (
	"context"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// TestIntegrationEmptyRulesDNSWorks tests that DNS queries work even when rules fail to load
func TestIntegrationEmptyRulesDNSWorks(t *testing.T) {
	// Create a hostlist with no sources (simulating failed loading)
	h := &Hostlist{
		Next:       test.NextHandler(dns.RcodeSuccess, nil),
		Origins:    []string{"."},
		mode:       "blacklist",
		blockType:  "nxdomain",
		domainTrie: NewCompactTrie(),
		exactTrie:  NewCompactTrie(),
		allowTrie:  NewCompactTrie(),
	}

	// Initialize with empty rule set (as done in setup.go)
	h.rules.Store(emptyRuleSet())

	// Test DNS query should pass through even with no rules
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected pass-through with empty rules, got rcode %d", rcode)
	}
}

// TestIntegrationUpdateWithEmptyResult tests that updating with empty result doesn't break DNS
func TestIntegrationUpdateWithEmptyResult(t *testing.T) {
	h := &Hostlist{
		Next:       test.NextHandler(dns.RcodeSuccess, nil),
		Origins:    []string{"."},
		mode:       "blacklist",
		blockType:  "nxdomain",
		domainTrie: NewCompactTrie(),
		exactTrie:  NewCompactTrie(),
		allowTrie:  NewCompactTrie(),
	}

	// Initialize with empty rule set
	h.rules.Store(emptyRuleSet())

	// Update with empty result (simulating failed load)
	h.Update(ParseResult{
		Blocked:    []string{},
		Allowlist:  []string{},
		SkipUpdate: false, // Important: should not skip update
	})

	// DNS query should still work
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected pass-through after empty update, got rcode %d", rcode)
	}
}

// TestIntegrationLoaderFailureDoesNotBlockDNS tests the complete flow
func TestIntegrationLoaderFailureDoesNotBlockDNS(t *testing.T) {
	// Create loader with invalid URL that will fail
	loader := NewLoader(
		[]FilterSource{{URL: "http://invalid.example.com/rules.txt"}},
		[]FilterSource{},
		[]string{},
		1*time.Hour, // refresh interval
		"",
	)

	h := &Hostlist{
		Next:       test.NextHandler(dns.RcodeSuccess, nil),
		Origins:    []string{"."},
		mode:       "blacklist",
		blockType:  "nxdomain",
		domainTrie: NewCompactTrie(),
		exactTrie:  NewCompactTrie(),
		allowTrie:  NewCompactTrie(),
		loader:     loader,
	}

	// Initialize with empty rule set (as done in setup.go)
	h.rules.Store(emptyRuleSet())

	// Simulate async loading (which will fail)
	result := loader.LoadAll()
	h.Update(result)

	// DNS query should still work even though loading failed
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error after failed load, got: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected pass-through after failed load, got rcode %d", rcode)
	}
}
