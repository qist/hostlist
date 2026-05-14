package hostlist

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// TestDNSQueryNotBlockedDuringLoad tests that DNS queries are not blocked during rule loading
func TestDNSQueryNotBlockedDuringLoad(t *testing.T) {
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

	// Start a slow loading process in background
	go func() {
		time.Sleep(100 * time.Millisecond) // Simulate slow load
		h.Update(ParseResult{
			Blocked:    []string{"blocked.example.com."},
			SkipUpdate: false,
		})
	}()

	// Send multiple DNS queries during loading
	for i := 0; i < 10; i++ {
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		rec := dnstest.NewRecorder(&test.ResponseWriter{})

		start := time.Now()
		rcode, err := h.ServeDNS(context.Background(), rec, req)
		duration := time.Since(start)

		if err != nil {
			t.Fatalf("query %d: expected no error, got: %v", i, err)
		}
		if rcode != dns.RcodeSuccess {
			t.Fatalf("query %d: expected pass-through, got rcode %d", i, rcode)
		}
		if duration > 50*time.Millisecond {
			t.Fatalf("query %d: took too long: %v", i, duration)
		}
	}
}

// TestConcurrentDNSQueries tests concurrent DNS queries don't block each other
func TestConcurrentDNSQueries(t *testing.T) {
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

	var wg sync.WaitGroup
	numQueries := 100
	errors := make(chan error, numQueries)

	for i := 0; i < numQueries; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeA)
			rec := dnstest.NewRecorder(&test.ResponseWriter{})

			rcode, err := h.ServeDNS(context.Background(), rec, req)
			if err != nil {
				errors <- err
				return
			}
			if rcode != dns.RcodeSuccess {
				errors <- nil // Not an error, but unexpected
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		if err != nil {
			t.Errorf("concurrent query failed: %v", err)
		}
	}
}

// TestEmptyRulesPerformance tests performance with empty rules
func TestEmptyRulesPerformance(t *testing.T) {
	h := &Hostlist{
		Next:       test.NextHandler(dns.RcodeSuccess, nil),
		Origins:    []string{"."},
		mode:       "blacklist",
		blockType:  "nxdomain",
		domainTrie: NewCompactTrie(),
		exactTrie:  NewCompactTrie(),
		allowTrie:  NewCompactTrie(),
	}

	h.rules.Store(emptyRuleSet())

	start := time.Now()
	numQueries := 1000

	for i := 0; i < numQueries; i++ {
		req := new(dns.Msg)
		req.SetQuestion("example.com.", dns.TypeA)
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		h.ServeDNS(context.Background(), rec, req)
	}

	duration := time.Since(start)
	avgDuration := duration / time.Duration(numQueries)

	t.Logf("Processed %d queries in %v (avg %v per query)", numQueries, duration, avgDuration)

	if avgDuration > 1*time.Millisecond {
		t.Errorf("Average query time %v is too slow", avgDuration)
	}
}
