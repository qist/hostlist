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

func TestDNSQueryNotBlockedDuringLoad(t *testing.T) {
	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
	}

	h.rules.Store(emptyRuleSet())

	go func() {
		time.Sleep(100 * time.Millisecond)
		h.Update(ParseResult{
			Blocked:    []string{"blocked.example.com."},
			SkipUpdate: false,
		})
	}()

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

func TestConcurrentDNSQueries(t *testing.T) {
	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
	}

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
				errors <- nil
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

func TestEmptyRulesPerformance(t *testing.T) {
	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
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