package hostlist

import (
	"context"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

func TestIntegrationEmptyRulesDNSWorks(t *testing.T) {
	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
	}

	h.rules.Store(emptyRuleSet())

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

func TestIntegrationUpdateWithEmptyResult(t *testing.T) {
	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
	}

	h.rules.Store(emptyRuleSet())

	h.Update(ParseResult{
		Blocked:    []string{},
		Allowlist:  []string{},
		SkipUpdate: false,
	})

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

func TestIntegrationLoaderFailureDoesNotBlockDNS(t *testing.T) {
	loader := NewLoader(
		[]FilterSource{{URL: "http://invalid.example.com/rules.txt"}},
		[]FilterSource{},
		[]string{},
		1*time.Hour,
		"",
	)

	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
		loader:    loader,
	}

	h.rules.Store(emptyRuleSet())

	result := loader.LoadAll()
	h.Update(result)

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