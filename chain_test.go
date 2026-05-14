package hostlist

import (
	"context"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// TestNextPluginIsCalled verifies that queries are passed to the next plugin
func TestNextPluginIsCalled(t *testing.T) {
	nextCalled := false
	nextHandler := test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		nextCalled = true
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{8, 8, 8, 8},
		}}
		w.WriteMsg(m)
		return m.Rcode, nil
	})

	h := &Hostlist{
		Next:       nextHandler,
		Origins:    []string{"."},
		mode:       "blacklist",
		blockType:  "nxdomain",
		domainTrie: NewCompactTrie(),
		exactTrie:  NewCompactTrie(),
		allowTrie:  NewCompactTrie(),
	}

	// Initialize with empty rule set
	h.rules.Store(emptyRuleSet())

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !nextCalled {
		t.Fatal("expected next plugin to be called, but it wasn't")
	}

	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", rcode)
	}

	if len(rec.Msg.Answer) == 0 {
		t.Fatal("expected answer from next plugin, got empty response")
	}
}

// TestNextPluginNotCalledWhenBlocked verifies blocked queries don't reach next plugin
func TestNextPluginNotCalledWhenBlocked(t *testing.T) {
	nextCalled := false
	nextHandler := test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		nextCalled = true
		m := new(dns.Msg)
		m.SetReply(r)
		w.WriteMsg(m)
		return m.Rcode, nil
	})

	h := &Hostlist{
		Next:       nextHandler,
		Origins:    []string{"."},
		mode:       "blacklist",
		blockType:  "nxdomain",
		domainTrie: NewCompactTrie(),
		exactTrie:  NewCompactTrie(),
		allowTrie:  NewCompactTrie(),
	}

	// Add a blocked domain
	h.domainTrie.Insert("blocked.example.com.")
	h.rules.Store(&ruleSet{
		domainTrie: h.domainTrie,
		exactTrie:  h.exactTrie,
		allowTrie:  h.allowTrie,
	})

	req := new(dns.Msg)
	req.SetQuestion("blocked.example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	h.ServeDNS(context.Background(), rec, req)

	if nextCalled {
		t.Fatal("expected next plugin NOT to be called for blocked domain, but it was")
	}

	if rec.Msg.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for blocked domain, got %d", rec.Msg.Rcode)
	}
}

// TestChainWithMultiplePlugins simulates the full plugin chain
func TestChainWithMultiplePlugins(t *testing.T) {
	// Create a chain: hostlist -> mockSpeedcheck -> mockForward
	forwardCalled := false
	mockForward := test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		forwardCalled = true
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{1, 1, 1, 1},
		}}
		w.WriteMsg(m)
		return m.Rcode, nil
	})

	mockSpeedcheck := plugin.Handler(mockForward)

	h := &Hostlist{
		Next:       mockSpeedcheck,
		Origins:    []string{"."},
		mode:       "blacklist",
		blockType:  "nxdomain",
		domainTrie: NewCompactTrie(),
		exactTrie:  NewCompactTrie(),
		allowTrie:  NewCompactTrie(),
	}

	h.rules.Store(emptyRuleSet())

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if !forwardCalled {
		t.Fatal("expected forward plugin to be called through the chain")
	}

	if len(rec.Msg.Answer) == 0 {
		t.Fatal("expected answer from forward plugin")
	}

	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", rcode)
	}
}
