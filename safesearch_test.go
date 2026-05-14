package hostlist

import (
	"context"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// TestSafeSearchGoesThroughDownstream verifies that SafeSearch queries go through downstream plugins
func TestSafeSearchGoesThroughDownstream(t *testing.T) {
	downstreamCalled := false

	downstreamHandler := test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		downstreamCalled = true

		// Simulate forward plugin resolving the CNAME target
		m := new(dns.Msg)
		m.SetReply(r)
		// Return A record for the CNAME target
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: "forcesafesearch.google.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(216, 239, 38, 120),
		}}
		w.WriteMsg(m)
		return m.Rcode, nil
	})

	h := &Hostlist{
		Next:       downstreamHandler,
		Origins:    []string{"."},
		mode:       "blacklist",
		blockType:  "nxdomain",
		domainTrie: NewCompactTrie(),
		exactTrie:  NewCompactTrie(),
		allowTrie:  NewCompactTrie(),
		safeSearch: NewSafeSearch(true),
	}

	h.rules.Store(emptyRuleSet())

	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify downstream was called
	if !downstreamCalled {
		t.Fatal("expected downstream plugin to be called for SafeSearch domain")
	}

	// Verify response was rewritten with CNAME
	if rec.Msg == nil {
		t.Fatal("expected response message")
	}

	t.Logf("Response Answer section has %d records", len(rec.Msg.Answer))
	for i, rr := range rec.Msg.Answer {
		t.Logf("Answer[%d]: %T - %v", i, rr, rr)
	}

	if len(rec.Msg.Answer) == 0 {
		t.Fatal("expected answer section")
	}

	// Check that the answer is a CNAME to SafeSearch target
	cname, ok := rec.Msg.Answer[0].(*dns.CNAME)
	if !ok {
		t.Fatalf("expected CNAME record, got %T", rec.Msg.Answer[0])
	}

	if cname.Target != "forcesafesearch.google.com." {
		t.Errorf("expected CNAME target forcesafesearch.google.com., got %s", cname.Target)
	}

	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", rcode)
	}
}

// TestSafeSearchWithBlockedDomain verifies blocked domains don't get SafeSearch rewrite
func TestSafeSearchWithBlockedDomain(t *testing.T) {
	downstreamCalled := false

	downstreamHandler := test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		downstreamCalled = true
		m := new(dns.Msg)
		m.SetReply(r)
		w.WriteMsg(m)
		return m.Rcode, nil
	})

	h := &Hostlist{
		Next:       downstreamHandler,
		Origins:    []string{"."},
		mode:       "blacklist",
		blockType:  "nxdomain",
		domainTrie: NewCompactTrie(),
		exactTrie:  NewCompactTrie(),
		allowTrie:  NewCompactTrie(),
		safeSearch: NewSafeSearch(true),
	}

	// Add www.google.com to blocklist
	h.domainTrie.Insert("www.google.com.")
	h.rules.Store(&ruleSet{
		domainTrie: h.domainTrie,
		exactTrie:  h.exactTrie,
		allowTrie:  h.allowTrie,
	})

	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	h.ServeDNS(context.Background(), rec, req)

	// Downstream should NOT be called for blocked domains
	if downstreamCalled {
		t.Fatal("expected downstream plugin NOT to be called for blocked domain")
	}

	// Should return NXDOMAIN
	if rec.Msg.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for blocked domain, got %d", rec.Msg.Rcode)
	}
}

// TestSafeSearchDisabledDoesNotRewrite verifies disabled SafeSearch doesn't rewrite
func TestSafeSearchDisabledDoesNotRewrite(t *testing.T) {
	downstreamCalled := false

	downstreamHandler := test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		downstreamCalled = true
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.IPv4(8, 8, 8, 8),
		}}
		w.WriteMsg(m)
		return m.Rcode, nil
	})

	h := &Hostlist{
		Next:       downstreamHandler,
		Origins:    []string{"."},
		mode:       "blacklist",
		blockType:  "nxdomain",
		domainTrie: NewCompactTrie(),
		exactTrie:  NewCompactTrie(),
		allowTrie:  NewCompactTrie(),
		safeSearch: NewSafeSearch(false), // Disabled
	}

	h.rules.Store(emptyRuleSet())

	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	h.ServeDNS(context.Background(), rec, req)

	if !downstreamCalled {
		t.Fatal("expected downstream plugin to be called")
	}

	// Response should NOT be rewritten (should have A record from downstream)
	if len(rec.Msg.Answer) == 0 {
		t.Fatal("expected answer from downstream")
	}

	_, ok := rec.Msg.Answer[0].(*dns.A)
	if !ok {
		t.Errorf("expected A record from downstream, got %T", rec.Msg.Answer[0])
	}
}
