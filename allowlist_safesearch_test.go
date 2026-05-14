package hostlist

import (
	"context"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

// TestAllowlistOverridesSafeSearch verifies that allowlisted domains bypass SafeSearch
func TestAllowlistOverridesSafeSearch(t *testing.T) {
	downstreamCalled := false

	downstreamHandler := test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		downstreamCalled = true
		m := new(dns.Msg)
		m.SetReply(r)
		// Return normal A record (not rewritten)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{8, 8, 8, 8},
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

	// Add m.youtube.com to allowlist
	h.allowTrie.Insert("m.youtube.com.")

	// Create a ruleSet with the allowlist
	h.rules.Store(&ruleSet{
		domainTrie: h.domainTrie,
		exactTrie:  h.exactTrie,
		allowTrie:  h.allowTrie,
	})

	req := new(dns.Msg)
	req.SetQuestion("m.youtube.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	// Verify downstream was called
	if !downstreamCalled {
		t.Fatal("expected downstream plugin to be called")
	}

	// Verify response is NOT rewritten (should have A record from downstream)
	if rec.Msg == nil {
		t.Fatal("expected response message")
	}

	if len(rec.Msg.Answer) == 0 {
		t.Fatal("expected answer from downstream")
	}

	// Should be A record, not CNAME
	_, ok := rec.Msg.Answer[0].(*dns.A)
	if !ok {
		t.Errorf("expected A record from downstream (not SafeSearch CNAME), got %T: %v", rec.Msg.Answer[0], rec.Msg.Answer[0])
	}

	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", rcode)
	}
}

// TestSafeSearchAppliedWhenNotAllowlisted verifies SafeSearch works for non-allowlisted domains
func TestSafeSearchAppliedWhenNotAllowlisted(t *testing.T) {
	downstreamCalled := false

	downstreamHandler := test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		downstreamCalled = true
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: "forcesafesearch.google.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{216, 239, 38, 120},
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
		allowTrie:  NewCompactTrie(), // Empty allowlist
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

	if !downstreamCalled {
		t.Fatal("expected downstream plugin to be called")
	}

	// Should be rewritten to CNAME
	cname, ok := rec.Msg.Answer[0].(*dns.CNAME)
	if !ok {
		t.Errorf("expected CNAME from SafeSearch, got %T: %v", rec.Msg.Answer[0], rec.Msg.Answer[0])
	}

	if ok && cname.Target != "forcesafesearch.google.com." {
		t.Errorf("expected CNAME target forcesafesearch.google.com., got %s", cname.Target)
	}

	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", rcode)
	}
}
