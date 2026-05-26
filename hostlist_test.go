package hostlist

import (
	"context"
	"net"
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
)

func makeRules(domainTrie, exactTrie, allowTrie *CompactTrie, blockRegexps, allowRegexps []string) *ruleSet {
	return &ruleSet{
		domainTrie:   domainTrie,
		exactTrie:    exactTrie,
		allowTrie:    allowTrie,
		blockRegexps: CompileRegexps(blockRegexps),
		allowRegexps: CompileRegexps(allowRegexps),
	}
}

func TestServeDNSBlacklistBlocked(t *testing.T) {
	domainTrie := NewCompactTrie()
	domainTrie.Insert("ads.example.com.")

	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
	}
	h.rules.Store(makeRules(domainTrie, NewCompactTrie(), NewCompactTrie(), nil, nil))

	req := new(dns.Msg)
	req.SetQuestion("ads.example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got %d", rcode)
	}
	if rec.Msg == nil {
		t.Fatal("expected response message")
	}
	if rec.Msg.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN in response, got %d", rec.Msg.Rcode)
	}
	if len(rec.Msg.Ns) != 1 {
		t.Fatalf("expected 1 SOA in authority section, got %d", len(rec.Msg.Ns))
	}
	if _, ok := rec.Msg.Ns[0].(*dns.SOA); !ok {
		t.Fatal("expected SOA record in authority section")
	}
}

func TestServeDNSBlacklistAncestorMatch(t *testing.T) {
	domainTrie := NewCompactTrie()
	domainTrie.Insert("example.com.")

	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
	}
	h.rules.Store(makeRules(domainTrie, NewCompactTrie(), NewCompactTrie(), nil, nil))

	req := new(dns.Msg)
	req.SetQuestion("sub.example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, _ := h.ServeDNS(context.Background(), rec, req)
	if rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for subdomain, got %d", rcode)
	}
}

func TestServeDNSBlacklistAllowed(t *testing.T) {
	domainTrie := NewCompactTrie()
	domainTrie.Insert("example.com.")
	allowTrie := NewCompactTrie()
	allowTrie.Insert("example.com.")

	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
	}
	h.rules.Store(makeRules(domainTrie, NewCompactTrie(), allowTrie, nil, nil))

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeAAAA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, _ := h.ServeDNS(context.Background(), rec, req)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected pass-through, got rcode %d", rcode)
	}
}

func TestServeDNSBlacklistNotBlocked(t *testing.T) {
	domainTrie := NewCompactTrie()
	domainTrie.Insert("ads.example.com.")

	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
	}
	h.rules.Store(makeRules(domainTrie, NewCompactTrie(), NewCompactTrie(), nil, nil))

	req := new(dns.Msg)
	req.SetQuestion("normal.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, _ := h.ServeDNS(context.Background(), rec, req)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected pass-through, got rcode %d", rcode)
	}
}

func TestServeDNSWhitelistMode(t *testing.T) {
	domainTrie := NewCompactTrie()
	domainTrie.Insert("allowed.com.")

	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "whitelist",
		blockType: "nxdomain",
	}
	h.rules.Store(makeRules(domainTrie, NewCompactTrie(), NewCompactTrie(), nil, nil))

	req := new(dns.Msg)
	req.SetQuestion("allowed.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, _ := h.ServeDNS(context.Background(), rec, req)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected pass-through for allowed domain, got %d", rcode)
	}

	req.SetQuestion("blocked.com.", dns.TypeA)
	rec = dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, _ = h.ServeDNS(context.Background(), rec, req)
	if rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for non-listed domain, got %d", rcode)
	}
}

func TestServeDNSBlockTypeEmpty(t *testing.T) {
	domainTrie := NewCompactTrie()
	domainTrie.Insert("ads.example.com.")

	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "empty",
	}
	h.rules.Store(makeRules(domainTrie, NewCompactTrie(), NewCompactTrie(), nil, nil))

	req := new(dns.Msg)
	req.SetQuestion("ads.example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, _ := h.ServeDNS(context.Background(), rec, req)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess for empty block_type, got %d", rcode)
	}
	if rec.Msg == nil {
		t.Fatal("expected response message")
	}
	if len(rec.Msg.Answer) != 0 {
		t.Fatalf("expected empty answer, got %d records", len(rec.Msg.Answer))
	}
}

func TestServeDNSAAAA(t *testing.T) {
	domainTrie := NewCompactTrie()
	domainTrie.Insert("ads.example.com.")

	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
	}
	h.rules.Store(makeRules(domainTrie, NewCompactTrie(), NewCompactTrie(), nil, nil))

	req := new(dns.Msg)
	req.SetQuestion("ads.example.com.", dns.TypeAAAA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, _ := h.ServeDNS(context.Background(), rec, req)
	if rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for AAAA query, got %d", rcode)
	}
}

func TestServeDNSUsesHostsExactBlockIP(t *testing.T) {
	exactTrie := NewCompactTrie()
	exactTrie.InsertExactValue("hosts.example.com.", "127.0.0.1")

	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "0.0.0.0",
	}
	h.rules.Store(makeRules(NewCompactTrie(), exactTrie, NewCompactTrie(), nil, nil))

	req := new(dns.Msg)
	req.SetQuestion("hosts.example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected RcodeSuccess, got %d", rcode)
	}
	if rec.Msg == nil || len(rec.Msg.Answer) != 1 {
		t.Fatalf("expected single answer, got %#v", rec.Msg)
	}
	rr, ok := rec.Msg.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("expected A answer, got %T", rec.Msg.Answer[0])
	}
	if got, want := rr.A.String(), "127.0.0.1"; got != want {
		t.Fatalf("expected block IP %q, got %q", want, got)
	}
}

func TestServeDNSRegex(t *testing.T) {
	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
	}
	h.rules.Store(makeRules(NewCompactTrie(), NewCompactTrie(), NewCompactTrie(), []string{`^ads\d*\.`}, nil))

	req := new(dns.Msg)
	req.SetQuestion("ads1.example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, _ := h.ServeDNS(context.Background(), rec, req)
	if rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN for regex match, got %d", rcode)
	}
}

func TestUpdateSkipDoesNotSkipInitialLoad(t *testing.T) {
	h := &Hostlist{}
	h.Update(ParseResult{
		Blocked:    []string{"ads.example.com."},
		SkipUpdate: true,
	})

	rules := h.currentRules()
	if !rules.domainTrie.Lookup("ads.example.com.") {
		t.Fatal("expected initial load even when result is marked SkipUpdate")
	}
}

func TestUpdatePublishesCompleteSnapshot(t *testing.T) {
	h := &Hostlist{}
	h.Update(ParseResult{Blocked: []string{"old.example.com."}})
	oldRules := h.currentRules()

	h.Update(ParseResult{Blocked: []string{"new.example.com."}})
	newRules := h.currentRules()

	if oldRules == newRules {
		t.Fatal("expected a new immutable snapshot")
	}
	if !oldRules.domainTrie.Lookup("old.example.com.") {
		t.Fatal("expected old snapshot to remain readable")
	}
	if !newRules.domainTrie.Lookup("new.example.com.") {
		t.Fatal("expected new snapshot to contain updated rules")
	}
}

func TestServeDNSWithEmptyRules(t *testing.T) {
	h := &Hostlist{
		Next:      test.NextHandler(dns.RcodeSuccess, nil),
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	rcode, _ := h.ServeDNS(context.Background(), rec, req)
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected pass-through with empty rules, got rcode %d", rcode)
	}
}

func TestServeDNSBypassIPUsesECSBeforeRemoteAddr(t *testing.T) {
	nextCalled := false
	var upstreamReq *dns.Msg
	nextHandler := test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		nextCalled = true
		upstreamReq = r
		m := new(dns.Msg)
		m.SetReply(r)
		return dns.RcodeSuccess, w.WriteMsg(m)
	})

	_, bypassCIDR, _ := net.ParseCIDR("192.168.100.220/32")
	domainTrie := NewCompactTrie()
	domainTrie.Insert("blocked.example.com.")

	h := &Hostlist{
		Next:      nextHandler,
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
		bypassIPs: []net.IPNet{*bypassCIDR},
	}
	h.rules.Store(makeRules(domainTrie, NewCompactTrie(), NewCompactTrie(), nil, nil))

	req := new(dns.Msg)
	req.SetQuestion("blocked.example.com.", dns.TypeA)
	req.SetEdns0(1232, false)
	req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 32,
		Address:       net.ParseIP("192.168.100.220").To4(),
	})

	rec := dnstest.NewRecorder(&test.ResponseWriter{RemoteIP: "127.0.0.1"})

	rcode, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !nextCalled {
		t.Fatal("expected bypass_ip to use ECS client IP and call next plugin")
	}
	if opt := upstreamReq.IsEdns0(); opt != nil && len(opt.Option) != 0 {
		t.Fatal("expected private ECS to be stripped before forwarding upstream")
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected pass-through, got rcode %d", rcode)
	}
}

func TestServeDNSBypassIPFallsBackToRemoteAddr(t *testing.T) {
	nextCalled := false
	nextHandler := test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		nextCalled = true
		m := new(dns.Msg)
		m.SetReply(r)
		return dns.RcodeSuccess, w.WriteMsg(m)
	})

	_, bypassCIDR, _ := net.ParseCIDR("192.168.100.220/32")
	domainTrie := NewCompactTrie()
	domainTrie.Insert("blocked.example.com.")

	h := &Hostlist{
		Next:      nextHandler,
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
		bypassIPs: []net.IPNet{*bypassCIDR},
	}
	h.rules.Store(makeRules(domainTrie, NewCompactTrie(), NewCompactTrie(), nil, nil))

	req := new(dns.Msg)
	req.SetQuestion("blocked.example.com.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{RemoteIP: "192.168.100.220"})

	rcode, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !nextCalled {
		t.Fatal("expected bypass_ip to fall back to RemoteAddr and call next plugin")
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected pass-through, got rcode %d", rcode)
	}
}

func TestServeDNSKeepsPublicECSForUpstream(t *testing.T) {
	var upstreamReq *dns.Msg
	nextHandler := test.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		upstreamReq = r
		m := new(dns.Msg)
		m.SetReply(r)
		return dns.RcodeSuccess, w.WriteMsg(m)
	})

	h := &Hostlist{
		Next:      nextHandler,
		Origins:   []string{"."},
		mode:      "blacklist",
		blockType: "nxdomain",
	}
	h.rules.Store(emptyRuleSet())

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(1232, false)
	req.IsEdns0().Option = append(req.IsEdns0().Option, &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 32,
		Address:       net.ParseIP("1.1.1.1").To4(),
	})

	rec := dnstest.NewRecorder(&test.ResponseWriter{RemoteIP: "127.0.0.1"})

	rcode, err := h.ServeDNS(context.Background(), rec, req)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if upstreamReq == nil {
		t.Fatal("expected next plugin to receive request")
	}

	opt := upstreamReq.IsEdns0()
	if opt == nil || len(opt.Option) != 1 {
		t.Fatal("expected public ECS to be kept when forwarding upstream")
	}
	subnet, ok := opt.Option[0].(*dns.EDNS0_SUBNET)
	if !ok {
		t.Fatalf("expected EDNS0_SUBNET, got %T", opt.Option[0])
	}
	if got := subnet.Address.String(); got != "1.1.1.1" {
		t.Fatalf("expected forwarded ECS address 1.1.1.1, got %s", got)
	}
	if rcode != dns.RcodeSuccess {
		t.Fatalf("expected pass-through, got rcode %d", rcode)
	}
}
