package hostlist

import (
	"context"
	"net"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

const pluginName = "hostlist"
const defaultTTL = 600

// Hostlist is a plugin that blocks DNS queries based on AdGuard-format rules.
type Hostlist struct {
	Next    plugin.Handler
	Origins []string

	domainTrie   *Trie            // ||domain^ rules (ancestor match)
	exactTrie    *Trie            // hosts format rules (exact match)
	allowTrie    *Trie            // @@||domain^ rules (ancestor match)
	blockRegexps []*regexp.Regexp // /REGEX/ compiled patterns
	allowRegexps []*regexp.Regexp // @@/REGEX/ compiled patterns
	mu           sync.RWMutex

	mode       string      // "blacklist" | "whitelist"
	blockType  string      // "0.0.0.0" | "nxdomain" | "empty"
	safeSearch *SafeSearch // safe search handler
	loader     *Loader

	bypassIPs []net.IPNet // client IPs that bypass parental control and safe search
}

func (h *Hostlist) Name() string { return pluginName }

func soaFromZone(zone string) *dns.SOA {
	ns := dns.Fqdn("ns1." + zone)
	mbox := dns.Fqdn("admin." + zone)
	if zone == "." {
		ns = "ns1.dns.hostlist."
		mbox = "admin.dns.hostlist."
	}
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: defaultTTL},
		Ns:      ns,
		Mbox:    mbox,
		Serial:  1,
		Refresh: 86400,
		Retry:   7200,
		Expire:  1209600,
		Minttl:  300,
	}
}

func (h *Hostlist) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	qname := state.Name()

	zone := plugin.Zones(h.Origins).Matches(qname)
	if zone == "" {
		return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
	}

	// Check if client IP is in bypass whitelist
	// Bypass IPs skip both safe search and parental control blocking
	if h.isBypassIP(state.IP()) {
		return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
	}

	// Safe search check (before blocklist, takes priority)
	if h.safeSearch != nil && h.safeSearch.Enabled() {
		if entry, ok := h.safeSearch.Lookup(qname); ok {
			m := buildSafeSearchResponse(r, qname, entry)
			w.WriteMsg(m)
			return m.Rcode, nil
		}
	}

	name := strings.ToLower(qname)

	h.mu.RLock()
	domainBlocked := h.domainTrie.Lookup(name)
	exactBlocked := h.exactTrie.Lookup(name)
	allowed := h.allowTrie.Lookup(name)
	blockRegex := MatchAny(name, h.blockRegexps)
	allowRegex := MatchAny(name, h.allowRegexps)
	h.mu.RUnlock()

	blocked := domainBlocked || exactBlocked || blockRegex
	if allowRegex {
		allowed = true
	}

	var shouldBlock bool
	switch h.mode {
	case "whitelist":
		shouldBlock = !blocked || allowed
	default: // blacklist
		shouldBlock = blocked && !allowed
	}

	if !shouldBlock {
		return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
	}

	RequestBlockCount.WithLabelValues(metrics.WithServer(ctx), zone).Inc()
	log.Debugf("Blocking query for %s", qname)

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	switch h.blockType {
	case "nxdomain":
		m.Rcode = dns.RcodeNameError
		m.Ns = []dns.RR{soaFromZone(zone)}
	case "empty":
		m.Rcode = dns.RcodeSuccess
	default: // "0.0.0.0" or any value
		m.Rcode = dns.RcodeSuccess
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
			A:   net.IPv4zero,
		}}
	}

	w.WriteMsg(m)
	return m.Rcode, nil
}

// Update rebuilds the tries and regexps from a ParseResult via atomic swap.
// If SkipUpdate is true (content unchanged), the rebuild is skipped.
func (h *Hostlist) Update(result ParseResult) {
	if result.SkipUpdate {
		log.Debugf("Content unchanged, skipping trie rebuild")
		return
	}

	newDomain := NewTrie()
	newExact := NewTrie()
	newAllow := NewTrie()

	for _, d := range result.Blocked {
		newDomain.Insert(d)
	}
	for _, d := range result.BlockedExact {
		newExact.InsertExact(d)
	}
	for _, d := range result.Allowlist {
		newAllow.Insert(d)
	}

	newBlockRe := CompileRegexps(result.RegexBlock)
	newAllowRe := CompileRegexps(result.RegexAllow)

	h.mu.Lock()
	h.domainTrie = newDomain
	h.exactTrie = newExact
	h.allowTrie = newAllow
	h.blockRegexps = newBlockRe
	h.allowRegexps = newAllowRe
	h.mu.Unlock()

	// Force GC to free old tries and return memory to OS (AdGuard Home pattern)
	runtime.GC()
	debug.FreeOSMemory()

	total := newDomain.Len() + newExact.Len()
	DomainsLoaded.Set(float64(total))
	log.Infof("Updated hostlist: %d blocked domains, %d exact, %d allowlist, %d block regexps, %d allow regexps",
		newDomain.Len(), newExact.Len(), newAllow.Len(), len(newBlockRe), len(newAllowRe))
}

// isBypassIP checks if the given IP is in the bypass whitelist.
func (h *Hostlist) isBypassIP(ip string) bool {
	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}
	for _, cidr := range h.bypassIPs {
		if cidr.Contains(clientIP) {
			return true
		}
	}
	return false
}
