package hostlist

import (
	"context"
	"net"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

const pluginName = "hostlist"
const defaultTTL = 600

// safeSearchResponseWriter wraps a ResponseWriter to rewrite responses with SafeSearch CNAME
type safeSearchResponseWriter struct {
	dns.ResponseWriter
	entry   *SafeSearchEntry
	qname   string
	request *dns.Msg // Store the original request
}

func (w *safeSearchResponseWriter) WriteMsg(m *dns.Msg) error {
	rewriteMsg := new(dns.Msg)
	rewriteMsg.SetReply(w.request)
	rewriteMsg.Authoritative = m.Authoritative
	rewriteMsg.RecursionAvailable = m.RecursionAvailable
	rewriteMsg.Rcode = m.Rcode

	if w.entry.CNAME != "" {
		cname := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   w.qname,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			Target: w.entry.CNAME,
		}
		rewriteMsg.Answer = []dns.RR{cname}

		// Copy A/AAAA records from downstream response as additional records
		// These are the resolved IPs for the CNAME target
		for _, rr := range m.Answer {
			switch r := rr.(type) {
			case *dns.A:
				r.Hdr.Name = w.entry.CNAME
				rewriteMsg.Extra = append(rewriteMsg.Extra, r)
			case *dns.AAAA:
				r.Hdr.Name = w.entry.CNAME
				rewriteMsg.Extra = append(rewriteMsg.Extra, r)
			}
		}
	} else if w.entry.A != nil {
		a := &dns.A{
			Hdr: dns.RR_Header{
				Name:   w.qname,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			A: w.entry.A,
		}
		rewriteMsg.Answer = []dns.RR{a}
	} else if w.entry.AAAA != nil {
		aaaa := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   w.qname,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    defaultTTL,
			},
			AAAA: w.entry.AAAA,
		}
		rewriteMsg.Answer = []dns.RR{aaaa}
	}

	rewriteMsg.Ns = m.Ns

	return w.ResponseWriter.WriteMsg(rewriteMsg)
}

// Hostlist is a plugin that blocks DNS queries based on AdGuard-format rules.
type Hostlist struct {
	Next    plugin.Handler
	Origins []string

	rules atomic.Value // stores *ruleSet; published as a complete immutable snapshot

	mode       string      // "blacklist" | "whitelist"
	blockType  string      // "0.0.0.0" | "nxdomain" | "empty"
	safeSearch *SafeSearch // safe search handler
	loader     *Loader

	bypassIPs []net.IPNet // client IPs that bypass parental control and safe search
}

type ruleSet struct {
	domainTrie   *CompactTrie
	exactTrie    *CompactTrie
	allowTrie    *CompactTrie
	blockRegexps []*regexp.Regexp
	allowRegexps []*regexp.Regexp
	ipMap        map[string]string // domain -> IP mapping for hosts format rules
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

	// Check safesearch match but don't respond immediately
	// We'll apply the rewrite after downstream plugins resolve the query
	var safeSearchEntry *SafeSearchEntry
	if h.safeSearch != nil && h.safeSearch.Enabled() {
		if entry, ok := h.safeSearch.Lookup(qname); ok {
			safeSearchEntry = &entry
		}
	}

	name := strings.ToLower(qname)

	rules := h.currentRules()

	// Ultra-fast path: if no rules loaded at all, immediately pass to next
	// This avoids any trie lookups or regex matching when rules haven't loaded yet
	if rules.domainTrie.Len() == 0 && rules.exactTrie.Len() == 0 &&
		len(rules.blockRegexps) == 0 && len(rules.allowRegexps) == 0 &&
		rules.allowTrie.Len() == 0 {
		if safeSearchEntry != nil {
			rw := &safeSearchResponseWriter{
				ResponseWriter: w,
				entry:          safeSearchEntry,
				qname:          qname,
				request:        r,
			}
			if safeSearchEntry.CNAME != "" {
				newReq := r.Copy()
				newReq.Question[0].Name = safeSearchEntry.CNAME
				return plugin.NextOrFailure(h.Name(), h.Next, ctx, rw, newReq)
			}
			return plugin.NextOrFailure(h.Name(), h.Next, ctx, rw, r)
		}
		return plugin.NextOrFailure(h.Name(), h.Next, ctx, w, r)
	}

	domainBlocked := rules.domainTrie.Lookup(name)
	exactBlocked := rules.exactTrie.Lookup(name)
	allowed := rules.allowTrie.Lookup(name)
	blockRegex := MatchAny(name, rules.blockRegexps)
	allowRegex := MatchAny(name, rules.allowRegexps)

	log.Debugf("hostlist: qname=%q domainBlocked=%v exactBlocked=%v allowed=%v blockRegex=%v allowRegex=%v mode=%q",
		qname, domainBlocked, exactBlocked, allowed, blockRegex, allowRegex, h.mode)

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
		if safeSearchEntry != nil && !allowed {
			rw := &safeSearchResponseWriter{
				ResponseWriter: w,
				entry:          safeSearchEntry,
				qname:          qname,
				request:        r,
			}
			// Modify the request to query the CNAME target instead of the original domain
			// This ensures downstream returns the correct IP for the safe search target
			if safeSearchEntry.CNAME != "" {
				newReq := r.Copy()
				newReq.Question[0].Name = safeSearchEntry.CNAME
				return plugin.NextOrFailure(h.Name(), h.Next, ctx, rw, newReq)
			}
			return plugin.NextOrFailure(h.Name(), h.Next, ctx, rw, r)
		}
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
		// Check if we have a specific IP for this domain from hosts format rules
		blockIP := h.blockType
		if rules.ipMap != nil {
			if ip, ok := rules.ipMap[name]; ok {
				blockIP = ip
			}
		}
		// Parse the IP address
		ipAddr := net.ParseIP(blockIP)
		if ipAddr == nil {
			// Fallback to 0.0.0.0 if parsing fails
			ipAddr = net.IPv4zero
		}
		m.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
			A:   ipAddr.To4(),
		}}
	}

	w.WriteMsg(m)
	return m.Rcode, nil
}

// Update rebuilds the tries and regexps from a ParseResult via atomic swap.
// If SkipUpdate is true (content unchanged), the rebuild is skipped.
// A new immutable snapshot is built off to the side and published in one store,
// so queries never observe nil or partially rebuilt rules.
func (h *Hostlist) Update(result ParseResult) {
	defer func() {
		if r := recover(); r != nil {
			log.Errorf("Panic in Update: %v", r)
		}
	}()

	log.Infof("Update called: SkipUpdate=%v, rules.Load()=%v",
		result.SkipUpdate, h.rules.Load() != nil)

	if result.SkipUpdate && h.rules.Load() != nil {
		log.Debugf("Content unchanged, skipping trie rebuild")
		return
	}

	// Parse and compile new data first (without holding the lock)
	// Use CompactTrie for memory optimization (AdGuardHome-style)
	log.Infof("Building domain trie with %d entries...", len(result.Blocked))
	newDomain := NewCompactTrie()
	for _, d := range result.Blocked {
		newDomain.insertNoLock(d) // Use lock-free insert for batch operation
	}
	log.Infof("Domain trie built (%d nodes). Building exact trie with %d entries...", newDomain.Len(), len(result.BlockedExact))
	newExact := NewCompactTrie()
	for _, d := range result.BlockedExact {
		newExact.insertExactNoLock(d) // Use lock-free insert for batch operation
	}
	log.Infof("Exact trie built (%d nodes). Building allow trie with %d entries...", newExact.Len(), len(result.Allowlist))
	newAllow := NewCompactTrie()
	for _, d := range result.Allowlist {
		newAllow.insertNoLock(d) // Use lock-free insert for batch operation
	}
	log.Infof("All tries built. Compiling regexps...")

	newBlockRe := CompileRegexps(result.RegexBlock)
	newAllowRe := CompileRegexps(result.RegexAllow)

	newRules := &ruleSet{
		domainTrie:   newDomain,
		exactTrie:    newExact,
		allowTrie:    newAllow,
		blockRegexps: newBlockRe,
		allowRegexps: newAllowRe,
		ipMap:        result.IPMap, // Copy the IP mappings
	}

	log.Infof("Before Store: newRules.exactTrie.Len()=%d", newRules.exactTrie.Len())

	// Clear children maps to save memory (queries will use linear search)
	newDomain.ClearChildrenMaps()
	newExact.ClearChildrenMaps()
	newAllow.ClearChildrenMaps()

	h.rules.Store(newRules)
	storedRules := h.rules.Load()
	if storedRules != nil {
		if rs, ok := storedRules.(*ruleSet); ok {
			log.Infof("After Store: exactTrie.Len()=%d", rs.exactTrie.Len())
		}
	}

	total := newDomain.Len() + newExact.Len()
	DomainsLoaded.Set(float64(total))
	log.Infof("Updated hostlist: %d blocked domains, %d exact, %d allowlist, %d block regexps, %d allow regexps",
		newDomain.Len(), newExact.Len(), newAllow.Len(), len(newBlockRe), len(newAllowRe))

	// Force garbage collection to release unused memory
	runtime.GC()
}

// Cleanup releases all resources held by the Hostlist plugin.
// This is called during shutdown to ensure proper memory cleanup,
// especially important during reload operations.
func (h *Hostlist) Cleanup() {
	log.Infof("Hostlist: cleaning up resources")

	h.rules.Store(emptyRuleSet())
	h.bypassIPs = nil

	// Clear safeSearch if it exists
	if h.safeSearch != nil {
		h.safeSearch.cleanup()
		h.safeSearch = nil
	}

	// Clear loader
	h.loader = nil

	// Force GC to reclaim memory
	runtime.GC()
	debug.FreeOSMemory()

	log.Infof("Hostlist: cleanup completed")
}

func (h *Hostlist) currentRules() *ruleSet {
	if v := h.rules.Load(); v != nil {
		return v.(*ruleSet)
	}
	return emptyRuleSet()
}

func emptyRuleSet() *ruleSet {
	return &ruleSet{
		domainTrie: NewCompactTrie(),
		exactTrie:  NewCompactTrie(),
		allowTrie:  NewCompactTrie(),
	}
}

// isBypassIP checks if the given IP is in the bypass whitelist.
// It handles IPv6-mapped IPv4 addresses (e.g., ::ffff:172.18.44.255).
func (h *Hostlist) isBypassIP(ip string) bool {
	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		return false
	}

	// Convert IPv6-mapped IPv4 address to pure IPv4 for matching
	// e.g., ::ffff:172.18.44.255 -> 172.18.44.255
	if clientIP.To4() != nil {
		// Already a pure IPv4 address
	} else if ipv6 := clientIP.To16(); ipv6 != nil {
		// Check if it's an IPv6-mapped IPv4 address (::ffff:x.x.x.x)
		if ipv6[0] == 0 && ipv6[1] == 0 && ipv6[2] == 0 && ipv6[3] == 0 &&
			ipv6[4] == 0 && ipv6[5] == 0 && ipv6[6] == 0 && ipv6[7] == 0 &&
			ipv6[8] == 0 && ipv6[9] == 0 && ipv6[10] == 0xff && ipv6[11] == 0xff {
			// Extract the IPv4 part and convert to net.IPv4
			clientIP = net.IPv4(ipv6[12], ipv6[13], ipv6[14], ipv6[15])
		}
	}

	for _, cidr := range h.bypassIPs {
		if cidr.Contains(clientIP) {
			return true
		}
	}
	return false
}
