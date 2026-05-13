package hostlist

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// SafeSearchEntry defines a safe search rewrite rule.
type SafeSearchEntry struct {
	CNAME string // CNAME target (empty if using A/AAAA record)
	A     net.IP // A record (IPv4)
	AAAA  net.IP // AAAA record (IPv6)
}

// safeSearchMap is the built-in safe search domain mapping.
// Key: queried domain (without trailing dot), Value: rewrite target.
// Based on AdGuard Home's safe search implementation.
var safeSearchMap = map[string]SafeSearchEntry{
	// Google (all country TLDs redirect to forcesafesearch.google.com)
	"www.google.com":    {CNAME: "forcesafesearch.google.com."},
	"www.google.ac":     {CNAME: "forcesafesearch.google.com."},
	"www.google.ad":     {CNAME: "forcesafesearch.google.com."},
	"www.google.ae":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.af": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.ag": {CNAME: "forcesafesearch.google.com."},
	"www.google.al":     {CNAME: "forcesafesearch.google.com."},
	"www.google.am":     {CNAME: "forcesafesearch.google.com."},
	"www.google.co.ao":  {CNAME: "forcesafesearch.google.com."},
	"www.google.com.ar": {CNAME: "forcesafesearch.google.com."},
	"www.google.at":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.au": {CNAME: "forcesafesearch.google.com."},
	"www.google.az":     {CNAME: "forcesafesearch.google.com."},
	"www.google.ba":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.bd": {CNAME: "forcesafesearch.google.com."},
	"www.google.be":     {CNAME: "forcesafesearch.google.com."},
	"www.google.bf":     {CNAME: "forcesafesearch.google.com."},
	"www.google.bg":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.bh": {CNAME: "forcesafesearch.google.com."},
	"www.google.bi":     {CNAME: "forcesafesearch.google.com."},
	"www.google.bj":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.bn": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.bo": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.br": {CNAME: "forcesafesearch.google.com."},
	"www.google.bs":     {CNAME: "forcesafesearch.google.com."},
	"www.google.co.bw":  {CNAME: "forcesafesearch.google.com."},
	"www.google.by":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.bz": {CNAME: "forcesafesearch.google.com."},
	"www.google.ca":     {CNAME: "forcesafesearch.google.com."},
	"www.google.cd":     {CNAME: "forcesafesearch.google.com."},
	"www.google.cf":     {CNAME: "forcesafesearch.google.com."},
	"www.google.cg":     {CNAME: "forcesafesearch.google.com."},
	"www.google.ch":     {CNAME: "forcesafesearch.google.com."},
	"www.google.ci":     {CNAME: "forcesafesearch.google.com."},
	"www.google.co.ck":  {CNAME: "forcesafesearch.google.com."},
	"www.google.cl":     {CNAME: "forcesafesearch.google.com."},
	"www.google.cm":     {CNAME: "forcesafesearch.google.com."},
	"www.google.cn":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.co": {CNAME: "forcesafesearch.google.com."},
	"www.google.co.cr":  {CNAME: "forcesafesearch.google.com."},
	"www.google.com.cu": {CNAME: "forcesafesearch.google.com."},
	"www.google.cv":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.cy": {CNAME: "forcesafesearch.google.com."},
	"www.google.cz":     {CNAME: "forcesafesearch.google.com."},
	"www.google.de":     {CNAME: "forcesafesearch.google.com."},
	"www.google.dj":     {CNAME: "forcesafesearch.google.com."},
	"www.google.dk":     {CNAME: "forcesafesearch.google.com."},
	"www.google.dm":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.do": {CNAME: "forcesafesearch.google.com."},
	"www.google.dz":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.ec": {CNAME: "forcesafesearch.google.com."},
	"www.google.ee":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.eg": {CNAME: "forcesafesearch.google.com."},
	"www.google.es":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.et": {CNAME: "forcesafesearch.google.com."},
	"www.google.fi":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.fj": {CNAME: "forcesafesearch.google.com."},
	"www.google.fm":     {CNAME: "forcesafesearch.google.com."},
	"www.google.fr":     {CNAME: "forcesafesearch.google.com."},
	"www.google.ga":     {CNAME: "forcesafesearch.google.com."},
	"www.google.ge":     {CNAME: "forcesafesearch.google.com."},
	"www.google.gg":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.gh": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.gi": {CNAME: "forcesafesearch.google.com."},
	"www.google.gl":     {CNAME: "forcesafesearch.google.com."},
	"www.google.gm":     {CNAME: "forcesafesearch.google.com."},
	"www.google.gr":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.gt": {CNAME: "forcesafesearch.google.com."},
	"www.google.gy":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.hk": {CNAME: "forcesafesearch.google.com."},
	"www.google.hn":     {CNAME: "forcesafesearch.google.com."},
	"www.google.hr":     {CNAME: "forcesafesearch.google.com."},
	"www.google.ht":     {CNAME: "forcesafesearch.google.com."},
	"www.google.hu":     {CNAME: "forcesafesearch.google.com."},
	"www.google.co.id":  {CNAME: "forcesafesearch.google.com."},
	"www.google.iq":     {CNAME: "forcesafesearch.google.com."},
	"www.google.ie":     {CNAME: "forcesafesearch.google.com."},
	"www.google.co.il":  {CNAME: "forcesafesearch.google.com."},
	"www.google.im":     {CNAME: "forcesafesearch.google.com."},
	"www.google.co.in":  {CNAME: "forcesafesearch.google.com."},
	"www.google.is":     {CNAME: "forcesafesearch.google.com."},
	"www.google.it":     {CNAME: "forcesafesearch.google.com."},
	"www.google.je":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.jm": {CNAME: "forcesafesearch.google.com."},
	"www.google.jo":     {CNAME: "forcesafesearch.google.com."},
	"www.google.co.jp":  {CNAME: "forcesafesearch.google.com."},
	"www.google.co.ke":  {CNAME: "forcesafesearch.google.com."},
	"www.google.ki":     {CNAME: "forcesafesearch.google.com."},
	"www.google.kg":     {CNAME: "forcesafesearch.google.com."},
	"www.google.co.kr":  {CNAME: "forcesafesearch.google.com."},
	"www.google.com.kw": {CNAME: "forcesafesearch.google.com."},
	"www.google.kz":     {CNAME: "forcesafesearch.google.com."},
	"www.google.la":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.lb": {CNAME: "forcesafesearch.google.com."},
	"www.google.li":     {CNAME: "forcesafesearch.google.com."},
	"www.google.lk":     {CNAME: "forcesafesearch.google.com."},
	"www.google.co.ls":  {CNAME: "forcesafesearch.google.com."},
	"www.google.lt":     {CNAME: "forcesafesearch.google.com."},
	"www.google.lu":     {CNAME: "forcesafesearch.google.com."},
	"www.google.lv":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.ly": {CNAME: "forcesafesearch.google.com."},
	"www.google.co.ma":  {CNAME: "forcesafesearch.google.com."},
	"www.google.md":     {CNAME: "forcesafesearch.google.com."},
	"www.google.me":     {CNAME: "forcesafesearch.google.com."},
	"www.google.mg":     {CNAME: "forcesafesearch.google.com."},
	"www.google.mk":     {CNAME: "forcesafesearch.google.com."},
	"www.google.ml":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.mm": {CNAME: "forcesafesearch.google.com."},
	"www.google.mn":     {CNAME: "forcesafesearch.google.com."},
	"www.google.ms":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.mt": {CNAME: "forcesafesearch.google.com."},
	"www.google.mu":     {CNAME: "forcesafesearch.google.com."},
	"www.google.mv":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.mx": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.my": {CNAME: "forcesafesearch.google.com."},
	"www.google.co.mz":  {CNAME: "forcesafesearch.google.com."},
	"www.google.com.na": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.ng": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.ni": {CNAME: "forcesafesearch.google.com."},
	"www.google.ne":     {CNAME: "forcesafesearch.google.com."},
	"www.google.nl":     {CNAME: "forcesafesearch.google.com."},
	"www.google.no":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.np": {CNAME: "forcesafesearch.google.com."},
	"www.google.nr":     {CNAME: "forcesafesearch.google.com."},
	"www.google.nu":     {CNAME: "forcesafesearch.google.com."},
	"www.google.co.nz":  {CNAME: "forcesafesearch.google.com."},
	"www.google.com.om": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.pa": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.pe": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.pg": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.ph": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.pk": {CNAME: "forcesafesearch.google.com."},
	"www.google.pl":     {CNAME: "forcesafesearch.google.com."},
	"www.google.pn":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.pr": {CNAME: "forcesafesearch.google.com."},
	"www.google.ps":     {CNAME: "forcesafesearch.google.com."},
	"www.google.pt":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.py": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.qa": {CNAME: "forcesafesearch.google.com."},
	"www.google.ro":     {CNAME: "forcesafesearch.google.com."},
	"www.google.ru":     {CNAME: "forcesafesearch.google.com."},
	"www.google.rw":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.sa": {CNAME: "forcesafesearch.google.com."},
	"www.google.com.sb": {CNAME: "forcesafesearch.google.com."},
	"www.google.sc":     {CNAME: "forcesafesearch.google.com."},
	"www.google.se":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.sg": {CNAME: "forcesafesearch.google.com."},
	"www.google.sh":     {CNAME: "forcesafesearch.google.com."},
	"www.google.si":     {CNAME: "forcesafesearch.google.com."},
	"www.google.sk":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.sl": {CNAME: "forcesafesearch.google.com."},
	"www.google.sn":     {CNAME: "forcesafesearch.google.com."},
	"www.google.so":     {CNAME: "forcesafesearch.google.com."},
	"www.google.sm":     {CNAME: "forcesafesearch.google.com."},
	"www.google.sr":     {CNAME: "forcesafesearch.google.com."},
	"www.google.st":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.sv": {CNAME: "forcesafesearch.google.com."},
	"www.google.td":     {CNAME: "forcesafesearch.google.com."},
	"www.google.tg":     {CNAME: "forcesafesearch.google.com."},
	"www.google.co.th":  {CNAME: "forcesafesearch.google.com."},
	"www.google.com.tj": {CNAME: "forcesafesearch.google.com."},
	"www.google.tk":     {CNAME: "forcesafesearch.google.com."},
	"www.google.tl":     {CNAME: "forcesafesearch.google.com."},
	"www.google.tm":     {CNAME: "forcesafesearch.google.com."},
	"www.google.tn":     {CNAME: "forcesafesearch.google.com."},
	"www.google.to":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.tr": {CNAME: "forcesafesearch.google.com."},
	"www.google.tt":     {CNAME: "forcesafesearch.google.com."},
	"www.google.com.tw": {CNAME: "forcesafesearch.google.com."},
	"www.google.co.tz":  {CNAME: "forcesafesearch.google.com."},
	"www.google.com.ua": {CNAME: "forcesafesearch.google.com."},
	"www.google.co.ug":  {CNAME: "forcesafesearch.google.com."},
	"www.google.co.uk":  {CNAME: "forcesafesearch.google.com."},
	"www.google.com.uy": {CNAME: "forcesafesearch.google.com."},
	"www.google.co.uz":  {CNAME: "forcesafesearch.google.com."},
	"www.google.co.ve":  {CNAME: "forcesafesearch.google.com."},
	"www.google.vg":     {CNAME: "forcesafesearch.google.com."},
	"www.google.co.vi":  {CNAME: "forcesafesearch.google.com."},
	"www.google.co.za":  {CNAME: "forcesafesearch.google.com."},
	"www.google.co.zm":  {CNAME: "forcesafesearch.google.com."},
	"www.google.co.zw":  {CNAME: "forcesafesearch.google.com."},

	// Bing
	"edgeservices.bing.com": {CNAME: "strict.bing.com."},
	"www.bing.com":          {CNAME: "strict.bing.com."},
	"www.bing.net":          {CNAME: "strict.bing.com."},

	// YouTube
	"www.youtube.com":          {CNAME: "restrict.youtube.com."},
	"m.youtube.com":            {CNAME: "restrict.youtube.com."},
	"youtubei.googleapis.com":  {CNAME: "restrict.youtube.com."},
	"youtube.googleapis.com":   {CNAME: "restrict.youtube.com."},
	"www.youtube-nocookie.com": {CNAME: "restrict.youtube.com."},
	"youtube.com":              {CNAME: "restrict.youtube.com."},

	// DuckDuckGo
	"duckduckgo.com":       {CNAME: "safe.duckduckgo.com."},
	"start.duckduckgo.com": {CNAME: "safe.duckduckgo.com."},
	"www.duckduckgo.com":   {CNAME: "safe.duckduckgo.com."},

	// Brave
	"search.brave.com": {CNAME: "safesearch.brave.com."},

	// Ecosia
	"www.ecosia.org": {CNAME: "strict-safe-search.ecosia.org."},

	// Pixabay
	"pixabay.com": {CNAME: "safesearch.pixabay.com."},

	// Qwant
	"api.qwant.com":    {CNAME: "safeapi.qwant.com."},
	"www.qwant.com":    {CNAME: "www.qwant.com."},
	"search.qwant.com": {CNAME: "safe.qwant.com."},

	// Yandex
	"yandex.com":        {A: net.IPv4(213, 180, 193, 56)},
	"yandex.ru":         {A: net.IPv4(213, 180, 193, 56)},
	"yandex.by":         {A: net.IPv4(213, 180, 193, 56)},
	"yandex.kz":         {A: net.IPv4(213, 180, 193, 56)},
	"yandex.uz":         {A: net.IPv4(213, 180, 193, 56)},
	"yandex.com.tr":     {A: net.IPv4(213, 180, 193, 56)},
	"ya.ru":             {A: net.IPv4(213, 180, 193, 56)},
	"www.yandex.com":    {A: net.IPv4(213, 180, 193, 56)},
	"www.yandex.ru":     {A: net.IPv4(213, 180, 193, 56)},
	"www.yandex.by":     {A: net.IPv4(213, 180, 193, 56)},
	"www.yandex.kz":     {A: net.IPv4(213, 180, 193, 56)},
	"www.yandex.com.tr": {A: net.IPv4(213, 180, 193, 56)},

	// Yahoo
	"search.yahoo.com":    {CNAME: "family.search.yahoo.com."},
	"search.yahoo.co.jp":  {CNAME: "family.search.yahoo.co.jp."},
	"search.yahoo.co.uk":  {CNAME: "family.search.yahoo.co.uk."},
	"search.yahoo.com.au": {CNAME: "family.search.yahoo.com.au."},
	"search.yahoo.co.in":  {CNAME: "family.search.yahoo.co.in."},

	// Naver (Korean search engine)
	"search.naver.com": {CNAME: "safe.search.naver.com."},
	"www.naver.com":    {CNAME: "safe.naver.com."},

	// Ask.com
	"www.ask.com": {CNAME: "safe.ask.com."},

	// Startpage
	"www.startpage.com": {CNAME: "family.startpage.com."},
	"startpage.com":     {CNAME: "family.startpage.com."},

	// AOL Search
	"search.aol.com": {CNAME: "safe.search.aol.com."},

	// Dogpile
	"www.dogpile.com": {CNAME: "safe.dogpile.com."},

	// WebCrawler
	"www.webcrawler.com": {CNAME: "safe.webcrawler.com."},

	// Lycos
	"search.lycos.com": {CNAME: "family.lycos.com."},

	// Infospace
	"www.infospace.com": {CNAME: "safe.infospace.com."},

	// Swisscows
	"swisscows.com": {CNAME: "family.swisscows.com."},

	// Gibiru
	"gibiru.com": {CNAME: "safe.gibiru.com."},

	// Mojeek
	"www.mojeek.com": {CNAME: "family.mojeek.com."},

	// Qwant Junior (kids search)
	"qwantjunior.com": {CNAME: "qwantjunior.com."},

	// KidRex
	"kidrex.org": {CNAME: "safe.kidrex.org."},

	// Kiddle
	"kiddle.co": {CNAME: "safe.kiddle.co."},
}

// cachedIP stores a resolved IP with its expiry time.
type cachedIP struct {
	ip      net.IP
	expires time.Time
}

// SafeSearch handles safe search DNS rewrites.
type SafeSearch struct {
	enabled          bool
	mu               sync.RWMutex
	entries          map[string]SafeSearchEntry
	resolveCache     map[string]cachedIP // CNAME target -> resolved A record with TTL
	resolveCacheAAAA map[string]cachedIP // CNAME target -> resolved AAAA record with TTL
	cacheTTL         time.Duration       // TTL for cached DNS resolutions
}

// NewSafeSearch creates a new SafeSearch handler.
func NewSafeSearch(enabled bool) *SafeSearch {
	entries := make(map[string]SafeSearchEntry, len(safeSearchMap))
	for k, v := range safeSearchMap {
		entries[k] = v
	}
	return &SafeSearch{
		enabled:          enabled,
		entries:          entries,
		resolveCache:     make(map[string]cachedIP),
		resolveCacheAAAA: make(map[string]cachedIP),
		cacheTTL:         defaultTTL * time.Second,
	}
}

// Lookup checks if a domain should be rewritten for safe search.
// Returns the entry and true if matched.
// For CNAME-only entries, it resolves the CNAME target to A and AAAA records
// on demand and caches the results with TTL expiry.
func (s *SafeSearch) Lookup(domain string) (SafeSearchEntry, bool) {
	if !s.enabled {
		return SafeSearchEntry{}, false
	}
	name := strings.ToLower(strings.TrimSuffix(domain, "."))
	s.mu.RLock()
	entry, ok := s.entries[name]
	s.mu.RUnlock()
	if !ok {
		return SafeSearchEntry{}, false
	}

	// If entry has CNAME but no A/AAAA record, resolve the CNAME target on demand
	if entry.CNAME != "" && entry.A == nil && entry.AAAA == nil {
		target := strings.TrimSuffix(entry.CNAME, ".")
		now := time.Now()

		s.mu.RLock()
		aCached, aOk := s.resolveCache[target]
		aaaaCached, aaaaOk := s.resolveCacheAAAA[target]
		s.mu.RUnlock()

		// Check if cached entries are still valid
		aValid := aOk && now.Before(aCached.expires)
		aaaaValid := aaaaOk && now.Before(aaaaCached.expires)

		if !aValid || !aaaaValid {
			ips, err := net.LookupHost(target)
			if err == nil {
				expires := now.Add(s.cacheTTL)
				for _, raw := range ips {
					parsed := net.ParseIP(raw)
					if parsed == nil {
						continue
					}
					if parsed.To4() != nil && !aValid {
						s.mu.Lock()
						s.resolveCache[target] = cachedIP{ip: parsed, expires: expires}
						s.mu.Unlock()
						aCached = cachedIP{ip: parsed, expires: expires}
						aValid = true
					} else if parsed.To16() != nil && parsed.To4() == nil && !aaaaValid {
						s.mu.Lock()
						s.resolveCacheAAAA[target] = cachedIP{ip: parsed, expires: expires}
						s.mu.Unlock()
						aaaaCached = cachedIP{ip: parsed, expires: expires}
						aaaaValid = true
					}
				}
			}
		}
		if aValid {
			entry.A = aCached.ip
		}
		if aaaaValid {
			entry.AAAA = aaaaCached.ip
		}
	}

	return entry, true
}

// SetEnabled enables or disables safe search.
// When disabling, clears the DNS resolution cache to free memory.
func (s *SafeSearch) SetEnabled(enabled bool) {
	s.mu.Lock()
	s.enabled = enabled
	if !enabled {
		s.resolveCache = make(map[string]cachedIP)
		s.resolveCacheAAAA = make(map[string]cachedIP)
	}
	s.mu.Unlock()
}

// Enabled returns whether safe search is enabled.
func (s *SafeSearch) Enabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.enabled
}

// buildSafeSearchResponse builds a DNS response for a safe search rewrite.
// Prefers A/AAAA records (resolved from CNAME targets) over CNAME responses.
func buildSafeSearchResponse(r *dns.Msg, qname string, entry SafeSearchEntry) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Rcode = dns.RcodeSuccess

	qtype := r.Question[0].Qtype

	if entry.A != nil && (qtype == dns.TypeA || qtype == dns.TypeANY) {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
			A:   entry.A,
		})
	}
	if entry.AAAA != nil && (qtype == dns.TypeAAAA || qtype == dns.TypeANY) {
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: defaultTTL},
			AAAA: entry.AAAA,
		})
	}
	if len(m.Answer) == 0 && entry.CNAME != "" {
		cname := &dns.CNAME{
			Hdr:    dns.RR_Header{Name: qname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: defaultTTL},
			Target: entry.CNAME,
		}
		m.Answer = append(m.Answer, cname)
	}

	return m
}
