package hostlist

import (
	"net"
	"path/filepath"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin(pluginName)

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	h, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	// Initialize with empty rule set immediately during parsing
	// This ensures DNS queries work even before startup completes
	h.rules.Store(emptyRuleSet())

	c.OnStartup(func() error {
		// Start async refresh immediately (no cache trie to avoid double memory)
		go func() {
			log.Infof("Starting LoadAll in goroutine")
			result := h.loader.LoadAll()
			log.Infof("LoadAll returned, calling Update with SkipUpdate=%v", result.SkipUpdate)
			h.Update(result)
			log.Infof("Update completed")
		}()

		return nil
	})

	stopChan := h.loader.StartPeriodicRefresh(func() {
		result := h.loader.LoadAll()
		h.Update(result)
	})

	c.OnShutdown(func() error {
		close(stopChan)
		h.Cleanup()
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		h.Next = next
		return h
	})

	return nil
}

func parse(c *caddy.Controller) (*Hostlist, error) {
	h := &Hostlist{
		Origins:    plugin.OriginsFromArgsOrServerBlock(nil, c.ServerBlockKeys),
		mode:       "blacklist",
		blockType:  "0.0.0.0",
		domainTrie: NewCompactTrie(),
		exactTrie:  NewCompactTrie(),
		allowTrie:  NewCompactTrie(),
	}

	var sources []FilterSource
	var allowSources []FilterSource
	var userRules []string
	seenSources := make(map[string]struct{})
	seenAllowSources := make(map[string]struct{})
	seenUserRules := make(map[string]struct{})
	var cacheDir string
	refreshInterval := 4 * 24 * time.Hour // default 4 days

	config := dnsserver.GetConfig(c)

	for c.Next() {
		args := c.RemainingArgs()
		if len(args) > 0 {
			h.Origins = plugin.OriginsFromArgsOrServerBlock(args, c.ServerBlockKeys)
		}

		for c.NextBlock() {
			switch c.Val() {
			case "url":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				sources = appendUniqueSource(sources, seenSources, FilterSource{URL: c.Val()})

			case "file":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				f := c.Val()
				if !filepath.IsAbs(f) && config.Root != "" {
					f = filepath.Join(config.Root, f)
				}
				sources = appendUniqueSource(sources, seenSources, FilterSource{File: f})

			case "whitelist_url":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				allowSources = appendUniqueSource(allowSources, seenAllowSources, FilterSource{URL: c.Val()})

			case "whitelist_file":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				f := c.Val()
				if !filepath.IsAbs(f) && config.Root != "" {
					f = filepath.Join(config.Root, f)
				}
				allowSources = appendUniqueSource(allowSources, seenAllowSources, FilterSource{File: f})

			case "allowlist":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				for _, rule := range append([]string{c.Val()}, c.RemainingArgs()...) {
					userRules = appendUniqueRule(userRules, seenUserRules, rule)
				}

			case "blocklist":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				for _, rule := range append([]string{c.Val()}, c.RemainingArgs()...) {
					userRules = appendUniqueRule(userRules, seenUserRules, rule)
				}

			case "mode":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				switch c.Val() {
				case "blacklist", "whitelist":
					h.mode = c.Val()
				default:
					return nil, c.Errf("invalid mode %q, must be 'blacklist' or 'whitelist'", c.Val())
				}

			case "refresh":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				dur, err := time.ParseDuration(c.Val())
				if err != nil {
					return nil, c.Errf("invalid duration for refresh: %q", c.Val())
				}
				if dur < 0 {
					return nil, c.Errf("refresh duration cannot be negative: %q", c.Val())
				}
				refreshInterval = dur

			case "block_type":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				switch c.Val() {
				case "nxdomain", "empty", "0.0.0.0":
					h.blockType = c.Val()
				default:
					return nil, c.Errf("invalid block_type %q, must be '0.0.0.0', 'nxdomain' or 'empty'", c.Val())
				}

			case "cache_dir":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				d := c.Val()
				if !filepath.IsAbs(d) && config.Root != "" {
					d = filepath.Join(config.Root, d)
				}
				cacheDir = d

			case "safesearch":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				switch c.Val() {
				case "on", "true":
					h.safeSearch = NewSafeSearch(true)
				case "off", "false":
					h.safeSearch = NewSafeSearch(false)
				default:
					return nil, c.Errf("invalid safesearch value %q, must be 'on' or 'off'", c.Val())
				}

			case "parental":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				switch c.Val() {
				case "on", "true":
					// Add parental control filter URLs (gambling + NSFW)
					sources = appendUniqueSource(sources, seenSources, FilterSource{
						URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.medium.txt",
					}) // Gambling
					sources = appendUniqueSource(sources, seenSources, FilterSource{
						URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt",
					}) // Malware / Phishing / Scam
					sources = appendUniqueSource(sources, seenSources, FilterSource{
						URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt",
					}) // NSFW / Adult
				case "off", "false":
					// do nothing
				default:
					return nil, c.Errf("invalid parental value %q, must be 'on' or 'off'", c.Val())
				}

			case "bypass_ip":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				for _, arg := range append([]string{c.Val()}, c.RemainingArgs()...) {
					_, cidr, err := net.ParseCIDR(arg)
					if err != nil {
						// Try as plain IP (convert to /32 or /128)
						ip := net.ParseIP(arg)
						if ip == nil {
							return nil, c.Errf("invalid IP or CIDR %q", arg)
						}
						if ip.To4() != nil {
							_, cidr, _ = net.ParseCIDR(ip.String() + "/32")
						} else {
							_, cidr, _ = net.ParseCIDR(ip.String() + "/128")
						}
					}
					h.bypassIPs = append(h.bypassIPs, *cidr)
				}

			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	if len(sources) == 0 && len(allowSources) == 0 && len(userRules) == 0 {
		return nil, c.Err("hostlist requires at least one url, file, allowlist, or blocklist directive")
	}

	// Default cache directory: hostlist/ under coredns working directory
	if cacheDir == "" {
		cacheDir = "hostlist"
		if config.Root != "" {
			cacheDir = filepath.Join(config.Root, "hostlist")
		}
	}

	h.loader = NewLoader(sources, allowSources, userRules, refreshInterval, cacheDir)
	return h, nil
}

func appendUniqueSource(sources []FilterSource, seen map[string]struct{}, source FilterSource) []FilterSource {
	key := source.URL
	if key == "" {
		key = "file:" + source.File
	} else {
		key = "url:" + key
	}
	if _, ok := seen[key]; ok {
		return sources
	}
	seen[key] = struct{}{}
	return append(sources, source)
}

func appendUniqueRule(rules []string, seen map[string]struct{}, rule string) []string {
	if rule == "" {
		return rules
	}
	if _, ok := seen[rule]; ok {
		return rules
	}
	seen[rule] = struct{}{}
	return append(rules, rule)
}
