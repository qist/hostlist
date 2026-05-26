package hostlist

import (
	"context"
	"net"
	"path/filepath"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

var log = clog.NewWithPlugin(pluginName)

var defaultParentalSources = []FilterSource{
	{URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/gambling.medium.txt"},
	{URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.medium.txt"},
	{URL: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt"},
}

type parseState struct {
	sources             []FilterSource
	allowSources        []FilterSource
	userRules           []string
	seenSources         map[string]struct{}
	seenAllowSources    map[string]struct{}
	seenUserRules       map[string]struct{}
	cacheDir            string
	refreshInterval     time.Duration
	parentalSources     []FilterSource
	seenParentalSources map[string]struct{}
	parentalConfigured  bool
	parentalExplicit    bool
	inParentalBlock     bool
	expectParentalBlock bool
}

func init() { plugin.Register(pluginName, setup) }

func setup(c *caddy.Controller) error {
	h, err := parse(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}

	// Initialize with empty rule set immediately during parsing
	// This ensures DNS queries work even before startup completes
	h.rules.Store(emptyRuleSet())

	ctx, cancel := context.WithCancel(context.Background())

	c.OnStartup(func() error {
		h.stopped.Store(false)

		// Start async refresh immediately (no cache trie to avoid double memory)
		go func() {
			result := h.loadAllWithContext(ctx)
			if ctx.Err() != nil || h.stopped.Load() {
				return
			}
			h.Update(result)
		}()

		return nil
	})

	var stopChans []chan struct{}
	startRefresh := func(loader *Loader) {
		if loader == nil {
			return
		}
		stopChans = append(stopChans, loader.StartPeriodicRefresh(func() {
			if ctx.Err() != nil || h.stopped.Load() {
				return
			}
			result := h.loadAllWithContext(ctx)
			if ctx.Err() != nil || h.stopped.Load() {
				return
			}
			h.Update(result)
		}))
	}
	startRefresh(h.loader)
	startRefresh(h.parentalLoader)
	if h.parentalLoader == nil {
		startRefresh(h.parentalFallbackLoader)
	}

	c.OnShutdown(func() error {
		cancel()
		for _, stopChan := range stopChans {
			close(stopChan)
		}
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
		Origins:   plugin.OriginsFromArgsOrServerBlock(nil, c.ServerBlockKeys),
		mode:      "blacklist",
		blockType: "0.0.0.0",
	}

	state := parseState{
		seenSources:         make(map[string]struct{}),
		seenAllowSources:    make(map[string]struct{}),
		seenUserRules:       make(map[string]struct{}),
		refreshInterval:     4 * 24 * time.Hour,
		seenParentalSources: make(map[string]struct{}),
	}

	config := dnsserver.GetConfig(c)

	for c.Next() {
		if c.Val() != pluginName {
			if err := applyDirective(c, c.Val(), c.RemainingArgs(), config.Root, h, &state); err != nil {
				return nil, err
			}
			continue
		}

		args := c.RemainingArgs()
		if len(args) > 0 {
			h.Origins = plugin.OriginsFromArgsOrServerBlock(args, c.ServerBlockKeys)
		}

		for c.NextBlock() {
			if err := applyDirective(c, c.Val(), c.RemainingArgs(), config.Root, h, &state); err != nil {
				return nil, err
			}
		}
		state.inParentalBlock = false
		state.expectParentalBlock = false
	}

	if state.parentalConfigured && !state.parentalExplicit {
		h.parentalEnabled = true
	}

	if len(state.sources) == 0 && len(state.allowSources) == 0 && len(state.userRules) == 0 && !h.parentalEnabled {
		return nil, c.Err("hostlist requires at least one url, file, allowlist, or blocklist directive")
	}

	// Default cache directory: hostlist/ under coredns working directory
	if state.cacheDir == "" {
		state.cacheDir = "hostlist"
		if config.Root != "" {
			state.cacheDir = filepath.Join(config.Root, "hostlist")
		}
	}

	if len(state.sources) > 0 || len(state.allowSources) > 0 || len(state.userRules) > 0 {
		h.loader = NewLoader(state.sources, state.allowSources, state.userRules, state.refreshInterval, state.cacheDir)
	}
	if h.parentalEnabled {
		parentalCacheDir := filepath.Join(state.cacheDir, "parental")
		if len(state.parentalSources) > 0 {
			h.parentalLoader = NewLoader(state.parentalSources, nil, nil, state.refreshInterval, parentalCacheDir)
		}
		h.parentalFallbackLoader = NewLoader(cloneSources(defaultParentalSources), nil, nil, state.refreshInterval, parentalCacheDir)
	}
	return h, nil
}

func applyDirective(c *caddy.Controller, name string, args []string, root string, h *Hostlist, state *parseState) error {
	if name == "" || name == "}" {
		state.inParentalBlock = false
		state.expectParentalBlock = false
		return nil
	}

	targetParental := state.inParentalBlock

	if name == "{" {
		if !state.expectParentalBlock {
			return c.Errf("unknown property %q", name)
		}
		state.inParentalBlock = true
		state.expectParentalBlock = false
		return nil
	}
	state.expectParentalBlock = false

	appendSource := func(source FilterSource) {
		if targetParental {
			state.parentalConfigured = true
			state.parentalSources = appendUniqueSource(state.parentalSources, state.seenParentalSources, source)
			return
		}
		state.sources = appendUniqueSource(state.sources, state.seenSources, source)
	}
	switch name {
	case "url":
		if len(args) == 0 {
			return c.ArgErr()
		}
		appendSource(FilterSource{URL: args[0]})
	case "file":
		if len(args) == 0 {
			return c.ArgErr()
		}
		f := args[0]
		if !filepath.IsAbs(f) && root != "" {
			f = filepath.Join(root, f)
		}
		appendSource(FilterSource{File: f})
	case "whitelist_url":
		if targetParental {
			return c.Errf("unknown parental property %q", name)
		}
		if len(args) == 0 {
			return c.ArgErr()
		}
		state.allowSources = appendUniqueSource(state.allowSources, state.seenAllowSources, FilterSource{URL: args[0]})
	case "whitelist_file":
		if targetParental {
			return c.Errf("unknown parental property %q", name)
		}
		if len(args) == 0 {
			return c.ArgErr()
		}
		f := args[0]
		if !filepath.IsAbs(f) && root != "" {
			f = filepath.Join(root, f)
		}
		state.allowSources = appendUniqueSource(state.allowSources, state.seenAllowSources, FilterSource{File: f})
	case "allowlist":
		if targetParental {
			return c.Errf("unknown parental property %q", name)
		}
		if len(args) == 0 {
			return c.ArgErr()
		}
		for _, rule := range args {
			state.userRules = appendUniqueRule(state.userRules, state.seenUserRules, rule)
		}
	case "blocklist":
		if targetParental {
			return c.Errf("unknown parental property %q", name)
		}
		if len(args) == 0 {
			return c.ArgErr()
		}
		for _, rule := range args {
			state.userRules = appendUniqueRule(state.userRules, state.seenUserRules, rule)
		}
	case "mode":
		if targetParental {
			return c.Errf("unknown parental property %q", name)
		}
		if len(args) == 0 {
			return c.ArgErr()
		}
		switch args[0] {
		case "blacklist", "whitelist":
			h.mode = args[0]
		default:
			return c.Errf("invalid mode %q, must be 'blacklist' or 'whitelist'", args[0])
		}
	case "refresh":
		if targetParental {
			return c.Errf("unknown parental property %q", name)
		}
		if len(args) == 0 {
			return c.ArgErr()
		}
		dur, err := time.ParseDuration(args[0])
		if err != nil {
			return c.Errf("invalid duration for refresh: %q", args[0])
		}
		if dur < 0 {
			return c.Errf("refresh duration cannot be negative: %q", args[0])
		}
		state.refreshInterval = dur
	case "block_type":
		if targetParental {
			return c.Errf("unknown parental property %q", name)
		}
		if len(args) == 0 {
			return c.ArgErr()
		}
		switch args[0] {
		case "nxdomain", "empty", "0.0.0.0":
			h.blockType = args[0]
		default:
			return c.Errf("invalid block_type %q, must be '0.0.0.0', 'nxdomain' or 'empty'", args[0])
		}
	case "cache_dir":
		if targetParental {
			return c.Errf("unknown parental property %q", name)
		}
		if len(args) == 0 {
			return c.ArgErr()
		}
		d := args[0]
		if !filepath.IsAbs(d) && root != "" {
			d = filepath.Join(root, d)
		}
		state.cacheDir = d
	case "safesearch":
		if targetParental {
			return c.Errf("unknown parental property %q", name)
		}
		if len(args) == 0 {
			return c.ArgErr()
		}
		switch args[0] {
		case "on", "true":
			h.safeSearch = NewSafeSearch(true)
		case "off", "false":
			h.safeSearch = NewSafeSearch(false)
		default:
			return c.Errf("invalid safesearch value %q, must be 'on' or 'off'", args[0])
		}
	case "parental":
		if targetParental {
			return c.Errf("unknown parental property %q", name)
		}
		if len(args) > 1 {
			return c.ArgErr()
		}
		if len(args) == 1 {
			state.parentalExplicit = true
			switch args[0] {
			case "on", "true":
				h.parentalEnabled = true
			case "off", "false":
				h.parentalEnabled = false
			default:
				return c.Errf("invalid parental value %q, must be 'on' or 'off'", args[0])
			}
			return nil
		}
		state.parentalConfigured = true
		state.expectParentalBlock = true
	case "bypass_ip":
		if targetParental {
			return c.Errf("unknown parental property %q", name)
		}
		if len(args) == 0 {
			return c.ArgErr()
		}
		for _, arg := range args {
			_, cidr, err := net.ParseCIDR(arg)
			if err != nil {
				ip := net.ParseIP(arg)
				if ip == nil {
					return c.Errf("invalid IP or CIDR %q", arg)
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
		if targetParental {
			return c.Errf("unknown parental property %q", name)
		}
		return c.Errf("unknown property %q", name)
	}
	return nil
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

func cloneSources(sources []FilterSource) []FilterSource {
	if len(sources) == 0 {
		return nil
	}
	cloned := make([]FilterSource, len(sources))
	copy(cloned, sources)
	return cloned
}
