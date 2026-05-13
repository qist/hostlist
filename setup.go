package hostlist

import (
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

	c.OnStartup(func() error {
		result := h.loader.LoadAll()
		h.Update(result)
		return nil
	})

	stopChan := h.loader.StartPeriodicRefresh(func() {
		result := h.loader.LoadAll()
		h.Update(result)
	})

	c.OnShutdown(func() error {
		close(stopChan)
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
		domainTrie: NewTrie(),
		exactTrie:  NewTrie(),
		allowTrie:  NewTrie(),
	}

	var sources []FilterSource
	var allowSources []FilterSource
	var userRules []string
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
				sources = append(sources, FilterSource{URL: c.Val()})

			case "file":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				f := c.Val()
				if !filepath.IsAbs(f) && config.Root != "" {
					f = filepath.Join(config.Root, f)
				}
				sources = append(sources, FilterSource{File: f})

			case "whitelist_url":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				allowSources = append(allowSources, FilterSource{URL: c.Val()})

			case "whitelist_file":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				f := c.Val()
				if !filepath.IsAbs(f) && config.Root != "" {
					f = filepath.Join(config.Root, f)
				}
				allowSources = append(allowSources, FilterSource{File: f})

			case "allowlist":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				userRules = append(userRules, c.Val())
				userRules = append(userRules, c.RemainingArgs()...)

			case "blocklist":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				userRules = append(userRules, c.Val())
				userRules = append(userRules, c.RemainingArgs()...)

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
