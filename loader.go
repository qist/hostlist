package hostlist

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FilterSource represents a single rule source (URL or file).
type FilterSource struct {
	URL  string
	File string
}

// Loader manages loading rules from multiple sources and periodic refresh.
type Loader struct {
	sources      []FilterSource // blacklist filter sources
	allowSources []FilterSource // whitelist filter sources (all rules treated as allowlist)
	userRules    []string       // raw user rule lines
	client       *http.Client
	interval     time.Duration
	cacheDir     string // directory to cache downloaded rules
}

// NewLoader creates a new Loader. cacheDir is the directory to store downloaded rules.
func NewLoader(sources, allowSources []FilterSource, userRules []string, interval time.Duration, cacheDir string) *Loader {
	return &Loader{
		sources:      sources,
		allowSources: allowSources,
		userRules:    userRules,
		client:       &http.Client{Timeout: 60 * time.Second},
		interval:     interval,
		cacheDir:     cacheDir,
	}
}

// ensureCacheDir creates the cache directory if it doesn't exist.
func (l *Loader) ensureCacheDir() {
	if l.cacheDir == "" {
		return
	}
	if err := os.MkdirAll(l.cacheDir, 0755); err != nil {
		log.Warningf("Failed to create cache directory %s: %v", l.cacheDir, err)
	}
}

// cachePath returns the cache file path for a given URL.
func (l *Loader) cachePath(url string) string {
	if l.cacheDir == "" {
		return ""
	}
	h := sha256.Sum256([]byte(url))
	return filepath.Join(l.cacheDir, fmt.Sprintf("%x.txt", h[:8]))
}

// saveCache saves content to a cache file. Errors are silently ignored.
func (l *Loader) saveCache(path string, data []byte) {
	if path == "" {
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Warningf("Failed to save cache %s: %v", path, err)
	}
}

// loadCache reads content from a cache file. Returns nil if not found or error.
func (l *Loader) loadCache(path string) []byte {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return data
}

// LoadAll loads rules from all sources and user rules, merging results.
// For URL sources: try remote download first, fall back to local cache.
// For file sources: read directly from disk.
// For allowlist sources: all rules (including ||domain^) are treated as allowlist entries.
// All errors are gracefully handled - never panics or crashes.
func (l *Loader) LoadAll() ParseResult {
	l.ensureCacheDir()
	var merged ParseResult

	// Load blacklist sources
	for _, src := range l.sources {
		result, err := l.loadSource(src)
		if err != nil {
			log.Warningf("Failed to load rules from %s: %v", sourceName(src), err)
			continue
		}
		mergeResult(&merged, result)
	}

	// Load whitelist sources — all rules go to allowlist
	for _, src := range l.allowSources {
		result, err := l.loadSource(src)
		if err != nil {
			log.Warningf("Failed to load allowlist from %s: %v", sourceName(src), err)
			continue
		}
		// Force all rules into allowlist regardless of @@ prefix
		merged.Allowlist = append(merged.Allowlist, result.Blocked...)
		merged.Allowlist = append(merged.Allowlist, result.Allowlist...)
		merged.RegexAllow = append(merged.RegexAllow, result.RegexBlock...)
		merged.RegexAllow = append(merged.RegexAllow, result.RegexAllow...)
	}

	// Parse user rules
	if len(l.userRules) > 0 {
		userResult := ParseRules(multiLineReader(l.userRules))
		mergeResult(&merged, userResult)
	}

	return merged
}

// loadSource loads rules from a single source. For URLs, tries remote then cache.
func (l *Loader) loadSource(src FilterSource) (ParseResult, error) {
	if src.URL != "" {
		return l.loadFromURL(src.URL)
	}
	if src.File != "" {
		return l.loadFromFile(src.File)
	}
	return ParseResult{}, fmt.Errorf("source has neither url nor file")
}

// loadFromURL downloads rules from a URL. On failure, falls back to local cache.
func (l *Loader) loadFromURL(url string) (ParseResult, error) {
	cachePath := l.cachePath(url)

	// Try remote download
	data, err := l.fetchURL(url)
	if err == nil {
		// Save to cache
		l.saveCache(cachePath, data)
		result := ParseRules(strings.NewReader(string(data)))
		return result, nil
	}

	// Remote failed, try cache
	log.Warningf("Failed to download %s: %v, trying cache", url, err)
	cached := l.loadCache(cachePath)
	if cached != nil {
		log.Infof("Loaded rules from cache: %s", cachePath)
		result := ParseRules(strings.NewReader(string(cached)))
		return result, nil
	}

	return ParseResult{}, fmt.Errorf("download failed and no cache available: %w", err)
}

// loadFromFile reads rules from a local file.
func (l *Loader) loadFromFile(path string) (ParseResult, error) {
	r, err := os.Open(path)
	if err != nil {
		return ParseResult{}, err
	}
	defer r.Close()
	return ParseRules(r), nil
}

// fetchURL performs an HTTP GET and returns the response body as bytes.
func (l *Loader) fetchURL(url string) ([]byte, error) {
	resp, err := l.client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpError{URL: url, StatusCode: resp.StatusCode}
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// StartPeriodicRefresh starts a goroutine that periodically reloads rules.
// Returns a stop channel that should be closed on shutdown.
func (l *Loader) StartPeriodicRefresh(onUpdate func()) chan struct{} {
	stop := make(chan struct{})
	if l.interval <= 0 {
		return stop
	}
	go func() {
		ticker := time.NewTicker(l.interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				onUpdate()
			case <-stop:
				return
			}
		}
	}()
	return stop
}

func sourceName(src FilterSource) string {
	if src.URL != "" {
		return src.URL
	}
	return src.File
}

func mergeResult(dst *ParseResult, src ParseResult) {
	dst.Blocked = append(dst.Blocked, src.Blocked...)
	dst.BlockedExact = append(dst.BlockedExact, src.BlockedExact...)
	dst.Allowlist = append(dst.Allowlist, src.Allowlist...)
	dst.RegexBlock = append(dst.RegexBlock, src.RegexBlock...)
	dst.RegexAllow = append(dst.RegexAllow, src.RegexAllow...)
}

type httpError struct {
	URL        string
	StatusCode int
}

func (e *httpError) Error() string {
	return "HTTP " + http.StatusText(e.StatusCode) + " from " + e.URL
}

// multiLineReader creates an io.Reader from a slice of lines.
func multiLineReader(lines []string) io.Reader {
	s := ""
	for _, l := range lines {
		s += l + "\n"
	}
	return strings.NewReader(s)
}
