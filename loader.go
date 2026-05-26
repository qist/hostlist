package hostlist

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// FilterSource represents a single rule source (URL or file).
type FilterSource struct {
	URL  string
	File string
}

// cacheMeta stores metadata for a cached URL, used for conditional downloads
// and content change detection.
type cacheMeta struct {
	ContentModified string `json:"content_modified,omitempty"` // raw "! Last modified:" from file content
	ContentVersion  string `json:"content_version,omitempty"`  // raw "! Version:" from file content
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
		client: &http.Client{
			Timeout: 30 * time.Second, // Reduced timeout for faster failure
			Transport: &http.Transport{
				MaxIdleConns:          10,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		},
		interval: interval,
		cacheDir: cacheDir,
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

// metaPath returns the metadata file path for a given cache file.
func (l *Loader) metaPath(cachePath string) string {
	return cachePath + ".meta"
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

// saveMeta saves cache metadata to a file.
func (l *Loader) saveMeta(cachePath string, meta cacheMeta) {
	path := l.metaPath(cachePath)
	if path == "" {
		return
	}
	data, err := json.Marshal(meta)
	if err != nil {
		log.Warningf("Failed to marshal meta for %s: %v", cachePath, err)
		return
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Warningf("Failed to save meta %s: %v", path, err)
	}
}

// loadMeta reads cache metadata from a file. Returns empty meta if not found.
func (l *Loader) loadMeta(cachePath string) cacheMeta {
	path := l.metaPath(cachePath)
	if path == "" {
		return cacheMeta{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cacheMeta{}
	}
	var meta cacheMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return cacheMeta{}
	}
	return meta
}

// parseLastModifiedFromContent extracts a timestamp from AdGuard filter list
// content for use as If-Modified-Since. Returns empty string if not found.
//
// Supported formats in file content:
//
//	! Last modified: 2026-04-17T10:06:25.395Z       (ISO 8601)
//	! Last modified: 12 May 2026 21:31 UTC           (day month year HH:MM TZ)
//	! Last modified: 12 May 2026 21:31:40 UTC         (day month year HH:MM:SS TZ)
//	! Version: 2026.0512.2131.40                      (version-based)
//
// The returned value is in HTTP RFC 1123 format for use with If-Modified-Since.
func parseLastModifiedFromBytes(content []byte) string {
	var rawDate string
	forEachTrimmedLine(content, func(line []byte) bool {
		if bytes.HasPrefix(line, []byte("! Last modified:")) {
			rawDate = string(bytes.TrimSpace(line[len("! Last modified:"):]))
			return false
		}
		return true
	})
	if rawDate == "" {
		return ""
	}

	// Try multiple date formats
	var t time.Time
	formats := []string{
		time.RFC1123,                  // "Tue, 12 May 2026 21:31:00 GMT"
		"2006-01-02T15:04:05.999Z",    // "2026-04-17T10:06:25.395Z"
		"2006-01-02T15:04:05Z",        // "2026-04-17T10:06:25Z"
		"2 January 2006 15:04 MST",    // "12 May 2026 21:31 UTC"
		"2 January 2006 15:04:05 MST", // "12 May 2026 21:31:40 UTC"
		"2 Jan 2006 15:04 MST",        // "12 May 2026 21:31 UTC" (short month)
		"2 Jan 2006 15:04:05 MST",     // "12 May 2026 21:31:40 UTC" (short month)
		"2006-01-02 15:04:05",         // "2026-04-17 10:06:25"
		"2006-01-02",                  // "2026-04-17"
	}
	for _, f := range formats {
		var err error
		t, err = time.Parse(f, rawDate)
		if err == nil {
			return t.Format(time.RFC1123)
		}
	}

	return ""
}

// LoadAll loads rules from all sources and user rules, merging results.
// For URL sources: try remote download first with conditional request,
// fall back to local cache on failure or 304 Not Modified.
// For file sources: read directly from disk.
// For allowlist sources: all rules (including ||domain^) are treated as allowlist entries.
func (l *Loader) LoadAll() ParseResult {
	return l.loadAllWithContext(context.Background())
}

// loadAllWithContext loads rules with context for timeout control
func (l *Loader) loadAllWithContext(ctx context.Context) ParseResult {
	l.ensureCacheDir()
	acc := newResultAccumulator()

	for _, src := range l.sources {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			log.Warningf("LoadAll cancelled, returning partial result")
			return acc.result
		default:
		}

		result, err := l.loadSource(src)
		if err != nil {
			log.Warningf("Failed to load rules from %s: %v", sourceName(src), err)
			continue
		}
		acc.addAll(result)
	}

	for _, src := range l.allowSources {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			log.Warningf("LoadAll cancelled, returning partial result")
			return acc.result
		default:
		}

		result, err := l.loadSource(src)
		if err != nil {
			log.Warningf("Failed to load allowlist from %s: %v", sourceName(src), err)
			continue
		}
		acc.addAllowOnly(result)
	}

	if len(l.userRules) > 0 {
		userResult := ParseRules(multiLineReader(l.userRules))
		acc.addAll(userResult)
	}

	// log.Infof("LoadAll completed: SkipUpdate=%v, Blocked=%d, Exact=%d, Allowlist=%d",
	// acc.result.SkipUpdate, len(acc.result.Blocked), len(acc.result.BlockedExact), len(acc.result.Allowlist))
	return acc.result
}

// LoadFromCache loads rules from local cache only (no network requests).
// Used for fast startup before background refresh completes.
func (l *Loader) LoadFromCache() ParseResult {
	l.ensureCacheDir()
	acc := newResultAccumulator()

	for _, src := range l.sources {
		result, err := l.loadFromCacheOnly(src)
		if err != nil {
			log.Debugf("No cached rules for %s: %v", sourceName(src), err)
			continue
		}
		acc.addAll(result)
	}

	for _, src := range l.allowSources {
		result, err := l.loadFromCacheOnly(src)
		if err != nil {
			log.Debugf("No cached allowlist for %s: %v", sourceName(src), err)
			continue
		}
		acc.addAllowOnly(result)
	}

	if len(l.userRules) > 0 {
		userResult := ParseRules(multiLineReader(l.userRules))
		acc.addAll(userResult)
	}

	return acc.result
}

// loadSource loads rules from a single source. For URLs, tries remote with
// conditional request, then falls back to cache.
func (l *Loader) loadSource(src FilterSource) (ParseResult, error) {
	if src.URL != "" {
		return l.loadFromURL(src.URL)
	}
	if src.File != "" {
		return l.loadFromFile(src.File)
	}
	return ParseResult{}, fmt.Errorf("source has neither url nor file")
}

// loadFromCacheOnly loads rules from local cache only (no network).
func (l *Loader) loadFromCacheOnly(src FilterSource) (ParseResult, error) {
	if src.URL != "" {
		cachePath := l.cachePath(src.URL)
		cached := l.loadCache(cachePath)
		if cached == nil {
			return ParseResult{}, fmt.Errorf("no cache for %s", src.URL)
		}
		return ParseRules(bytes.NewReader(cached)), nil
	}
	if src.File != "" {
		return l.loadFromFile(src.File)
	}
	return ParseResult{}, fmt.Errorf("source has neither url nor file")
}

// loadFromURL downloads rules from a URL with conditional request support.
// Uses ! Last modified: from file content as If-Modified-Since.
// On 304 Not Modified or content unchanged: returns cached result (no rebuild needed).
// On network failure: falls back to local cache.
func (l *Loader) loadFromURL(url string) (ParseResult, error) {
	cachePath := l.cachePath(url)

	cached := l.loadCache(cachePath)
	meta := l.loadMeta(cachePath)

	// Build If-Modified-Since from cached content's ! Last modified:
	ifModifiedSince := ""
	if meta.ContentModified != "" {
		ifModifiedSince = meta.ContentModified
	} else if cached != nil {
		ifModifiedSince = parseLastModifiedFromBytes(cached)
	}

	data, statusCode, _, err := l.fetchURL(url, ifModifiedSince, "")
	if err == nil && statusCode == http.StatusNotModified {
		log.Debugf("Remote %s not modified (304), using cache", url)
		if cached != nil {
			result := ParseRules(bytes.NewReader(cached))
			result.SkipUpdate = true
			return result, nil
		}
	}
	if err == nil && statusCode == http.StatusOK {
		newModified := extractLastModifiedBytes(data)
		newVersion := extractVersionBytes(data)

		// Compare content identifiers: if same, skip trie rebuild
		if cached != nil {
			cachedModified := extractLastModifiedBytes(cached)
			cachedVersion := extractVersionBytes(cached)
			if newModified != "" && newModified == cachedModified &&
				newVersion == cachedVersion {
				log.Debugf("Content %s unchanged (%s), skipping rebuild", url, newModified)
				l.saveCache(cachePath, data)
				result := ParseRules(bytes.NewReader(cached))
				result.SkipUpdate = true
				return result, nil
			}
		}

		// Content changed: save cache + meta, parse and return
		l.saveCache(cachePath, data)
		l.saveMeta(cachePath, cacheMeta{
			ContentModified: newModified,
			ContentVersion:  newVersion,
		})
		return ParseRules(bytes.NewReader(data)), nil
	}

	// Remote failed, try cache
	if cached != nil {
		log.Warningf("Failed to download %s: %v, using cache", url, err)
		return ParseRules(bytes.NewReader(cached)), nil
	}

	return ParseResult{}, fmt.Errorf("download failed and no cache available: %w", err)
}

// extractLastModifiedBytes returns the raw ! Last modified: value from content.
func extractLastModifiedBytes(content []byte) string {
	var value string
	forEachTrimmedLine(content, func(line []byte) bool {
		if bytes.HasPrefix(line, []byte("! Last modified:")) {
			value = string(bytes.TrimSpace(line[len("! Last modified:"):]))
			return false
		}
		return true
	})
	if value != "" {
		return value
	}
	return ""
}

// extractVersionBytes returns the raw ! Version: value from content.
func extractVersionBytes(content []byte) string {
	var value string
	forEachTrimmedLine(content, func(line []byte) bool {
		if bytes.HasPrefix(line, []byte("! Version:")) {
			value = string(bytes.TrimSpace(line[len("! Version:"):]))
			return false
		}
		return true
	})
	if value != "" {
		return value
	}
	return ""
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

// fetchURL performs an HTTP GET with optional conditional headers.
// Returns the body bytes, status code, response headers, and any error.
// For 304 Not Modified, the body will be nil with no error.
func (l *Loader) fetchURL(url, ifModifiedSince, ifNoneMatch string) ([]byte, int, http.Header, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	if ifModifiedSince != "" {
		req.Header.Set("If-Modified-Since", ifModifiedSince)
	}
	if ifNoneMatch != "" {
		req.Header.Set("If-None-Match", ifNoneMatch)
	}

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, resp.StatusCode, resp.Header, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, resp.Header, &httpError{URL: url, StatusCode: resp.StatusCode}
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, resp.Header, err
	}
	return data, resp.StatusCode, resp.Header, nil
}

// StartPeriodicRefresh starts a goroutine that periodically reloads rules.
// Returns a stop channel that should be closed on shutdown.
// Uses conditional HTTP requests to skip downloads when content hasn't changed.
func (l *Loader) StartPeriodicRefresh(onUpdate func()) chan struct{} {
	stop := make(chan struct{})
	if l.interval <= 0 {
		return stop
	}
	go func() {
		ticker := time.NewTicker(l.interval)
		defer ticker.Stop()
		var reloading int32
		for {
			select {
			case <-ticker.C:
				if !atomic.CompareAndSwapInt32(&reloading, 0, 1) {
					log.Warningf("Skipping reload: previous refresh still running")
					continue
				}
				go func() {
					defer atomic.StoreInt32(&reloading, 0)
					onUpdate()
				}()
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

type resultAccumulator struct {
	result         ParseResult
	seenBlocked    map[string]struct{}
	seenExact      map[string]struct{}
	seenAllow      map[string]struct{}
	seenRegexBlock map[string]struct{}
	seenRegexAllow map[string]struct{}
}

func newResultAccumulator() *resultAccumulator {
	return &resultAccumulator{
		result: ParseResult{
			SkipUpdate: false,
		},
		seenBlocked:    make(map[string]struct{}),
		seenExact:      make(map[string]struct{}),
		seenAllow:      make(map[string]struct{}),
		seenRegexBlock: make(map[string]struct{}),
		seenRegexAllow: make(map[string]struct{}),
	}
}

func (a *resultAccumulator) addAll(src ParseResult) {
	a.addBlocked(src.Blocked)
	a.addExact(src.BlockedExact, src.IPMap)
	a.addAllow(src.Allowlist)
	a.addRegexBlock(src.RegexBlock)
	a.addRegexAllow(src.RegexAllow)
	a.result.SkipUpdate = a.result.SkipUpdate && src.SkipUpdate
}

func (a *resultAccumulator) addAllowOnly(src ParseResult) {
	a.addAllow(src.Allowlist)
	a.addRegexAllow(src.RegexAllow)
}

func (a *resultAccumulator) addBlocked(values []string) {
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := a.seenBlocked[value]; ok {
			continue
		}
		a.seenBlocked[value] = struct{}{}
		a.result.Blocked = append(a.result.Blocked, value)
	}
}

func (a *resultAccumulator) addExact(values []string, ipMap map[string]string) {
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := a.seenExact[value]; !ok {
			a.seenExact[value] = struct{}{}
			a.result.BlockedExact = append(a.result.BlockedExact, value)
		}
		if ipMap != nil {
			if ip, ok := ipMap[value]; ok {
				if a.result.IPMap == nil {
					a.result.IPMap = make(map[string]string)
				}
				a.result.IPMap[value] = ip
			}
		}
	}
}

func (a *resultAccumulator) addAllow(values []string) {
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := a.seenAllow[value]; ok {
			continue
		}
		a.seenAllow[value] = struct{}{}
		a.result.Allowlist = append(a.result.Allowlist, value)
	}
}

func (a *resultAccumulator) addRegexBlock(values []string) {
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := a.seenRegexBlock[value]; ok {
			continue
		}
		a.seenRegexBlock[value] = struct{}{}
		a.result.RegexBlock = append(a.result.RegexBlock, value)
	}
}

func (a *resultAccumulator) addRegexAllow(values []string) {
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := a.seenRegexAllow[value]; ok {
			continue
		}
		a.seenRegexAllow[value] = struct{}{}
		a.result.RegexAllow = append(a.result.RegexAllow, value)
	}
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
	return &sliceLineReader{lines: lines}
}

func forEachTrimmedLine(content []byte, fn func([]byte) bool) {
	start := 0
	for start <= len(content) {
		end := bytes.IndexByte(content[start:], '\n')
		if end == -1 {
			line := bytes.TrimSpace(content[start:])
			if len(line) > 0 && !fn(line) {
				return
			}
			return
		}

		line := bytes.TrimSpace(content[start : start+end])
		if len(line) > 0 && !fn(line) {
			return
		}
		start += end + 1
	}
}

type sliceLineReader struct {
	lines       []string
	lineIdx     int
	byteIdx     int
	emitNewline bool
}

func (r *sliceLineReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	n := 0
	for n < len(p) {
		if r.lineIdx >= len(r.lines) {
			if n == 0 {
				return 0, io.EOF
			}
			return n, nil
		}

		if r.emitNewline {
			p[n] = '\n'
			n++
			r.emitNewline = false
			r.lineIdx++
			r.byteIdx = 0
			continue
		}

		line := r.lines[r.lineIdx]
		if r.byteIdx >= len(line) {
			r.emitNewline = true
			continue
		}

		copied := copy(p[n:], line[r.byteIdx:])
		n += copied
		r.byteIdx += copied
	}

	return n, nil
}
