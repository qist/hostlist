package hostlist

import (
	"regexp"
	"sync"
)

// RegexCache provides memory-efficient regex compilation and caching.
// It compiles regex patterns lazily and caches them to avoid redundant compilations.
type RegexCache struct {
	mu     sync.RWMutex
	cache  map[string]*regexp.Regexp
	hits   int64
	misses int64
}

// NewRegexCache creates a new regex cache
func NewRegexCache() *RegexCache {
	return &RegexCache{
		cache: make(map[string]*regexp.Regexp),
	}
}

// Compile compiles a regex pattern, using cache if available
func (rc *RegexCache) Compile(pattern string) (*regexp.Regexp, error) {
	// Check cache first
	rc.mu.RLock()
	if re, ok := rc.cache[pattern]; ok {
		rc.hits++
		rc.mu.RUnlock()
		return re, nil
	}
	rc.mu.RUnlock()

	// Compile the regex
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	// Store in cache
	rc.mu.Lock()
	rc.cache[pattern] = re
	rc.misses++
	rc.mu.Unlock()

	return re, nil
}

// MustCompile compiles a regex pattern, panicking on error
func (rc *RegexCache) MustCompile(pattern string) *regexp.Regexp {
	re, err := rc.Compile(pattern)
	if err != nil {
		panic(err)
	}
	return re
}

// GetStats returns cache statistics
func (rc *RegexCache) GetStats() (hits, misses int64, size int) {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return rc.hits, rc.misses, len(rc.cache)
}

// Clear clears the cache
func (rc *RegexCache) Clear() {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.cache = make(map[string]*regexp.Regexp)
	rc.hits = 0
	rc.misses = 0
}

// Len returns the number of cached regexps
func (rc *RegexCache) Len() int {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	return len(rc.cache)
}

// CompileRegexpsOptimized compiles a list of regex patterns with caching
func CompileRegexpsOptimized(patterns []string) []*regexp.Regexp {
	cache := NewRegexCache()
	result := make([]*regexp.Regexp, 0, len(patterns))

	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		re, err := cache.Compile(pattern)
		if err != nil {
			log.Warningf("Failed to compile regex %q: %v", pattern, err)
			continue
		}
		result = append(result, re)
	}

	return result
}
