package hostlist

import (
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Interner deduplicates strings to reduce memory usage.
// Safe for concurrent use.
type Interner struct {
	mu   sync.RWMutex
	pool map[string]string
}

func NewInterner() *Interner {
	return &Interner{pool: make(map[string]string)}
}

// Intern returns a canonical copy of s, reusing previously interned strings.
// This ensures identical label strings (e.g., "com", "org") share the same
// memory across the entire trie structure.
func (in *Interner) Intern(s string) string {
	if s == "" {
		return s
	}
	in.mu.RLock()
	if cached, ok := in.pool[s]; ok {
		in.mu.RUnlock()
		return cached
	}
	in.mu.RUnlock()
	in.mu.Lock()
	if cached, ok := in.pool[s]; ok {
		in.mu.Unlock()
		return cached
	}
	in.pool[s] = s
	in.mu.Unlock()
	return s
}

// package-level string interners shared across all tries for maximum deduplication
var labelInterner = NewInterner()

type trieNode struct {
	children []trieChild // nil until first child added; slices are smaller than maps for typical DNS fanout
	blocked  bool        // set by Insert: blocks this node AND all descendants
	exact    bool        // set by InsertExact: blocks ONLY this exact domain
}

type trieChild struct {
	label string
	node  *trieNode
}

// Trie is a reversed-label trie for efficient DNS domain matching.
// For "sub.example.com.", the walk is com -> example -> sub.
//
// Memory optimizations:
//   - String interning: identical label strings share memory via Interner
//   - Compact child slices: leaf nodes have nil children (no wasted memory)
type Trie struct {
	root   *trieNode
	length int
}

func NewTrie() *Trie {
	return &Trie{root: &trieNode{}}
}

// labels returns the reversed, lowercased labels of a normalized FQDN.
// "sub.example.com." -> ["com", "example", "sub"]
func labels(domain string) []string {
	fqdn := strings.ToLower(dns.Fqdn(domain))
	fqdn = strings.TrimSuffix(fqdn, ".")
	if fqdn == "" {
		return nil
	}
	parts := strings.Split(fqdn, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

// getOrCreateChild returns the child node for label, creating it if needed.
// The label is interned for memory deduplication.
func (t *Trie) getOrCreateChild(node *trieNode, label string) *trieNode {
	interned := labelInterner.Intern(label)
	for i := range node.children {
		if node.children[i].label == interned {
			return node.children[i].node
		}
	}
	child := &trieNode{}
	node.children = append(node.children, trieChild{label: interned, node: child})
	return child
}

// Insert adds a domain with ancestor matching.
// Blocking "example.com." also blocks "foo.bar.example.com."
// because the "example" node is marked blocked, and Lookup
// checks blocked at every ancestor.
func (t *Trie) Insert(domain string) {
	parts := labels(domain)
	if len(parts) == 0 {
		return
	}
	node := t.root
	for _, label := range parts {
		node = t.getOrCreateChild(node, label)
	}
	if !node.blocked {
		node.blocked = true
		t.length++
	}
}

// InsertExact adds a domain with exact-only matching.
// Blocking "360in.com." does NOT block "test.360in.com."
// even if other subdomains like "ad.360in.com" exist.
func (t *Trie) InsertExact(domain string) {
	parts := labels(domain)
	if len(parts) == 0 {
		return
	}
	node := t.root
	for _, label := range parts {
		node = t.getOrCreateChild(node, label)
	}
	if !node.exact {
		node.exact = true
		t.length++
	}
}

// Lookup checks if a domain is matched.
//
// For "blocked" (Insert) ancestors: if ANY ancestor node has blocked=true,
// the domain is blocked. This implements wildcard-style blocking:
// "||example.com^" blocks all subdomains.
//
// For "exact" (InsertExact): only the terminal node's exact flag is checked.
// Intermediate ancestors with exact=true are NOT matched.
func (t *Trie) Lookup(domain string) bool {
	parts := labels(domain)
	if len(parts) == 0 {
		return false
	}
	node := t.root
	for _, label := range parts {
		if node.blocked {
			return true // ancestor match (Insert wildcard)
		}
		if len(node.children) == 0 {
			return false
		}
		child := node.child(label)
		if child == nil {
			return false
		}
		node = child
	}
	// Terminal node: check both blocked and exact
	return node.blocked || node.exact
}

func (n *trieNode) child(label string) *trieNode {
	for i := range n.children {
		if n.children[i].label == label {
			return n.children[i].node
		}
	}
	return nil
}

// Len returns the number of entries in the trie.
func (t *Trie) Len() int {
	return t.length
}

// Clear resets the trie.
func (t *Trie) Clear() {
	t.root = &trieNode{}
	t.length = 0
}
