package hostlist

import (
	"strings"

	"github.com/miekg/dns"
)

type trieNode struct {
	children map[string]*trieNode
	blocked  bool // set by Insert: blocks this node AND all descendants
	exact    bool // set by InsertExact: blocks ONLY this exact domain
}

// Trie is a reversed-label trie for efficient DNS domain matching.
// For "sub.example.com.", the walk is com -> example -> sub.
type Trie struct {
	root   *trieNode
	length int
}

func NewTrie() *Trie {
	return &Trie{root: &trieNode{children: make(map[string]*trieNode)}}
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
		child, ok := node.children[label]
		if !ok {
			child = &trieNode{children: make(map[string]*trieNode)}
			node.children[label] = child
		}
		node = child
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
		child, ok := node.children[label]
		if !ok {
			child = &trieNode{children: make(map[string]*trieNode)}
			node.children[label] = child
		}
		node = child
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
		child, ok := node.children[label]
		if !ok {
			return false
		}
		node = child
	}
	// Terminal node: check both blocked and exact
	return node.blocked || node.exact
}

// Len returns the number of entries in the trie.
func (t *Trie) Len() int {
	return t.length
}

// Clear resets the trie.
func (t *Trie) Clear() {
	t.root = &trieNode{children: make(map[string]*trieNode)}
	t.length = 0
}
