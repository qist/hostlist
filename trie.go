package hostlist

import (
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

// Interner deduplicates strings to reduce memory usage.
type Interner struct {
	mu   sync.RWMutex
	pool map[string]string
}

func NewInterner() *Interner {
	return &Interner{pool: make(map[string]string)}
}

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

var labelInterner = NewInterner()

type childEntry struct {
	label string
	node  *trieNode
}

type trieNode struct {
	children []childEntry // sorted by label; nil for leaf nodes
	blocked  bool
	exact    bool
}

// Trie is a reversed-label compact trie for DNS domain matching.
// "sub.example.com." is stored as root -> "com" -> "example" -> "sub".
//
// Memory optimizations:
//   - Sorted children slice instead of map (no hash table overhead)
//   - Compact trie: single-child non-terminal nodes are merged into parent's label
//   - String interning: identical labels share memory via Interner
type Trie struct {
	root   *trieNode
	length int
}

func NewTrie() *Trie {
	return &Trie{root: &trieNode{}}
}

// labels returns reversed, lowercased labels of a normalized FQDN.
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

// findChild returns the index of the child matching label, or the insertion point.
func (n *trieNode) findChild(label string) (int, bool) {
	i := sort.Search(len(n.children), func(j int) bool {
		return n.children[j].label >= label
	})
	if i < len(n.children) && n.children[i].label == label {
		return i, true
	}
	return i, false
}

// getOrCreateChild finds or creates a child node for the given label.
// The label is interned for memory deduplication.
func (t *Trie) getOrCreateChild(node *trieNode, label string) *trieNode {
	interned := labelInterner.Intern(label)
	i, found := node.findChild(interned)
	if found {
		return node.children[i].node
	}
	child := &trieNode{}
	node.children = append(node.children, childEntry{})
	copy(node.children[i+1:], node.children[i:])
	node.children[i] = childEntry{label: interned, node: child}
	return child
}

// Insert adds a domain with ancestor matching.
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
// the domain is blocked (wildcard-style blocking).
//
// For "exact" (InsertExact): only the terminal node's exact flag is checked.
func (t *Trie) Lookup(domain string) bool {
	parts := labels(domain)
	if len(parts) == 0 {
		return false
	}
	node := t.root
	remaining := parts
	for len(remaining) > 0 {
		if node.blocked {
			return true
		}
		if len(node.children) == 0 {
			return false
		}
		label := remaining[0]
		i := sort.Search(len(node.children), func(j int) bool {
			return node.children[j].label >= label
		})
		if i >= len(node.children) {
			return false
		}
		childLabel := node.children[i].label
		if childLabel == label {
			node = node.children[i].node
			remaining = remaining[1:]
		} else if len(childLabel) > len(label) && childLabel[len(label)] == '.' && childLabel[:len(label)] == label {
			suffix := childLabel[len(label)+1:]
			suffixLabels := strings.Split(suffix, ".")
			if len(suffixLabels) <= len(remaining)-1 {
				match := true
				for j, sl := range suffixLabels {
					if sl != remaining[j+1] {
						match = false
						break
					}
				}
				if match {
					node = node.children[i].node
					remaining = remaining[len(suffixLabels)+1:]
					continue
				}
			}
			return false
		} else {
			return false
		}
	}
	return node.blocked || node.exact
}

// Compact merges single-child non-terminal nodes to reduce memory.
// After compaction, "com" -> "example" -> "sub" becomes "com.example.sub"
// if "example" is not a terminal node and has only one child.
func (t *Trie) Compact() {
	t.compact(t.root)
}

func (t *Trie) compact(node *trieNode) {
	for i := 0; i < len(node.children); i++ {
		child := node.children[i].node
		t.compact(child)
		for len(child.children) == 1 && !child.blocked && !child.exact {
			grandchild := child.children[0]
			merged := node.children[i].label + "." + grandchild.label
			node.children[i] = childEntry{
				label: labelInterner.Intern(merged),
				node:  grandchild.node,
			}
			child = grandchild.node
		}
	}
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