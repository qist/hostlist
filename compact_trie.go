package hostlist

import (
	"sync"
	"sync/atomic"
)

// CompactTrie is a memory-optimized trie using a flat array structure.
// Inspired by AdGuardHome's approach to reduce memory overhead.
//
// Memory optimizations:
// 1. Flat array storage instead of pointer-based nodes
// 2. Compressed label storage with shared string pool
// 3. Bitmap for blocked/exact flags
// 4. Sequential layout for better cache locality
type CompactTrie struct {
	// nodes stores all trie nodes in a flat array
	// Each node is represented by:
	// - childrenOffset: offset to first child in nodes array (0 if leaf)
	// - childrenCount: number of children
	// - labelOffset: offset to label in labels array
	// - labelLen: length of label
	// - flags: bitmap for blocked/exact status
	nodes []trieNodeCompact

	// labels stores all labels as a continuous byte array
	labels []byte

	// labelOffsets stores the starting offset of each unique label
	labelOffsets map[string]int

	// rootIdx is the index of the root node
	rootIdx int

	// count is the number of inserted domains (atomic for lock-free reads)
	count atomic.Int64

	// mu protects concurrent reads during updates
	mu sync.RWMutex
}

type trieNodeCompact struct {
	childrenOffset int            // offset to first child (0 = no children)
	childrenCount  int            // number of children
	labelOffset    int            // offset into labels array
	labelLen       int            // length of label
	blocked        bool           // ancestor match (Insert)
	exact          bool           // exact match only (InsertExact)
	childrenMap    map[string]int // map from label to child index (for fast lookup during build)
}

// NewCompactTrie creates a new memory-optimized trie
func NewCompactTrie() *CompactTrie {
	ct := &CompactTrie{
		nodes:        make([]trieNodeCompact, 0, 1024),
		labels:       make([]byte, 0, 4096),
		labelOffsets: make(map[string]int),
		rootIdx:      0,
	}
	// Initialize root node
	ct.nodes = append(ct.nodes, trieNodeCompact{})
	return ct
}

// getOrCreateLabel adds a label to the labels array if not exists,
// returns its offset and length
func (ct *CompactTrie) getOrCreateLabel(label string) (offset, length int) {
	if off, ok := ct.labelOffsets[label]; ok {
		return off, len(label)
	}
	offset = len(ct.labels)
	ct.labels = append(ct.labels, []byte(label)...)
	ct.labelOffsets[label] = offset
	return offset, len(label)
}

// findChild finds a child node with the given label
func (ct *CompactTrie) findChild(nodeIdx int, label string) int {
	node := ct.nodes[nodeIdx]
	if node.childrenCount == 0 {
		return -1
	}

	// Use childrenMap for fast lookup if available
	if node.childrenMap != nil {
		if idx, ok := node.childrenMap[label]; ok {
			return idx
		}
		return -1
	}

	// Fallback to linear search (for backward compatibility)
	for i := 0; i < node.childrenCount; i++ {
		childIdx := node.childrenOffset + i
		child := ct.nodes[childIdx]
		if child.labelLen == len(label) {
			// Compare label bytes
			match := true
			for j := 0; j < child.labelLen; j++ {
				if ct.labels[child.labelOffset+j] != label[j] {
					match = false
					break
				}
			}
			if match {
				return childIdx
			}
		}
	}
	return -1
}

// addChild adds a child node to the parent
func (ct *CompactTrie) addChild(parentIdx int, label string, blocked, exact bool) int {
	parent := ct.nodes[parentIdx]
	labelOff, labelLen := ct.getOrCreateLabel(label)

	newNode := trieNodeCompact{
		labelOffset: labelOff,
		labelLen:    labelLen,
		blocked:     blocked,
		exact:       exact,
	}

	newIdx := len(ct.nodes)
	ct.nodes = append(ct.nodes, newNode)

	// Update parent's children
	if parent.childrenCount == 0 {
		// First child
		ct.nodes[parentIdx].childrenOffset = newIdx
		ct.nodes[parentIdx].childrenCount = 1
		// Initialize childrenMap for fast lookup
		ct.nodes[parentIdx].childrenMap = make(map[string]int)
	} else {
		ct.nodes[parentIdx].childrenCount++
	}

	// Add to childrenMap
	ct.nodes[parentIdx].childrenMap[label] = newIdx

	return newIdx
}

// Insert adds a domain with ancestor matching (wildcard-style)
func (ct *CompactTrie) Insert(domain string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	parts := labels(domain)
	if len(parts) == 0 {
		return
	}

	nodeIdx := ct.rootIdx
	for _, label := range parts {
		childIdx := ct.findChild(nodeIdx, label)
		if childIdx == -1 {
			childIdx = ct.addChild(nodeIdx, label, false, false)
		}
		nodeIdx = childIdx
	}

	// Mark this node as blocked (affects all descendants)
	if !ct.nodes[nodeIdx].blocked {
		ct.nodes[nodeIdx].blocked = true
		ct.count.Add(1)
	}
}

// insertNoLock is like Insert but without locking (for batch operations)
func (ct *CompactTrie) insertNoLock(domain string) {
	parts := labels(domain)
	if len(parts) == 0 {
		return
	}

	nodeIdx := ct.rootIdx
	for _, label := range parts {
		childIdx := ct.findChild(nodeIdx, label)
		if childIdx == -1 {
			childIdx = ct.addChild(nodeIdx, label, false, false)
		}
		nodeIdx = childIdx
	}

	// Mark this node as blocked (affects all descendants)
	if !ct.nodes[nodeIdx].blocked {
		ct.nodes[nodeIdx].blocked = true
		ct.count.Add(1)
	}
}

// InsertExact adds a domain with exact-only matching
func (ct *CompactTrie) InsertExact(domain string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	parts := labels(domain)
	if len(parts) == 0 {
		return
	}

	nodeIdx := ct.rootIdx
	for _, label := range parts {
		childIdx := ct.findChild(nodeIdx, label)
		if childIdx == -1 {
			childIdx = ct.addChild(nodeIdx, label, false, false)
		}
		nodeIdx = childIdx
	}

	// Mark this node as exact match only
	if !ct.nodes[nodeIdx].exact {
		ct.nodes[nodeIdx].exact = true
		ct.count.Add(1)
	}
}

// insertExactNoLock is like InsertExact but without locking (for batch operations)
func (ct *CompactTrie) insertExactNoLock(domain string) {
	parts := labels(domain)
	if len(parts) == 0 {
		return
	}

	nodeIdx := ct.rootIdx
	for _, label := range parts {
		childIdx := ct.findChild(nodeIdx, label)
		if childIdx == -1 {
			childIdx = ct.addChild(nodeIdx, label, false, false)
		}
		nodeIdx = childIdx
	}

	// Mark this node as exact match only
	if !ct.nodes[nodeIdx].exact {
		ct.nodes[nodeIdx].exact = true
		ct.count.Add(1)
	}
}

// Lookup checks if a domain matches any rule
func (ct *CompactTrie) Lookup(domain string) bool {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	parts := labels(domain)
	if len(parts) == 0 {
		return false
	}

	nodeIdx := ct.rootIdx
	for _, label := range parts {
		// Check if current node is blocked (ancestor match)
		if ct.nodes[nodeIdx].blocked {
			return true
		}

		childIdx := ct.findChild(nodeIdx, label)
		if childIdx == -1 {
			return false
		}
		nodeIdx = childIdx
	}

	// Terminal node: check both blocked and exact
	node := ct.nodes[nodeIdx]
	return node.blocked || node.exact
}

// Len returns the number of entries (lock-free atomic read)
func (ct *CompactTrie) Len() int {
	return int(ct.count.Load())
}

// ClearChildrenMaps removes all childrenMap to save memory after build is complete.
// This should be called after all insertions are done and before the trie is used for queries.
// Queries will fall back to linear search, which is acceptable for typical trie depths (2-4 levels).
func (ct *CompactTrie) ClearChildrenMaps() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	for i := range ct.nodes {
		ct.nodes[i].childrenMap = nil
	}
}

// Clear resets the trie
func (ct *CompactTrie) Clear() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.nodes = make([]trieNodeCompact, 0, 1024)
	ct.labels = make([]byte, 0, 4096)
	ct.labelOffsets = make(map[string]int)
	ct.nodes = append(ct.nodes, trieNodeCompact{})
	ct.count.Store(0)
}
