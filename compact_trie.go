package hostlist

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

// CompactTrie is an immutable-once-published radix trie over reversed domain
// labels. Builders (Insert*) take the write lock; lookups are lock-free and
// rely on the caller never mutating a published trie (Update builds a new one
// and swaps it into the atomic snapshot).
type CompactTrie struct {
	nodes        []trieNodeCompact
	childMaps    []map[string]int
	labels       []byte
	labelOffsets map[string]int
	values       []string
	valueIndexes map[string]int
	rootIdx      int
	count        atomic.Int64
	mu           sync.RWMutex
}

type trieNodeCompact struct {
	childrenOffset int32
	childrenCount  int32
	labelOffset    int32
	labelLen       int32
	valueIdx       uint32
	flags          uint8
}

func (n trieNodeCompact) blocked() bool { return n.flags&1 != 0 }
func (n trieNodeCompact) exact() bool   { return n.flags&2 != 0 }

func setBlocked(n *trieNodeCompact) {
	if n.flags&1 == 0 {
		n.flags |= 1
	}
}

func setExact(n *trieNodeCompact) {
	if n.flags&2 == 0 {
		n.flags |= 2
	}
}

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

func labelsFromFQDNLower(domain string) []string {
	return splitReversed(strings.TrimSuffix(domain, "."))
}

// splitReversed splits an FQDN into its labels, TLD first.
func splitReversed(fqdn string) []string {
	if fqdn == "" {
		return nil
	}
	parts := strings.Split(fqdn, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

// trimName strips the trailing dot once; the label walkers below then match
// labels in place, so a lookup allocates nothing.
func trimName(name string) string {
	return strings.TrimSuffix(name, ".")
}

// LookupNameWithParentCheck is LookupWithParentCheckLabels without the
// per-query label slice; see that method for the matching rules.
func (ct *CompactTrie) LookupNameWithParentCheck(name string) bool {
	// ToLower is a no-op for the already lowercased query name, and keeps
	// this entry point equivalent to the label-based API for other callers.
	name = trimName(strings.ToLower(name))
	if name == "" {
		return false
	}
	nodeIdx := ct.rootIdx
	depth := 0
	for end := len(name); end > 0; {
		start := strings.LastIndexByte(name[:end], '.') + 1
		childIdx := ct.findChild(nodeIdx, name[start:end])
		if childIdx == -1 {
			if depth > 0 && ct.nodes[nodeIdx].blocked() {
				return true
			}
			return false
		}
		nodeIdx = childIdx
		node := ct.nodes[nodeIdx]
		if node.blocked() || node.exact() {
			return true
		}
		depth++
		if start == 0 {
			break
		}
		end = start - 1
	}
	return false
}

// LookupExactValueName is LookupExactValueLabels without the label slice.
func (ct *CompactTrie) LookupExactValueName(name string) (bool, string) {
	name = trimName(strings.ToLower(name))
	if name == "" {
		return false, ""
	}
	nodeIdx := ct.rootIdx
	for end := len(name); end > 0; {
		start := strings.LastIndexByte(name[:end], '.') + 1
		childIdx := ct.findChild(nodeIdx, name[start:end])
		if childIdx == -1 {
			return false, ""
		}
		nodeIdx = childIdx
		if start == 0 {
			break
		}
		end = start - 1
	}

	node := ct.nodes[nodeIdx]
	if !node.exact() {
		return false, ""
	}
	if node.valueIdx == 0 || int(node.valueIdx) >= len(ct.values) {
		return true, ""
	}
	return true, ct.values[node.valueIdx]
}

func NewCompactTrie() *CompactTrie {
	ct := &CompactTrie{
		nodes:        make([]trieNodeCompact, 0, 1024),
		childMaps:    make([]map[string]int, 0, 1024),
		labels:       make([]byte, 0, 4096),
		labelOffsets: make(map[string]int),
		values:       []string{""},
		valueIndexes: make(map[string]int),
		rootIdx:      0,
	}
	ct.nodes = append(ct.nodes, trieNodeCompact{})
	ct.childMaps = append(ct.childMaps, nil)
	return ct
}

func (ct *CompactTrie) getOrCreateLabel(label string) (offset, length int) {
	if ct.labelOffsets == nil {
		ct.labelOffsets = make(map[string]int)
	}
	if off, ok := ct.labelOffsets[label]; ok {
		return off, len(label)
	}
	offset = len(ct.labels)
	ct.labels = append(ct.labels, []byte(label)...)
	ct.labelOffsets[label] = offset
	return offset, len(label)
}

func (ct *CompactTrie) getOrCreateValue(value string) int {
	if value == "" {
		return 0
	}
	if ct.valueIndexes == nil {
		ct.valueIndexes = make(map[string]int)
	}
	if idx, ok := ct.valueIndexes[value]; ok {
		return idx
	}
	idx := len(ct.values)
	ct.values = append(ct.values, value)
	ct.valueIndexes[value] = idx
	return idx
}

func (ct *CompactTrie) findChild(nodeIdx int, label string) int {
	node := ct.nodes[nodeIdx]
	if node.childrenCount == 0 {
		return -1
	}

	if len(ct.childMaps) > nodeIdx && ct.childMaps[nodeIdx] != nil {
		if idx, ok := ct.childMaps[nodeIdx][label]; ok {
			return idx
		}
		return -1
	}

	start := int(node.childrenOffset)
	end := start + int(node.childrenCount)
	if start < 0 || end > len(ct.nodes) || start > end {
		return -1
	}
	for idx := start; idx < end; idx++ {
		child := ct.nodes[idx]
		start := int(child.labelOffset)
		end := start + int(child.labelLen)
		if start < 0 || end > len(ct.labels) || start > end {
			continue
		}
		if labelBytesEqual(ct.labels[start:end], label) {
			return idx
		}
	}
	return -1
}

func (ct *CompactTrie) addChild(parentIdx int, label string, blocked, exact bool) int {
	labelOff, labelLen := ct.getOrCreateLabel(label)

	newNode := trieNodeCompact{
		labelOffset: int32(labelOff),
		labelLen:    int32(labelLen),
	}
	if blocked {
		setBlocked(&newNode)
	}
	if exact {
		setExact(&newNode)
	}

	// 确保子节点连续存储
	if ct.nodes[parentIdx].childrenCount == 0 {
		// 第一个子节点
		newIdx := len(ct.nodes)
		ct.nodes = append(ct.nodes, newNode)
		ct.childMaps = append(ct.childMaps, nil)
		ct.nodes[parentIdx].childrenOffset = int32(newIdx)
		ct.nodes[parentIdx].childrenCount = 1
		ct.ensureChildMapsSize()
		if len(ct.childMaps) <= parentIdx || ct.childMaps[parentIdx] == nil {
			ct.childMaps[parentIdx] = make(map[string]int)
		}
		ct.childMaps[parentIdx][label] = newIdx
		return newIdx
	}

	// 如果 childrenMap 为 nil（被 ClearChildrenMaps 清空），重新创建并填充现有子节点
	if len(ct.childMaps) <= parentIdx || ct.childMaps[parentIdx] == nil {
		ct.ensureChildMapsSize()
		ct.childMaps[parentIdx] = make(map[string]int)
		// 填充现有子节点到新创建的 childrenMap
		offset := int(ct.nodes[parentIdx].childrenOffset)
		count := int(ct.nodes[parentIdx].childrenCount)
		for childIdx := range count {
			childIdx += offset
			if childIdx < len(ct.nodes) {
				child := ct.nodes[childIdx]
				childLabel := string(ct.labels[int(child.labelOffset) : int(child.labelOffset)+int(child.labelLen)])
				ct.childMaps[parentIdx][childLabel] = childIdx
			}
		}
	}

	// Subsequent children are appended at the end of ct.nodes; ClearChildrenMaps
	// rebuilds the layout so each parent's children end up contiguous.
	newIdx := len(ct.nodes)
	ct.nodes = append(ct.nodes, newNode)
	ct.childMaps = append(ct.childMaps, nil)

	// 更新父节点的子节点计数
	ct.nodes[parentIdx].childrenCount++

	// 确保 childrenMap 不为 nil
	if len(ct.childMaps) <= parentIdx || ct.childMaps[parentIdx] == nil {
		ct.ensureChildMapsSize()
		ct.childMaps[parentIdx] = make(map[string]int)
	}
	ct.childMaps[parentIdx][label] = newIdx

	return newIdx
}

func (ct *CompactTrie) Insert(domain string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.insertNoLock(domain)
}

func (ct *CompactTrie) insertNoLock(domain string) {
	nodeIdx := ct.insertWalk(domain)
	if nodeIdx < 0 {
		return
	}

	if !ct.nodes[nodeIdx].blocked() {
		setBlocked(&ct.nodes[nodeIdx])
		ct.count.Add(1)
	}
}

// insertWalk walks (creating as needed) the nodes for domain and returns the
// terminal node index, or -1 for an empty name. It scans the name in place,
// so bulk inserts do not allocate a label slice per rule.
func (ct *CompactTrie) insertWalk(domain string) int {
	name := trimName(strings.ToLower(domain))
	if name == "" {
		return -1
	}

	nodeIdx := ct.rootIdx
	for end := len(name); end > 0; {
		start := strings.LastIndexByte(name[:end], '.') + 1
		label := name[start:end]
		childIdx := ct.findChild(nodeIdx, label)
		if childIdx == -1 {
			childIdx = ct.addChild(nodeIdx, label, false, false)
		}
		nodeIdx = childIdx
		if start == 0 {
			break
		}
		end = start - 1
	}
	return nodeIdx
}

func (ct *CompactTrie) InsertExact(domain string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.insertExactNoLock(domain)
}

func (ct *CompactTrie) InsertExactValue(domain, value string) {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	ct.insertExactValueNoLock(domain, value)
}

func (ct *CompactTrie) insertExactNoLock(domain string) {
	ct.insertExactValueNoLock(domain, "")
}

func (ct *CompactTrie) insertExactValueNoLock(domain, value string) {
	nodeIdx := ct.insertWalk(domain)
	if nodeIdx < 0 {
		return
	}

	if !ct.nodes[nodeIdx].exact() {
		setExact(&ct.nodes[nodeIdx])
		ct.count.Add(1)
	}
	if value != "" {
		ct.nodes[nodeIdx].valueIdx = uint32(ct.getOrCreateValue(value))
	}
}

func (ct *CompactTrie) Lookup(domain string) bool {
	return ct.LookupLabels(labels(domain))
}

func (ct *CompactTrie) LookupLabels(parts []string) bool {
	if len(parts) == 0 {
		return false
	}

	nodeIdx := ct.rootIdx
	for _, label := range parts {
		childIdx := ct.findChild(nodeIdx, label)
		if childIdx == -1 {
			return false
		}
		nodeIdx = childIdx

		node := ct.nodes[nodeIdx]
		if node.blocked() || node.exact() {
			return true
		}
	}

	return false
}

func (ct *CompactTrie) LookupExactValue(domain string) (bool, string) {
	return ct.LookupExactValueLabels(labels(domain))
}

func (ct *CompactTrie) LookupExactValueLabels(parts []string) (bool, string) {
	if len(parts) == 0 {
		return false, ""
	}

	nodeIdx := ct.rootIdx
	for _, label := range parts {
		childIdx := ct.findChild(nodeIdx, label)
		if childIdx == -1 {
			return false, ""
		}
		nodeIdx = childIdx
	}

	node := ct.nodes[nodeIdx]
	if !node.exact() {
		return false, ""
	}
	if node.valueIdx == 0 || int(node.valueIdx) >= len(ct.values) {
		return true, ""
	}
	return true, ct.values[node.valueIdx]
}

func (ct *CompactTrie) LookupWithParentCheck(domain string) bool {
	return ct.LookupWithParentCheckLabels(labels(domain))
}

func (ct *CompactTrie) LookupWithParentCheckLabels(parts []string) bool {
	if len(parts) == 0 {
		return false
	}

	nodeIdx := ct.rootIdx
	for i, label := range parts {
		childIdx := ct.findChild(nodeIdx, label)
		if childIdx == -1 {
			if i > 0 {
				parentNode := ct.nodes[nodeIdx]
				if parentNode.blocked() {
					return true
				}
			}
			return false
		}
		nodeIdx = childIdx

		node := ct.nodes[nodeIdx]
		if node.blocked() || node.exact() {
			return true
		}
	}

	return false
}

func (ct *CompactTrie) Len() int {
	return int(ct.count.Load())
}

// ClearChildrenMaps releases the per-node child lookup maps to save memory
// after the trie has been fully constructed. It also shrinks the nodes/labels/
// values slices to their exact size to eliminate over-capacity from
// incremental growth during insertion.
func (ct *CompactTrie) ClearChildrenMaps() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	if len(ct.nodes) <= 1 {
		ct.childMaps = nil
		ct.labels = cloneBytesTight(ct.labels)
		ct.values = cloneStringsTight(ct.values)
		ct.labelOffsets = nil
		ct.valueIndexes = nil
		return
	}

	// Rebuild the nodes array so that every parent's children are stored
	// contiguously. During insertion, children are appended at the end of
	// ct.nodes (newIdx = len(ct.nodes)), which means different parents'
	// children interleave. After this rebuild, findChild's linear scan
	// over [childrenOffset, childrenOffset+childrenCount) is correct.
	newNodes := make([]trieNodeCompact, 1, len(ct.nodes))
	newNodes[0] = trieNodeCompact{}

	var rebuild func(oldIdx, newIdx int)
	rebuild = func(oldIdx, newIdx int) {
		children := ct.childIndices(oldIdx)
		if len(children) == 0 {
			return
		}

		start := len(newNodes)
		newNodes[newIdx].childrenOffset = int32(start)
		newNodes[newIdx].childrenCount = int32(len(children))

		newChildIdxs := make([]int, len(children))
		for i, childOldIdx := range children {
			oldChild := ct.nodes[childOldIdx]
			newChild := trieNodeCompact{
				labelOffset: oldChild.labelOffset,
				labelLen:    oldChild.labelLen,
				valueIdx:    oldChild.valueIdx,
				flags:       oldChild.flags,
			}
			newChildIdxs[i] = len(newNodes)
			newNodes = append(newNodes, newChild)
		}

		for i, childOldIdx := range children {
			rebuild(childOldIdx, newChildIdxs[i])
		}
	}

	rebuild(ct.rootIdx, 0)
	ct.nodes = newNodes
	ct.childMaps = nil

	// Shrink the flat slices to their exact size (releases over-capacity).
	ct.labels = cloneBytesTight(ct.labels)
	ct.values = cloneStringsTight(ct.values)

	ct.labelOffsets = nil
	ct.valueIndexes = nil
}

func (ct *CompactTrie) childIndices(nodeIdx int) []int {
	node := ct.nodes[nodeIdx]
	if node.childrenCount == 0 {
		return nil
	}
	if len(ct.childMaps) <= nodeIdx || ct.childMaps[nodeIdx] == nil {
		start := int(node.childrenOffset)
		end := start + int(node.childrenCount)
		if start < 0 || end > len(ct.nodes) || start > end {
			return nil
		}
		indices := make([]int, 0, node.childrenCount)
		for idx := start; idx < end; idx++ {
			indices = append(indices, idx)
		}
		return indices
	}

	indices := make([]int, 0, len(ct.childMaps[nodeIdx]))
	for _, idx := range ct.childMaps[nodeIdx] {
		indices = append(indices, idx)
	}
	// No sorting: trie correctness does not depend on child order.
	// Sorting only improves cache locality during lookups, but the cost
	// of allocating and sorting during rebuild outweighs the benefit.
	return indices
}

func (ct *CompactTrie) nodeLabel(nodeIdx int) string {
	node := ct.nodes[nodeIdx]
	start := int(node.labelOffset)
	end := start + int(node.labelLen)
	if start < 0 || end > len(ct.labels) || start > end {
		return ""
	}
	return string(ct.labels[start:end])
}

func (ct *CompactTrie) Clear() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.nodes = make([]trieNodeCompact, 0, 1024)
	ct.childMaps = make([]map[string]int, 0, 1024)
	ct.labels = make([]byte, 0, 4096)
	ct.labelOffsets = make(map[string]int)
	ct.values = []string{""}
	ct.valueIndexes = make(map[string]int)
	ct.nodes = append(ct.nodes, trieNodeCompact{})
	ct.childMaps = append(ct.childMaps, nil)
	ct.count.Store(0)
}

func (ct *CompactTrie) ensureChildMapsSize() {
	if len(ct.childMaps) < len(ct.nodes) {
		ct.childMaps = append(ct.childMaps, make([]map[string]int, len(ct.nodes)-len(ct.childMaps))...)
	}
}

func cloneNodesTight(src []trieNodeCompact) []trieNodeCompact {
	if len(src) == 0 {
		return nil
	}
	dst := make([]trieNodeCompact, len(src))
	copy(dst, src)
	return dst
}

func cloneBytesTight(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func cloneStringsTight(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}

func labelBytesEqual(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := range b {
		if b[i] != s[i] {
			return false
		}
	}
	return true
}
