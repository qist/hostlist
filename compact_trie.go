package hostlist

import (
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

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
	fqdn := strings.TrimSuffix(domain, ".")
	if fqdn == "" {
		return nil
	}
	parts := strings.Split(fqdn, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
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

	// 后续子节点：插入到当前子节点区域的末尾
	currentOffset := int(ct.nodes[parentIdx].childrenOffset)
	currentCount := int(ct.nodes[parentIdx].childrenCount)
	newIdx := currentOffset + currentCount

	// 优化：总是追加到末尾，不保证子节点连续存储
	// 这样可以避免昂贵的数组移动和索引更新操作
	newIdx = len(ct.nodes)
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

	if !ct.nodes[nodeIdx].blocked() {
		setBlocked(&ct.nodes[nodeIdx])
		ct.count.Add(1)
	}
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
	ct.mu.RLock()
	defer ct.mu.RUnlock()

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
	ct.mu.RLock()
	defer ct.mu.RUnlock()

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
	ct.mu.RLock()
	defer ct.mu.RUnlock()

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
	sort.Slice(indices, func(i, j int) bool {
		return ct.nodeLabel(indices[i]) < ct.nodeLabel(indices[j])
	})
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
