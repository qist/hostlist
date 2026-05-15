package hostlist

import (
	"strings"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
)

type CompactTrie struct {
	nodes        []trieNodeCompact
	labels       []byte
	labelOffsets map[string]int
	rootIdx      int
	count        atomic.Int64
	mu           sync.RWMutex
}

type trieNodeCompact struct {
	childrenOffset int32
	childrenCount  int32
	labelOffset    int32
	labelLen       int32
	flags          uint8
	childrenMap    map[string]int
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

func NewCompactTrie() *CompactTrie {
	ct := &CompactTrie{
		nodes:        make([]trieNodeCompact, 0, 1024),
		labels:       make([]byte, 0, 4096),
		labelOffsets: make(map[string]int),
		rootIdx:      0,
	}
	ct.nodes = append(ct.nodes, trieNodeCompact{})
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

func (ct *CompactTrie) findChild(nodeIdx int, label string) int {
	node := ct.nodes[nodeIdx]
	if node.childrenCount == 0 {
		return -1
	}

	// 因为子节点不再连续存储，必须使用 childrenMap 查找
	if node.childrenMap != nil {
		if idx, ok := node.childrenMap[label]; ok {
			return idx
		}
	}

	// 如果 childrenMap 为 nil，无法进行查找（这种情况不应该发生）
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
		ct.nodes[parentIdx].childrenOffset = int32(newIdx)
		ct.nodes[parentIdx].childrenCount = 1
		ct.nodes[parentIdx].childrenMap = make(map[string]int)
		ct.nodes[parentIdx].childrenMap[label] = newIdx
		return newIdx
	}

	// 如果 childrenMap 为 nil（被 ClearChildrenMaps 清空），重新创建并填充现有子节点
	if ct.nodes[parentIdx].childrenMap == nil {
		ct.nodes[parentIdx].childrenMap = make(map[string]int)
		// 填充现有子节点到新创建的 childrenMap
		offset := int(ct.nodes[parentIdx].childrenOffset)
		count := int(ct.nodes[parentIdx].childrenCount)
		for i := 0; i < count; i++ {
			childIdx := offset + i
			if childIdx < len(ct.nodes) {
				child := ct.nodes[childIdx]
				childLabel := string(ct.labels[int(child.labelOffset) : int(child.labelOffset)+int(child.labelLen)])
				ct.nodes[parentIdx].childrenMap[childLabel] = childIdx
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

	// 更新父节点的子节点计数
	ct.nodes[parentIdx].childrenCount++

	// 确保 childrenMap 不为 nil
	if ct.nodes[parentIdx].childrenMap == nil {
		ct.nodes[parentIdx].childrenMap = make(map[string]int)
	}
	ct.nodes[parentIdx].childrenMap[label] = newIdx

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

	if !ct.nodes[nodeIdx].exact() {
		setExact(&ct.nodes[nodeIdx])
		ct.count.Add(1)
	}
}

func (ct *CompactTrie) Lookup(domain string) bool {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	parts := labels(domain)
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

func (ct *CompactTrie) LookupWithParentCheck(domain string) bool {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	parts := labels(domain)
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
	// 由于子节点不再连续存储，清空 childrenMap 后无法进行查找
	// 此方法现在为空操作，保留是为了保持 API 兼容性
	// 内存优化通过其他方式实现（如 GOGC 调优）
}

func (ct *CompactTrie) Clear() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ct.nodes = make([]trieNodeCompact, 0, 1024)
	ct.labels = make([]byte, 0, 4096)
	ct.labelOffsets = make(map[string]int)
	ct.nodes = append(ct.nodes, trieNodeCompact{})
	ct.count.Store(0)
}
