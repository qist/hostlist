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

	if node.childrenMap != nil {
		if idx, ok := node.childrenMap[label]; ok {
			return idx
		}
		return -1
	}

	n := int(node.childrenCount)
	off := int(node.childrenOffset)
	for i := 0; i < n; i++ {
		childIdx := off + i
		child := ct.nodes[childIdx]
		if int(child.labelLen) == len(label) {
			match := true
			coff := int(child.labelOffset)
			clen := int(child.labelLen)
			for j := 0; j < clen; j++ {
				if ct.labels[coff+j] != label[j] {
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

func (ct *CompactTrie) addChild(parentIdx int, label string, blocked, exact bool) int {
	parent := ct.nodes[parentIdx]
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

	newIdx := len(ct.nodes)
	ct.nodes = append(ct.nodes, newNode)

	if parent.childrenCount == 0 {
		ct.nodes[parentIdx].childrenOffset = int32(newIdx)
		ct.nodes[parentIdx].childrenCount = 1
		ct.nodes[parentIdx].childrenMap = make(map[string]int)
	} else {
		ct.nodes[parentIdx].childrenCount++
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
	}

	node := ct.nodes[nodeIdx]
	return node.blocked() || node.exact()
}

func (ct *CompactTrie) Len() int {
	return int(ct.count.Load())
}

func (ct *CompactTrie) ClearChildrenMaps() {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// 首先构建一个映射表，记录每个节点在新数组中的位置
	nodeMapping := make([]int, len(ct.nodes))
	for i := range nodeMapping {
		nodeMapping[i] = i
	}

	// 遍历所有节点，确保子节点连续存储
	for parentIdx := range ct.nodes {
		parent := ct.nodes[parentIdx]
		if parent.childrenCount == 0 || parent.childrenMap == nil {
			continue
		}

		// 获取当前子节点区域的信息
		currentOffset := int(parent.childrenOffset)
		currentCount := int(parent.childrenCount)

		// 检查子节点是否已经连续存储
		isContiguous := true
		expectedEnd := currentOffset + currentCount
		if expectedEnd > len(ct.nodes) {
			isContiguous = false
		} else {
			seen := make(map[int]bool)
			for _, childIdx := range parent.childrenMap {
				seen[childIdx] = true
			}
			for i := currentOffset; i < expectedEnd; i++ {
				if !seen[i] {
					isContiguous = false
					break
				}
			}
		}

		if isContiguous {
			ct.nodes[parentIdx].childrenMap = nil
			continue
		}

		// 需要重新组织子节点，将它们移动到连续的位置
		// 创建一个临时数组来保存重新组织后的节点
		newNodes := make([]trieNodeCompact, 0, len(ct.nodes))

		// 添加父节点之前的所有节点
		for i := 0; i <= parentIdx; i++ {
			newNodes = append(newNodes, ct.nodes[i])
		}

		// 添加父节点的子节点（连续存储）
		newChildOffset := len(newNodes)
		for _, childIdx := range parent.childrenMap {
			newNodes = append(newNodes, ct.nodes[childIdx])
			// 更新映射表
			nodeMapping[childIdx] = len(newNodes) - 1
		}

		// 更新父节点的 childrenOffset
		ct.nodes[parentIdx].childrenOffset = int32(newChildOffset)

		// 添加剩余的节点（排除已经移动的子节点）
		seen := make(map[int]bool)
		for _, childIdx := range parent.childrenMap {
			seen[childIdx] = true
		}
		for i := parentIdx + 1; i < len(ct.nodes); i++ {
			if !seen[i] {
				newNodes = append(newNodes, ct.nodes[i])
				nodeMapping[i] = len(newNodes) - 1
			}
		}

		// 更新所有受影响的 childrenMap 中的索引
		for i := 0; i <= parentIdx; i++ {
			if ct.nodes[i].childrenMap != nil {
				for label, idx := range ct.nodes[i].childrenMap {
					ct.nodes[i].childrenMap[label] = nodeMapping[idx]
				}
			}
		}

		ct.nodes = newNodes
		ct.nodes[parentIdx].childrenMap = nil
	}

	ct.labelOffsets = nil
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
