package hostlist

import (
	"fmt"
	"testing"
)

// TestCompactTrieNameLookupMatchesLabelLookup guards the allocation-free name
// walkers against the slice-based reference implementation. A divergence here
// means wrong block decisions, so every variant is compared on the same trie.
func TestCompactTrieNameLookupMatchesLabelLookup(t *testing.T) {
	trie := NewCompactTrie()
	blocked := []string{
		"example.com.",
		"ads.example.com.",
		"tracker.sub.example.com.",
		"xn--fiq228c.cn.",
		"cn.",
	}
	for _, d := range blocked {
		trie.Insert(d)
	}
	for _, d := range []string{"hosts.example.org.", "1.0.0.127.in-addr.arpa."} {
		trie.InsertExactValue(d, "127.0.0.1")
	}
	trie.ClearChildrenMaps()

	queries := append([]string{
		"example.com.",
		"EXAMPLE.COM.",
		"example.com",
		"www.example.com.",
		"deep.www.example.com.",
		"ads.example.com.",
		"notads.example.com.",
		"tracker.sub.example.com.",
		"x.tracker.sub.example.com.",
		"xn--fiq228c.cn.",
		"cn.",
		"other.net.",
		".",
		"",
		"hosts.example.org.",
		"1.0.0.127.in-addr.arpa.",
	}, blocked...)

	for _, name := range queries {
		// Reference implementation: labels() normalizes case and FQDN, which
		// is what the query path feeds the trie.
		wantParent := trie.LookupWithParentCheck(name)
		if got := trie.LookupNameWithParentCheck(name); got != wantParent {
			t.Fatalf("LookupNameWithParentCheck(%q)=%v, want %v", name, got, wantParent)
		}

		wantMatch, wantVal := trie.LookupExactValue(name)
		gotMatch, gotVal := trie.LookupExactValueName(name)
		if gotMatch != wantMatch || gotVal != wantVal {
			t.Fatalf("LookupExactValueName(%q)=(%v,%q), want (%v,%q)", name, gotMatch, gotVal, wantMatch, wantVal)
		}
	}
}

func buildBenchTrie(n int) *CompactTrie {
	trie := NewCompactTrie()
	for i := 0; i < n; i++ {
		trie.Insert(fmt.Sprintf("host%d.blocklist%d.example.com.", i, i%97))
	}
	trie.InsertExactValue("exact.example.com.", "10.0.0.1")
	trie.ClearChildrenMaps()
	return trie
}

func BenchmarkLookupWithParentCheckLabels(b *testing.B) {
	trie := buildBenchTrie(10000)
	name := "www.host42.blocklist42.example.com."
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		trie.LookupWithParentCheckLabels(labelsFromFQDNLower(name))
	}
}

func BenchmarkLookupNameWithParentCheck(b *testing.B) {
	trie := buildBenchTrie(10000)
	name := "www.host42.blocklist42.example.com."
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		trie.LookupNameWithParentCheck(name)
	}
}

func BenchmarkInsertPrepared(b *testing.B) {
	domains := make([]string, 10000)
	for i := range domains {
		domains[i] = fmt.Sprintf("host%d.example%d.com.", i, i%97)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		trie := NewCompactTrie()
		for _, d := range domains {
			trie.insertNoLock(d)
		}
	}
}


func TestCompactTrieClearChildrenMapsPreservesLookup(t *testing.T) {
	trie := NewCompactTrie()
	trie.Insert("example.com.")
	trie.Insert("ads.example.com.")
	trie.InsertExact("exact.example.com.")

	before := []struct {
		domain string
		parent bool
		exact  bool
	}{
		{domain: "example.com.", parent: true, exact: true},
		{domain: "www.example.com.", parent: true, exact: true},
		{domain: "ads.example.com.", parent: true, exact: true},
		{domain: "exact.example.com.", parent: true, exact: true},
		{domain: "no-match.example.net.", parent: false, exact: false},
	}

	for _, tc := range before {
		if got := trie.LookupWithParentCheck(tc.domain); got != tc.parent {
			t.Fatalf("before clear LookupWithParentCheck(%q)=%v, want %v", tc.domain, got, tc.parent)
		}
		if got := trie.Lookup(tc.domain); got != tc.exact {
			t.Fatalf("before clear Lookup(%q)=%v, want %v", tc.domain, got, tc.exact)
		}
	}

	trie.ClearChildrenMaps()

	for _, tc := range before {
		if got := trie.LookupWithParentCheck(tc.domain); got != tc.parent {
			t.Fatalf("after clear LookupWithParentCheck(%q)=%v, want %v", tc.domain, got, tc.parent)
		}
		if got := trie.Lookup(tc.domain); got != tc.exact {
			t.Fatalf("after clear Lookup(%q)=%v, want %v", tc.domain, got, tc.exact)
		}
	}

	if trie.labelOffsets != nil {
		t.Fatal("expected labelOffsets to be released after ClearChildrenMaps")
	}
}

func TestCompactTrieInsertAfterClearChildrenMaps(t *testing.T) {
	trie := NewCompactTrie()
	trie.Insert("example.com.")
	trie.ClearChildrenMaps()

	trie.Insert("new.example.com.")
	trie.InsertExact("exact.new.example.com.")

	if !trie.LookupWithParentCheck("foo.example.com.") {
		t.Fatal("expected parent lookup to keep working after ClearChildrenMaps")
	}
	if !trie.LookupWithParentCheck("new.example.com.") {
		t.Fatal("expected inserted domain lookup to work after ClearChildrenMaps")
	}
	if !trie.Lookup("exact.new.example.com.") {
		t.Fatal("expected inserted exact domain lookup to work after ClearChildrenMaps")
	}
}

func TestCompactTrieLookupExactValuePreservedAfterClear(t *testing.T) {
	trie := NewCompactTrie()
	trie.InsertExactValue("hosts.example.com.", "127.0.0.1")

	matched, value := trie.LookupExactValue("hosts.example.com.")
	if !matched || value != "127.0.0.1" {
		t.Fatalf("before clear LookupExactValue mismatch: matched=%v value=%q", matched, value)
	}

	trie.ClearChildrenMaps()

	matched, value = trie.LookupExactValue("hosts.example.com.")
	if !matched || value != "127.0.0.1" {
		t.Fatalf("after clear LookupExactValue mismatch: matched=%v value=%q", matched, value)
	}
}

func TestCompactTrieClearChildrenMapsShrinksBackingCapacity(t *testing.T) {
	trie := NewCompactTrie()
	trie.Insert("example.com.")
	trie.InsertExactValue("hosts.example.com.", "127.0.0.1")

	if cap(trie.labels) == len(trie.labels) && cap(trie.values) == len(trie.values) {
		t.Fatal("expected trie to have spare capacity before ClearChildrenMaps")
	}

	trie.ClearChildrenMaps()

	if cap(trie.labels) != len(trie.labels) {
		t.Fatalf("expected labels capacity to shrink to len, got len=%d cap=%d", len(trie.labels), cap(trie.labels))
	}
	if cap(trie.values) != len(trie.values) {
		t.Fatalf("expected values capacity to shrink to len, got len=%d cap=%d", len(trie.values), cap(trie.values))
	}
	if trie.labelOffsets != nil {
		t.Fatal("expected labelOffsets to be nil after ClearChildrenMaps")
	}
	if trie.valueIndexes != nil {
		t.Fatal("expected valueIndexes to be nil after ClearChildrenMaps")
	}
}
