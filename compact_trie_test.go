package hostlist

import "testing"

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
}
