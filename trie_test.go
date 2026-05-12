package hostlist

import "testing"

func TestTrieInsertLookup(t *testing.T) {
	tr := NewTrie()
	tr.Insert("example.com.")

	if !tr.Lookup("example.com.") {
		t.Fatal("expected exact match")
	}
	if !tr.Lookup("sub.example.com.") {
		t.Fatal("expected ancestor match for subdomain")
	}
	if !tr.Lookup("a.b.c.example.com.") {
		t.Fatal("expected ancestor match for deep subdomain")
	}
	if tr.Lookup("other.com.") {
		t.Fatal("expected no match for unrelated domain")
	}
	if tr.Len() != 1 {
		t.Fatalf("expected len 1, got %d", tr.Len())
	}
}

func TestTrieInsertExact(t *testing.T) {
	tr := NewTrie()
	tr.InsertExact("example.com.")

	if !tr.Lookup("example.com.") {
		t.Fatal("expected exact match")
	}
	if tr.Lookup("sub.example.com.") {
		t.Fatal("expected NO ancestor match for exact insert")
	}
}

func TestTrieMultipleEntries(t *testing.T) {
	tr := NewTrie()
	tr.Insert("ads.example.com.")
	tr.Insert("tracker.other.com.")
	tr.InsertExact("cdn.specific.org.")

	if !tr.Lookup("ads.example.com.") {
		t.Fatal("expected match for ads.example.com")
	}
	if !tr.Lookup("sub.ads.example.com.") {
		t.Fatal("expected ancestor match for sub.ads.example.com")
	}
	if !tr.Lookup("tracker.other.com.") {
		t.Fatal("expected match for tracker.other.com")
	}
	if !tr.Lookup("cdn.specific.org.") {
		t.Fatal("expected match for cdn.specific.org")
	}
	if tr.Lookup("sub.cdn.specific.org.") {
		t.Fatal("expected NO match for sub.cdn.specific.org (exact insert)")
	}
	if tr.Len() != 3 {
		t.Fatalf("expected len 3, got %d", tr.Len())
	}
}

func TestTrieClear(t *testing.T) {
	tr := NewTrie()
	tr.Insert("example.com.")
	tr.Clear()

	if tr.Lookup("example.com.") {
		t.Fatal("expected no match after clear")
	}
	if tr.Len() != 0 {
		t.Fatalf("expected len 0, got %d", tr.Len())
	}
}

func TestTrieNormalization(t *testing.T) {
	tr := NewTrie()
	tr.Insert("EXAMPLE.COM.")

	if !tr.Lookup("example.com.") {
		t.Fatal("expected case-insensitive match")
	}
	if !tr.Lookup("EXAMPLE.COM.") {
		t.Fatal("expected case-insensitive match uppercase")
	}
}

func TestTrieEmptyDomain(t *testing.T) {
	tr := NewTrie()
	tr.Insert("")
	tr.Insert(".")

	if tr.Len() != 0 {
		t.Fatalf("expected len 0 for empty inserts, got %d", tr.Len())
	}
}

func TestTrieInsertExactWithSubdomains(t *testing.T) {
	// Simulate filter_2: 360in.com and ad.360in.com both inserted
	tr := NewTrie()
	tr.InsertExact("360in.com.")
	tr.InsertExact("ad.360in.com.")
	tr.InsertExact("challenge.360in.com.")

	// Exact match should work
	if !tr.Lookup("360in.com.") {
		t.Fatal("expected match for 360in.com")
	}
	if !tr.Lookup("ad.360in.com.") {
		t.Fatal("expected match for ad.360in.com")
	}
	// Subdomain NOT in list should NOT match (exact only)
	if tr.Lookup("test.360in.com.") {
		t.Fatal("expected NO match for test.360in.com (not in exact list)")
	}
	if tr.Lookup("random.360in.com.") {
		t.Fatal("expected NO match for random.360in.com")
	}
}
