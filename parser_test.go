package hostlist

import (
	"strings"
	"testing"
)

func TestParseAdblockRules(t *testing.T) {
	input := `! Title: Test
||ads.example.com^
||tracker.other.com^$third-party
||blocked.org^
`
	result := ParseRules(strings.NewReader(input))
	if len(result.Blocked) != 3 {
		t.Fatalf("expected 3 blocked domains, got %d: %v", len(result.Blocked), result.Blocked)
	}
	expected := map[string]bool{
		"ads.example.com.": true,
		"tracker.other.com.": true,
		"blocked.org.":     true,
	}
	for _, d := range result.Blocked {
		if !expected[d] {
			t.Errorf("unexpected blocked domain: %s", d)
		}
	}
}

func TestParseExceptionRules(t *testing.T) {
	input := `||ads.example.com^
@@||whitelisted.com^
@@||unblocked.org^
`
	result := ParseRules(strings.NewReader(input))
	if len(result.Blocked) != 1 {
		t.Fatalf("expected 1 blocked, got %d", len(result.Blocked))
	}
	if len(result.Allowlist) != 2 {
		t.Fatalf("expected 2 allowlist, got %d: %v", len(result.Allowlist), result.Allowlist)
	}
}

func TestParseHostsFormat(t *testing.T) {
	input := `# comment
127.0.0.1 example.com
0.0.0.0 ads.org tracker.net
`
	result := ParseRules(strings.NewReader(input))
	if len(result.BlockedExact) != 3 {
		t.Fatalf("expected 3 exact blocked, got %d: %v", len(result.BlockedExact), result.BlockedExact)
	}
}

func TestParseRegexRules(t *testing.T) {
	input := `/^ads?\./
/^tracker\..*\.com$/
`
	result := ParseRules(strings.NewReader(input))
	if len(result.RegexBlock) != 2 {
		t.Fatalf("expected 2 regex patterns, got %d", len(result.RegexBlock))
	}
}

func TestParseDNSRewriteIgnored(t *testing.T) {
	input := `|www.google.com^$dnsrewrite=NOERROR;CNAME;forcesafesearch.google.com
||normal-block.com^
`
	result := ParseRules(strings.NewReader(input))
	if len(result.Blocked) != 1 {
		t.Fatalf("expected 1 blocked (dnsrewrite ignored), got %d", len(result.Blocked))
	}
	if result.Blocked[0] != "normal-block.com." {
		t.Errorf("expected normal-block.com., got %s", result.Blocked[0])
	}
}

func TestParseCommentsIgnored(t *testing.T) {
	input := `! This is a comment
# This is also a comment

||blocked.com^
`
	result := ParseRules(strings.NewReader(input))
	if len(result.Blocked) != 1 {
		t.Fatalf("expected 1 blocked, got %d", len(result.Blocked))
	}
}

func TestParseMixed(t *testing.T) {
	input := `! Title: Mixed Test
||ads.example.com^
@@||whitelisted.com^
127.0.0.1 specifichost.org
/^regex-block\./
! comment
# another comment

||tracker.net^$third-party
`
	result := ParseRules(strings.NewReader(input))
	if len(result.Blocked) != 2 {
		t.Errorf("expected 2 blocked, got %d", len(result.Blocked))
	}
	if len(result.Allowlist) != 1 {
		t.Errorf("expected 1 allowlist, got %d", len(result.Allowlist))
	}
	if len(result.BlockedExact) != 1 {
		t.Errorf("expected 1 exact, got %d", len(result.BlockedExact))
	}
	if len(result.RegexBlock) != 1 {
		t.Errorf("expected 1 regex, got %d", len(result.RegexBlock))
	}
}

func TestCompileRegexps(t *testing.T) {
	patterns := []string{`^ads\.`, `valid`, `[invalid`}
	regexps := CompileRegexps(patterns)
	if len(regexps) != 2 {
		t.Fatalf("expected 2 valid regexps, got %d", len(regexps))
	}
	if !MatchAny("ads.example.com", regexps) {
		t.Fatal("expected match for ads.example.com")
	}
	if MatchAny("normal.com", regexps) {
		t.Fatal("expected no match for normal.com")
	}
}

func TestParseAllowlistWithTrailingPipe(t *testing.T) {
	// User's format: @@||domain^| (trailing | after ^)
	input := `@@||unsubscribe.lhinsights.com^|
@@||belgium.wolterskluwer.com^|
@@||sedge.nfl.com^|
@@||data.orders.costco.com^|
@@|affiliate.notion.so^|`
	result := ParseRules(strings.NewReader(input))
	if len(result.Allowlist) != 5 {
		t.Fatalf("expected 5 allowlist, got %d: %v", len(result.Allowlist), result.Allowlist)
	}
	for _, d := range result.Allowlist {
		if d == "" {
			t.Fatal("empty domain in allowlist")
		}
		t.Logf("Allowlist domain: %s", d)
	}
}
