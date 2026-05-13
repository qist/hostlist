package hostlist

import (
	"bufio"
	"io"
	"net"
	"regexp"
	"strings"

	"github.com/miekg/dns"
)

// ParseResult holds the parsed domains and regex patterns from rule files.
type ParseResult struct {
	Blocked      []string // ||domain^ rules (ancestor match)
	BlockedExact []string // IP domain rules (exact match, hosts format)
	Allowlist    []string // @@||domain^ rules
	RegexBlock   []string // /REGEX/ patterns
	RegexAllow   []string // @@/REGEX/ patterns
	SkipUpdate   bool     // true if content unchanged, caller should skip trie rebuild
}

// ParseRules reads AdGuard-format rules from r and extracts domains.
func ParseRules(r io.Reader) ParseResult {
	var result ParseResult
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Strip surrounding quotes (from Corefile quoting)
		if len(line) >= 2 && ((line[0] == '\'' && line[len(line)-1] == '\'') || (line[0] == '"' && line[len(line)-1] == '"')) {
			line = line[1 : len(line)-1]
		}
		// Comments
		if line[0] == '!' || line[0] == '#' {
			continue
		}

		// @@ exception rules (allowlist)
		if strings.HasPrefix(line, "@@") {
			rest := line[2:]
			// @@/REGEX/
			if strings.HasPrefix(rest, "/") && strings.HasSuffix(rest, "/") && len(rest) > 1 {
				result.RegexAllow = append(result.RegexAllow, rest[1:len(rest)-1])
				continue
			}
			// @@||domain^ or @@|domain^
			if strings.HasPrefix(rest, "||") || (len(rest) > 1 && rest[0] == '|') {
				var domainPart string
				if strings.HasPrefix(rest, "||") {
					domainPart = rest[2:]
				} else {
					domainPart = rest[1:]
				}
				if containsDNSRewrite(rest) {
					continue
				}
				if hasBadfilter(rest) {
					continue
				}
				domain := extractAdblockDomain(domainPart)
				if domain != "" {
					result.Allowlist = append(result.Allowlist, normalizeDomain(domain))
				}
			}
			continue
		}

		// /REGEX/ rules
		if line[0] == '/' && strings.HasSuffix(line, "/") && len(line) > 1 {
			result.RegexBlock = append(result.RegexBlock, line[1:len(line)-1])
			continue
		}

		// Skip $badfilter rules (they disable other rules, not applicable here)
		if hasBadfilter(line) {
			continue
		}

		// Skip $dnsrewrite rules
		if containsDNSRewrite(line) {
			continue
		}

		// ||domain^ adblock rules
		if strings.HasPrefix(line, "||") {
			domain := extractAdblockDomain(line[2:])
			if domain != "" {
				if strings.Contains(domain, "*") {
					// Wildcard: convert to regex
					if re := wildcardToRegex(domain); re != "" {
						result.RegexBlock = append(result.RegexBlock, re)
					}
				} else {
					result.Blocked = append(result.Blocked, normalizeDomain(domain))
				}
			}
			continue
		}

		// Single |domain^ adblock rules (safe search style)
		if line[0] == '|' && !strings.HasPrefix(line, "||") {
			domain := extractAdblockDomain(line[1:])
			if domain != "" {
				if strings.Contains(domain, "*") {
					if re := wildcardToRegex(domain); re != "" {
						result.RegexBlock = append(result.RegexBlock, re)
					}
				} else {
					result.Blocked = append(result.Blocked, normalizeDomain(domain))
				}
			}
			continue
		}

		// Hosts format: 127.0.0.1 domain or 0.0.0.0 domain
		if hostsDomains := parseHostsLine(line); len(hostsDomains) > 0 {
			result.BlockedExact = append(result.BlockedExact, hostsDomains...)
			continue
		}

		// Plain domain rules: .domain^ or domain (without ||)
		// These are less common but appear in some filter lists
		if domain := extractPlainDomain(line); domain != "" {
			result.Blocked = append(result.Blocked, normalizeDomain(domain))
			continue
		}

		// Everything else is ignored (cosmetic rules, unknown modifiers, etc.)
	}
	return result
}

// extractAdblockDomain extracts the domain from an adblock rule.
// Input: "example.com^$options" or "example.com^"
// Output: "example.com"
func extractAdblockDomain(s string) string {
	end := len(s)
	for i, c := range s {
		if c == '^' || c == '$' || c == ' ' || c == '\t' {
			end = i
			break
		}
	}
	domain := s[:end]
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	if !strings.Contains(domain, ".") {
		return ""
	}
	return domain
}

// extractPlainDomain tries to extract a domain from a plain rule (no || prefix).
// Handles: ".domain^", "domain$modifier", "domain"
// Returns empty string if not a valid domain rule.
func extractPlainDomain(line string) string {
	// Must contain at least one dot
	if !strings.Contains(line, ".") {
		return ""
	}
	// Skip lines that look like unknown modifiers or have special chars
	if strings.ContainsAny(line, "*[]{}()|\\") {
		return ""
	}
	// Extract domain: strip leading . and trailing ^/$
	domain := line
	domain = strings.TrimPrefix(domain, ".")
	// Find end of domain
	end := len(domain)
	for i, c := range domain {
		if c == '^' || c == '$' || c == ' ' || c == '\t' {
			end = i
			break
		}
	}
	domain = strings.TrimSpace(domain[:end])
	if domain == "" || !strings.Contains(domain, ".") {
		return ""
	}
	// Reject if it looks like a modifier value
	if strings.HasPrefix(domain, "!") || strings.HasPrefix(domain, "#") {
		return ""
	}
	return domain
}

// containsDNSRewrite checks if a rule line contains $dnsrewrite modifier.
func containsDNSRewrite(line string) bool {
	idx := strings.Index(line, "$")
	if idx < 0 {
		return false
	}
	modifiers := line[idx+1:]
	return strings.Contains(modifiers, "dnsrewrite")
}

// hasBadfilter checks if a rule line contains $badfilter modifier.
func hasBadfilter(line string) bool {
	idx := strings.Index(line, "$")
	if idx < 0 {
		return false
	}
	modifiers := line[idx+1:]
	for _, mod := range strings.Split(modifiers, ",") {
		mod = strings.TrimSpace(mod)
		if mod == "badfilter" {
			return true
		}
	}
	return false
}

// parseHostsLine parses a hosts-format line and returns the domains.
// "127.0.0.1 example.com example.org" -> ["example.com.", "example.org."]
func parseHostsLine(line string) []string {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}
	ip := net.ParseIP(fields[0])
	if ip == nil {
		return nil
	}
	var domains []string
	for _, f := range fields[1:] {
		if f == "" || f[0] == '#' || f[0] == '!' {
			break
		}
		domains = append(domains, normalizeDomain(f))
	}
	return domains
}

// normalizeDomain lowercases and ensures FQDN.
func normalizeDomain(domain string) string {
	return strings.ToLower(dns.Fqdn(domain))
}

// CompileRegexps compiles a slice of regex patterns into compiled regexps.
// Invalid patterns are skipped with a log warning.
func CompileRegexps(patterns []string) []*regexp.Regexp {
	var regexps []*regexp.Regexp
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			log.Warningf("Invalid regexp pattern %q: %v", p, err)
			continue
		}
		regexps = append(regexps, re)
	}
	return regexps
}

// wildcardToRegex converts an adblock wildcard domain to a regex pattern.
// "*serror*.wo.com.cn" -> `^.*serror.*\.wo\.com\.cn$`
func wildcardToRegex(domain string) string {
	var re strings.Builder
	re.WriteString("^")
	for _, c := range strings.ToLower(domain) {
		switch c {
		case '*':
			re.WriteString(".*")
		case '.':
			re.WriteString(`\.`)
		case '+', '(', ')', '[', ']', '{', '}', '?', '^', '$', '|', '\\':
			re.WriteByte('\\')
			re.WriteRune(c)
		default:
			re.WriteRune(c)
		}
	}
	re.WriteString("$")
	pattern := re.String()
	if _, err := regexp.Compile(pattern); err != nil {
		log.Warningf("Invalid wildcard pattern %q -> %q: %v", domain, pattern, err)
		return ""
	}
	return pattern
}

// MatchAny checks if domain matches any of the compiled regexps.
func MatchAny(domain string, regexps []*regexp.Regexp) bool {
	for _, re := range regexps {
		if re.MatchString(domain) {
			return true
		}
	}
	return false
}
