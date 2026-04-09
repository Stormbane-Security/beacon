// Package wafbypass provides a WAF-adaptive payload encoding engine.
// When a WAF blocks an injection payload, the engine automatically retries
// with encoding variants (double URL encoding, Unicode, HTML entities,
// comment insertion, etc.) to find a technique that bypasses the filter.
package wafbypass

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net/url"
	"strings"
	"unicode"
)

// Encoder transforms a payload using a specific bypass technique.
type Encoder struct {
	Name        string
	Description string
	Encode      func(payload string) string
}

// EncodedPayload pairs an encoded variant with metadata about how it was produced.
type EncodedPayload struct {
	Original string
	Encoded  string
	Encoder  string // which encoder was used
}

// AllEncoders returns all available WAF bypass encoders.
func AllEncoders() []Encoder {
	return []Encoder{
		{
			Name:        "double_url_encode",
			Description: "Double URL-encodes every byte so WAF decodes once but backend decodes twice",
			Encode:      encodeDoubleURL,
		},
		{
			Name:        "unicode_escape",
			Description: "Replaces angle brackets and quotes with JavaScript Unicode escapes (\\u00XX)",
			Encode:      encodeUnicodeEscape,
		},
		{
			Name:        "html_entity",
			Description: "Replaces <, >, \", ' with HTML numeric character references",
			Encode:      encodeHTMLEntity,
		},
		{
			Name:        "mixed_case",
			Description: "Randomly alternates upper/lower case to bypass case-sensitive pattern matching",
			Encode:      encodeMixedCase,
		},
		{
			Name:        "null_byte",
			Description: "Prepends a URL-encoded null byte (%00) to break WAF string matching",
			Encode:      encodeNullByte,
		},
		{
			Name:        "sql_comment",
			Description: "Inserts inline SQL comments (/**/) between SQL keywords",
			Encode:      encodeSQLComment,
		},
		{
			Name:        "whitespace_sub",
			Description: "Replaces spaces with alternative whitespace: tabs, newlines, inline SQL comments",
			Encode:      encodeWhitespaceSub,
		},
		{
			Name:        "json_smuggle",
			Description: "Wraps payload in a JSON object body for Content-Type: application/json delivery",
			Encode:      encodeJSONSmuggle,
		},
		{
			Name:        "multipart_wrap",
			Description: "Wraps payload in a multipart/form-data body to bypass URL-encoded body inspection",
			Encode:      encodeMultipartWrap,
		},
		{
			Name:        "param_pollution",
			Description: "Duplicates the parameter with a clean value first and payload second",
			Encode:      encodeParamPollution,
		},
		{
			Name:        "sql_case_variation",
			Description: "Alternates case on SQL keywords (sElEcT, UnIoN) to bypass keyword matching",
			Encode:      encodeSQLCaseVariation,
		},
		{
			Name:        "hex_encode_sql",
			Description: "Replaces single quotes and other SQL-sensitive characters with hex (0x27)",
			Encode:      encodeHexSQL,
		},
	}
}

// EncodePayload returns all encoded variants of a payload.
func EncodePayload(payload string) []EncodedPayload {
	var results []EncodedPayload
	for _, enc := range AllEncoders() {
		encoded := enc.Encode(payload)
		if encoded != payload {
			results = append(results, EncodedPayload{
				Original: payload,
				Encoded:  encoded,
				Encoder:  enc.Name,
			})
		}
	}
	return results
}

// ── Encoder implementations ─────────────────────────────────────────────────

// encodeDoubleURL double-URL-encodes every byte: ' → %27 → %2527
func encodeDoubleURL(payload string) string {
	first := url.QueryEscape(payload)
	return url.QueryEscape(first)
}

// encodeUnicodeEscape replaces <, >, ', " with \uXXXX escapes.
func encodeUnicodeEscape(payload string) string {
	replacer := strings.NewReplacer(
		"<", `\u003c`,
		">", `\u003e`,
		"'", `\u0027`,
		`"`, `\u0022`,
	)
	return replacer.Replace(payload)
}

// encodeHTMLEntity replaces <, >, ', " with HTML numeric entities.
func encodeHTMLEntity(payload string) string {
	replacer := strings.NewReplacer(
		"<", "&#60;",
		">", "&#62;",
		"'", "&#39;",
		`"`, "&#34;",
	)
	return replacer.Replace(payload)
}

// encodeMixedCase alternates character case deterministically (odd=upper, even=lower).
func encodeMixedCase(payload string) string {
	var b strings.Builder
	i := 0
	for _, c := range payload {
		if unicode.IsLetter(c) {
			if i%2 == 0 {
				b.WriteRune(unicode.ToUpper(c))
			} else {
				b.WriteRune(unicode.ToLower(c))
			}
			i++
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// encodeNullByte prepends a URL-encoded null byte.
func encodeNullByte(payload string) string {
	return "%00" + payload
}

// encodeSQLComment inserts /**/ between characters of SQL keywords.
var sqlKeywords = []string{
	"UNION", "SELECT", "INSERT", "UPDATE", "DELETE", "FROM", "WHERE",
	"AND", "OR", "ORDER", "GROUP", "HAVING", "LIMIT", "DROP", "ALTER",
	"SLEEP", "WAITFOR", "BENCHMARK", "CONCAT", "LOAD_FILE",
}

func encodeSQLComment(payload string) string {
	upper := strings.ToUpper(payload)
	result := payload
	for _, kw := range sqlKeywords {
		idx := strings.Index(strings.ToUpper(result), kw)
		if idx < 0 {
			continue
		}
		// Build commented version: UN/**/ION
		original := result[idx : idx+len(kw)]
		if len(original) < 3 {
			continue
		}
		mid := len(original) / 2
		commented := original[:mid] + "/**/" + original[mid:]
		result = result[:idx] + commented + result[idx+len(kw):]
	}
	_ = upper
	return result
}

// encodeWhitespaceSub replaces spaces with tab, newline, or SQL comment alternatives.
func encodeWhitespaceSub(payload string) string {
	alternatives := []string{"\t", "\n", "/**/"}
	var b strings.Builder
	i := 0
	for _, c := range payload {
		if c == ' ' {
			b.WriteString(alternatives[i%len(alternatives)])
			i++
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// encodeJSONSmuggle wraps the payload in a JSON body.
func encodeJSONSmuggle(payload string) string {
	// Escape payload for JSON string value
	escaped := strings.ReplaceAll(payload, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return fmt.Sprintf(`{"q":"%s"}`, escaped)
}

// encodeMultipartWrap wraps the payload in a multipart/form-data body.
func encodeMultipartWrap(payload string) string {
	boundary := "----BeaconBoundary" + fmt.Sprintf("%08x", rand.Int31()) // #nosec G404 -- boundary randomness for WAF bypass, not crypto
	return fmt.Sprintf("--%s\r\nContent-Disposition: form-data; name=\"q\"\r\n\r\n%s\r\n--%s--", boundary, payload, boundary)
}

// encodeParamPollution duplicates the parameter: clean value first, payload second.
func encodeParamPollution(payload string) string {
	return "q=harmless&q=" + url.QueryEscape(payload)
}

// encodeSQLCaseVariation alternates case on SQL keywords.
func encodeSQLCaseVariation(payload string) string {
	result := payload
	for _, kw := range sqlKeywords {
		idx := strings.Index(strings.ToUpper(result), kw)
		if idx < 0 {
			continue
		}
		original := result[idx : idx+len(kw)]
		varied := alternateCase(original)
		result = result[:idx] + varied + result[idx+len(kw):]
	}
	return result
}

// alternateCase produces sElEcT-style case alternation.
func alternateCase(s string) string {
	var b strings.Builder
	for i, c := range s {
		if i%2 == 0 {
			b.WriteRune(unicode.ToLower(c))
		} else {
			b.WriteRune(unicode.ToUpper(c))
		}
	}
	return b.String()
}

// encodeHexSQL replaces ' with 0x27 hex notation for SQL injection contexts.
func encodeHexSQL(payload string) string {
	var b strings.Builder
	for _, c := range payload {
		switch c {
		case '\'':
			b.WriteString("0x" + hex.EncodeToString([]byte{byte(c)}))
		case '"':
			b.WriteString("0x" + hex.EncodeToString([]byte{byte(c)}))
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}
