// Package scan — response diffing engine.
//
// Diff compares two HTTP response snapshots to detect meaningful differences.
// Used by IDOR, privesc, access control, and second-order injection scanners
// to determine whether different inputs produce meaningfully different outputs.
package scan

import (
	"crypto/sha256"
	"fmt"
	"math"
	"net/http"
)

const maxSnapshotBody = 4096 // first 4 KB stored for content comparison

// ResponseSnapshot captures the significant characteristics of an HTTP
// response for later comparison. Create via Snapshot().
type ResponseSnapshot struct {
	StatusCode  int
	BodyHash    string            // SHA-256 hex digest of full body
	BodyLen     int               // full body length
	ContentType string
	Headers     map[string]string // canonicalized header key → first value
	SetCookies  []string          // raw Set-Cookie header values
	Body        string            // first 4 KB for content comparison
}

// Snapshot captures response characteristics from an HTTP response and its
// already-read body bytes. The caller is responsible for reading and closing
// the response body before calling Snapshot.
func Snapshot(resp *http.Response, body []byte) *ResponseSnapshot {
	if resp == nil {
		return &ResponseSnapshot{}
	}

	h := sha256.Sum256(body)

	headers := make(map[string]string, len(resp.Header))
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}

	setCookies := append([]string{}, resp.Header["Set-Cookie"]...)

	bodySnippet := string(body)
	if len(bodySnippet) > maxSnapshotBody {
		bodySnippet = bodySnippet[:maxSnapshotBody]
	}

	return &ResponseSnapshot{
		StatusCode:  resp.StatusCode,
		BodyHash:    fmt.Sprintf("%x", h),
		BodyLen:     len(body),
		ContentType: resp.Header.Get("Content-Type"),
		Headers:     headers,
		SetCookies:  setCookies,
		Body:        bodySnippet,
	}
}

// DiffResult describes the meaningful differences between two response snapshots.
type DiffResult struct {
	StatusChanged      bool     // status codes differ
	BodyChanged        bool     // body hashes differ
	BodyLenDelta       int      // absolute difference in body length
	BodyLenDeltaPct    float64  // percentage change relative to snapshot A
	ContentTypeChanged bool     // Content-Type headers differ
	NewHeaders         []string // headers present in B but absent in A
	NewCookies         []string // Set-Cookie values in B but not in A
	Significant        bool     // true if any change is likely meaningful
}

// Diff compares two snapshots and returns meaningful differences.
// A nil snapshot is treated as an empty response.
func Diff(a, b *ResponseSnapshot) *DiffResult {
	if a == nil {
		a = &ResponseSnapshot{}
	}
	if b == nil {
		b = &ResponseSnapshot{}
	}

	dr := &DiffResult{}

	// Status code comparison.
	dr.StatusChanged = a.StatusCode != b.StatusCode

	// Body hash comparison.
	dr.BodyChanged = a.BodyHash != b.BodyHash

	// Body length delta.
	dr.BodyLenDelta = abs(b.BodyLen - a.BodyLen)
	if a.BodyLen > 0 {
		dr.BodyLenDeltaPct = float64(dr.BodyLenDelta) / float64(a.BodyLen) * 100.0
	} else if b.BodyLen > 0 {
		dr.BodyLenDeltaPct = 100.0 // went from 0 to something
	}

	// Content-Type comparison.
	dr.ContentTypeChanged = a.ContentType != b.ContentType

	// New headers: in B but not A.
	for k := range b.Headers {
		if _, ok := a.Headers[k]; !ok {
			dr.NewHeaders = append(dr.NewHeaders, k)
		}
	}

	// New cookies: Set-Cookie values in B but not A.
	aCookies := make(map[string]bool, len(a.SetCookies))
	for _, c := range a.SetCookies {
		aCookies[c] = true
	}
	for _, c := range b.SetCookies {
		if !aCookies[c] {
			dr.NewCookies = append(dr.NewCookies, c)
		}
	}

	// Determine significance: any of these changes suggest a meaningful
	// difference rather than cosmetic variation (timestamps, CSRF tokens, etc.).
	dr.Significant = dr.StatusChanged ||
		dr.ContentTypeChanged ||
		len(dr.NewHeaders) > 0 ||
		len(dr.NewCookies) > 0 ||
		(dr.BodyChanged && dr.BodyLenDeltaPct > 5.0)

	return dr
}

func abs(n int) int {
	return int(math.Abs(float64(n)))
}
