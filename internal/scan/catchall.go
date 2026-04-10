// Package scan — catch-all baseline detection for servers that return 200 for
// all paths (e.g. SPAs). Instead of bailing entirely, scanners can compare
// responses against the baseline to distinguish real content from the default
// catch-all page.
package scan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
)

// CatchAllBaseline stores the baseline response for a catch-all server.
// When a server returns 200 for nonexistent paths, this lets scanners
// distinguish real responses from the default catch-all page.
type CatchAllBaseline struct {
	IsCatchAll bool
	StatusCode int
	BodyHash   string            // SHA256 of response body
	BodyLen    int               // length of the body in bytes
	Headers    map[string]string // key response headers (Content-Type, Set-Cookie, Location)
}

// keyHeaders are the response headers that are significant when comparing
// a response against the catch-all baseline.
var keyHeaders = []string{"Content-Type", "Set-Cookie", "Location"}

// DetectCatchAll probes the server with a random path and returns a baseline.
// If the server returns 200, IsCatchAll is true and the baseline captures
// the default response signature.
func DetectCatchAll(ctx context.Context, client *http.Client, baseURL string) *CatchAllBaseline {
	// Generate a random path that cannot exist on any real server.
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	probePath := fmt.Sprintf("/beacon-catchall-%s-doesnotexist", hex.EncodeToString(buf[:]))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+probePath, nil)
	if err != nil {
		return &CatchAllBaseline{IsCatchAll: false}
	}
	resp, err := client.Do(req)
	if err != nil {
		return &CatchAllBaseline{IsCatchAll: false}
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	hash := sha256.Sum256(body)

	headers := make(map[string]string)
	for _, h := range keyHeaders {
		if v := resp.Header.Get(h); v != "" {
			headers[h] = v
		}
	}

	return &CatchAllBaseline{
		IsCatchAll: resp.StatusCode == http.StatusOK,
		StatusCode: resp.StatusCode,
		BodyHash:   hex.EncodeToString(hash[:]),
		BodyLen:    len(body),
		Headers:    headers,
	}
}

// IsDifferentFromBaseline returns true if the given response differs
// meaningfully from the catch-all baseline. Differences checked:
//   - Different HTTP status code
//   - Different body SHA256 hash
//   - Body length differs by more than 10%
//   - Key headers (Content-Type, Set-Cookie, Location) differ
//
// If the baseline is not a catch-all server, this always returns true
// (all responses are "different" from a non-catch-all baseline).
func (b *CatchAllBaseline) IsDifferentFromBaseline(resp *http.Response, body []byte) bool {
	if !b.IsCatchAll {
		return true
	}

	// Different status code → definitely different.
	if resp.StatusCode != b.StatusCode {
		return true
	}

	// Different body hash → different content.
	hash := sha256.Sum256(body)
	if hex.EncodeToString(hash[:]) != b.BodyHash {
		return true
	}

	// Body length differs by >10%.
	if b.BodyLen > 0 {
		ratio := math.Abs(float64(len(body)-b.BodyLen)) / float64(b.BodyLen)
		if ratio > 0.10 {
			return true
		}
	}

	// Key header differences.
	for _, h := range keyHeaders {
		respVal := resp.Header.Get(h)
		baseVal := b.Headers[h]
		// For Set-Cookie: any cookie present when baseline had none is significant.
		if h == "Set-Cookie" {
			if baseVal == "" && respVal != "" {
				return true
			}
			if baseVal != "" && respVal == "" {
				return true
			}
			// Compare case-insensitively ignoring values that change per-request
			// (like session IDs). If the cookie name differs, it's significant.
			if !strings.EqualFold(cookieName(baseVal), cookieName(respVal)) {
				return true
			}
			continue
		}
		if !strings.EqualFold(baseVal, respVal) {
			return true
		}
	}

	return false
}

// cookieName extracts the cookie name (everything before '=') from a
// Set-Cookie header value.
func cookieName(setCookie string) string {
	if i := strings.IndexByte(setCookie, '='); i >= 0 {
		return setCookie[:i]
	}
	return setCookie
}
