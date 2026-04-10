package scan_test

import (
	"net/http"
	"testing"

	"github.com/stormbane-security/beacon/internal/scan"
)

func makeResp(status int, contentType string, headers map[string][]string) *http.Response {
	h := make(http.Header)
	for k, vals := range headers {
		for _, v := range vals {
			h.Add(k, v)
		}
	}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return &http.Response{
		StatusCode: status,
		Header:     h,
	}
}

func TestSnapshot_CapturesFields(t *testing.T) {
	resp := makeResp(200, "application/json", map[string][]string{
		"X-Custom":   {"value1"},
		"Set-Cookie": {"session=abc123", "lang=en"},
	})
	body := []byte(`{"user":"alice"}`)

	snap := scan.Snapshot(resp, body)

	if snap.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", snap.StatusCode)
	}
	if snap.ContentType != "application/json" {
		t.Errorf("ContentType = %q, want %q", snap.ContentType, "application/json")
	}
	if snap.BodyLen != len(body) {
		t.Errorf("BodyLen = %d, want %d", snap.BodyLen, len(body))
	}
	if snap.Body != string(body) {
		t.Errorf("Body = %q, want %q", snap.Body, string(body))
	}
	if len(snap.SetCookies) != 2 {
		t.Errorf("SetCookies len = %d, want 2", len(snap.SetCookies))
	}
	if snap.BodyHash == "" {
		t.Error("BodyHash should not be empty")
	}
}

func TestSnapshot_TruncatesLargeBody(t *testing.T) {
	resp := makeResp(200, "text/html", nil)
	body := make([]byte, 8192)
	for i := range body {
		body[i] = 'A'
	}

	snap := scan.Snapshot(resp, body)

	if len(snap.Body) != 4096 {
		t.Errorf("Body length = %d, want 4096 (truncated)", len(snap.Body))
	}
	if snap.BodyLen != 8192 {
		t.Errorf("BodyLen = %d, want 8192 (full body length)", snap.BodyLen)
	}
}

func TestSnapshot_NilResponse(t *testing.T) {
	snap := scan.Snapshot(nil, nil)
	if snap.StatusCode != 0 {
		t.Errorf("StatusCode = %d, want 0 for nil response", snap.StatusCode)
	}
}

func TestDiff_IdenticalSnapshots_NotSignificant(t *testing.T) {
	resp := makeResp(200, "text/html", nil)
	body := []byte("hello world")

	a := scan.Snapshot(resp, body)
	b := scan.Snapshot(resp, body)

	dr := scan.Diff(a, b)

	if dr.StatusChanged {
		t.Error("StatusChanged should be false for identical snapshots")
	}
	if dr.BodyChanged {
		t.Error("BodyChanged should be false for identical body")
	}
	if dr.Significant {
		t.Error("Significant should be false for identical snapshots")
	}
	if dr.BodyLenDelta != 0 {
		t.Errorf("BodyLenDelta = %d, want 0", dr.BodyLenDelta)
	}
}

func TestDiff_StatusChanged_IsSignificant(t *testing.T) {
	body := []byte("body")
	a := scan.Snapshot(makeResp(200, "text/html", nil), body)
	b := scan.Snapshot(makeResp(403, "text/html", nil), body)

	dr := scan.Diff(a, b)

	if !dr.StatusChanged {
		t.Error("StatusChanged should be true")
	}
	if !dr.Significant {
		t.Error("Significant should be true when status changes")
	}
}

func TestDiff_ContentTypeChanged_IsSignificant(t *testing.T) {
	body := []byte("body")
	a := scan.Snapshot(makeResp(200, "text/html", nil), body)
	b := scan.Snapshot(makeResp(200, "application/json", nil), body)

	dr := scan.Diff(a, b)

	if !dr.ContentTypeChanged {
		t.Error("ContentTypeChanged should be true")
	}
	if !dr.Significant {
		t.Error("Significant should be true when content type changes")
	}
}

func TestDiff_NewHeaders_IsSignificant(t *testing.T) {
	body := []byte("body")
	a := scan.Snapshot(makeResp(200, "text/html", nil), body)
	b := scan.Snapshot(makeResp(200, "text/html", map[string][]string{
		"X-New-Header": {"surprise"},
	}), body)

	dr := scan.Diff(a, b)

	if len(dr.NewHeaders) == 0 {
		t.Error("NewHeaders should contain the new header")
	}
	if !dr.Significant {
		t.Error("Significant should be true when new headers appear")
	}
}

func TestDiff_NewCookies_IsSignificant(t *testing.T) {
	body := []byte("body")
	a := scan.Snapshot(makeResp(200, "text/html", nil), body)
	b := scan.Snapshot(makeResp(200, "text/html", map[string][]string{
		"Set-Cookie": {"admin=true"},
	}), body)

	dr := scan.Diff(a, b)

	if len(dr.NewCookies) == 0 {
		t.Error("NewCookies should contain the new cookie")
	}
	if !dr.Significant {
		t.Error("Significant should be true when new cookies appear")
	}
}

func TestDiff_LargeBodyChange_IsSignificant(t *testing.T) {
	a := scan.Snapshot(makeResp(200, "text/html", nil), []byte("short"))
	b := scan.Snapshot(makeResp(200, "text/html", nil), []byte("this is a much longer body that exceeds the 5% threshold by a wide margin for significance detection"))

	dr := scan.Diff(a, b)

	if !dr.BodyChanged {
		t.Error("BodyChanged should be true")
	}
	if dr.BodyLenDeltaPct <= 5.0 {
		t.Errorf("BodyLenDeltaPct = %f, expected > 5.0", dr.BodyLenDeltaPct)
	}
	if !dr.Significant {
		t.Error("Significant should be true for large body change")
	}
}

func TestDiff_SmallBodyChange_NotSignificant(t *testing.T) {
	// Two bodies that differ only slightly (< 5% of body length).
	base := make([]byte, 1000)
	for i := range base {
		base[i] = 'A'
	}
	variant := make([]byte, 1010)
	for i := range variant {
		variant[i] = 'A'
	}

	a := scan.Snapshot(makeResp(200, "text/html", nil), base)
	b := scan.Snapshot(makeResp(200, "text/html", nil), variant)

	dr := scan.Diff(a, b)

	if !dr.BodyChanged {
		t.Error("BodyChanged should be true (different hashes)")
	}
	if dr.Significant {
		t.Error("Significant should be false for < 5% body change with same status/headers")
	}
}

func TestDiff_NilSnapshots(t *testing.T) {
	dr := scan.Diff(nil, nil)
	if dr.Significant {
		t.Error("Significant should be false for two nil snapshots")
	}
}
