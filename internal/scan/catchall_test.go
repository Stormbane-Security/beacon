package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectCatchAll_Returns200_IsCatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>SPA index</html>"))
	}))
	defer srv.Close()

	b := DetectCatchAll(t.Context(), srv.Client(), srv.URL)
	if !b.IsCatchAll {
		t.Fatal("expected IsCatchAll=true for server returning 200 on random path")
	}
	if b.StatusCode != 200 {
		t.Errorf("expected StatusCode=200, got %d", b.StatusCode)
	}
	if b.BodyLen != len("<html>SPA index</html>") {
		t.Errorf("expected BodyLen=%d, got %d", len("<html>SPA index</html>"), b.BodyLen)
	}
}

func TestDetectCatchAll_Returns404_NotCatchAll(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	b := DetectCatchAll(t.Context(), srv.Client(), srv.URL)
	if b.IsCatchAll {
		t.Fatal("expected IsCatchAll=false for server returning 404")
	}
}

func TestIsDifferentFromBaseline_NotCatchAll_AlwaysTrue(t *testing.T) {
	b := &CatchAllBaseline{IsCatchAll: false}
	if !b.IsDifferentFromBaseline(&http.Response{StatusCode: 200}, []byte("anything")) {
		t.Error("non-catch-all baseline should always report different")
	}
}

func TestIsDifferentFromBaseline_SameResponse_False(t *testing.T) {
	body := []byte("<html>SPA index</html>")
	hash := sha256.Sum256(body)

	b := &CatchAllBaseline{
		IsCatchAll: true,
		StatusCode: 200,
		BodyHash:   hex.EncodeToString(hash[:]),
		BodyLen:    len(body),
		Headers:    map[string]string{"Content-Type": "text/html"},
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}

	if b.IsDifferentFromBaseline(resp, body) {
		t.Error("identical response should not be flagged as different")
	}
}

func TestIsDifferentFromBaseline_DifferentStatus_True(t *testing.T) {
	body := []byte("<html>SPA index</html>")
	hash := sha256.Sum256(body)

	b := &CatchAllBaseline{
		IsCatchAll: true,
		StatusCode: 200,
		BodyHash:   hex.EncodeToString(hash[:]),
		BodyLen:    len(body),
		Headers:    map[string]string{},
	}

	resp := &http.Response{
		StatusCode: 302,
		Header:     http.Header{},
	}

	if !b.IsDifferentFromBaseline(resp, body) {
		t.Error("different status code should be flagged as different")
	}
}

func TestIsDifferentFromBaseline_DifferentBody_True(t *testing.T) {
	baseBody := []byte("<html>SPA index</html>")
	hash := sha256.Sum256(baseBody)

	b := &CatchAllBaseline{
		IsCatchAll: true,
		StatusCode: 200,
		BodyHash:   hex.EncodeToString(hash[:]),
		BodyLen:    len(baseBody),
		Headers:    map[string]string{},
	}

	differentBody := []byte(`{"user":"admin","token":"abc123"}`)
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
	}

	if !b.IsDifferentFromBaseline(resp, differentBody) {
		t.Error("different body content should be flagged as different")
	}
}

func TestIsDifferentFromBaseline_NewSetCookie_True(t *testing.T) {
	body := []byte("<html>SPA index</html>")
	hash := sha256.Sum256(body)

	b := &CatchAllBaseline{
		IsCatchAll: true,
		StatusCode: 200,
		BodyHash:   hex.EncodeToString(hash[:]),
		BodyLen:    len(body),
		Headers:    map[string]string{}, // no cookies in baseline
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Set-Cookie": []string{"session=abc123; Path=/"}},
	}

	if !b.IsDifferentFromBaseline(resp, body) {
		t.Error("new Set-Cookie header should be flagged as different")
	}
}

func TestIsDifferentFromBaseline_DifferentContentType_True(t *testing.T) {
	body := []byte("<html>SPA index</html>")
	hash := sha256.Sum256(body)

	b := &CatchAllBaseline{
		IsCatchAll: true,
		StatusCode: 200,
		BodyHash:   hex.EncodeToString(hash[:]),
		BodyLen:    len(body),
		Headers:    map[string]string{"Content-Type": "text/html"},
	}

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}

	if !b.IsDifferentFromBaseline(resp, body) {
		t.Error("different Content-Type should be flagged as different")
	}
}
