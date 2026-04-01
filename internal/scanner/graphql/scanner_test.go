package graphql

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
)

// --- checkIntrospection ---

func TestCheckIntrospection_SchemaInResponse_ReturnsTrue(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"__schema":{"types":[{"name":"Query"}]}}}`))
	}))
	defer ts.Close()

	exposed, snippet := checkIntrospection(context.Background(), ts.Client(), ts.URL)
	if !exposed {
		t.Error("expected introspection to be detected")
	}
	if snippet == "" {
		t.Error("expected a non-empty body snippet")
	}
}

func TestCheckIntrospection_NoSchemaInResponse_ReturnsFalse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Introspection disabled — server returns a data response without __schema
		w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer ts.Close()

	exposed, _ := checkIntrospection(context.Background(), ts.Client(), ts.URL)
	if exposed {
		t.Error("should not detect introspection when __schema is absent")
	}
}

func TestCheckIntrospection_Non200Status_ReturnsFalse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	exposed, _ := checkIntrospection(context.Background(), ts.Client(), ts.URL)
	if exposed {
		t.Error("should not detect introspection on non-200 response")
	}
}

func TestCheckIntrospection_ServerUnreachable_ReturnsFalse(t *testing.T) {
	// Port 1 always refuses connections
	exposed, _ := checkIntrospection(context.Background(), &http.Client{}, "http://127.0.0.1:1/graphql")
	if exposed {
		t.Error("should not detect introspection when server is unreachable")
	}
}

func TestCheckIntrospection_ContextCancelled_ReturnsFalse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"__schema":{}}}`))
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	exposed, _ := checkIntrospection(ctx, ts.Client(), ts.URL)
	if exposed {
		t.Error("should not detect introspection with cancelled context")
	}
}

// --- isGraphQLEndpoint ---

func TestIsGraphQLEndpoint_DataAndTypenameInResponse_ReturnsTrue(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer ts.Close()

	if !isGraphQLEndpoint(context.Background(), ts.Client(), ts.URL) {
		t.Error("expected endpoint to be identified as GraphQL")
	}
}

func TestIsGraphQLEndpoint_OnlyDataKey_ReturnsFalse(t *testing.T) {
	// REST API that happens to return a "data" key — should not be flagged
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"id":1,"name":"Alice"}}`))
	}))
	defer ts.Close()

	if isGraphQLEndpoint(context.Background(), ts.Client(), ts.URL) {
		t.Error("REST endpoint with 'data' key but no '__typename' should not match")
	}
}

func TestIsGraphQLEndpoint_Non200Status_ReturnsFalse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer ts.Close()

	if isGraphQLEndpoint(context.Background(), ts.Client(), ts.URL) {
		t.Error("non-200 status should not be identified as GraphQL endpoint")
	}
}

// --- checkBatchQuery ---

func TestCheckBatchQuery_ArrayResponse_FindingEmitted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Return a JSON array — signals batch support
		w.Write([]byte(`[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`))
	}))
	defer ts.Close()

	f := checkBatchQuery(context.Background(), ts.Client(), "example.com", ts.URL)
	if f == nil {
		t.Fatal("expected a batch query finding, got nil")
	}
	if f.CheckID != finding.CheckGraphQLBatchQuery {
		t.Errorf("expected CheckGraphQLBatchQuery, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected Medium severity, got %v", f.Severity)
	}
}

func TestCheckBatchQuery_ObjectResponse_NoFinding(t *testing.T) {
	// Server returns a single JSON object — no batch support
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer ts.Close()

	f := checkBatchQuery(context.Background(), ts.Client(), "example.com", ts.URL)
	if f != nil {
		t.Errorf("expected no finding for single-object response, got %+v", f)
	}
}

func TestCheckBatchQuery_Non200Status_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	f := checkBatchQuery(context.Background(), ts.Client(), "example.com", ts.URL)
	if f != nil {
		t.Errorf("expected no finding on non-200 status, got %+v", f)
	}
}

// --- checkPersistedQueryBypass ---

func TestCheckPersistedQueryBypass_ExecutesQueryOnMiss_FindingEmitted(t *testing.T) {
	// Misconfigured server: executes the query even on APQ cache miss
	// (returns "data" instead of PersistedQueryNotFound)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data":{"__typename":"Query"}}`))
	}))
	defer ts.Close()

	f := checkPersistedQueryBypass(context.Background(), ts.Client(), "example.com", ts.URL)
	if f == nil {
		t.Fatal("expected APQ bypass finding, got nil")
	}
	if f.CheckID != finding.CheckGraphQLPersistedQueryBypass {
		t.Errorf("expected CheckGraphQLPersistedQueryBypass, got %s", f.CheckID)
	}
}

func TestCheckPersistedQueryBypass_ReturnsPersistedQueryNotFound_NoFinding(t *testing.T) {
	// Correctly implemented APQ server — returns the expected error
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"errors":[{"message":"PersistedQueryNotFound"}]}`))
	}))
	defer ts.Close()

	f := checkPersistedQueryBypass(context.Background(), ts.Client(), "example.com", ts.URL)
	if f != nil {
		t.Errorf("expected no finding when server returns PersistedQueryNotFound, got %+v", f)
	}
}

func TestCheckPersistedQueryBypass_NoDataKey_NoFinding(t *testing.T) {
	// Server returns 200 but no "data" field — ambiguous, should not fire
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	f := checkPersistedQueryBypass(context.Background(), ts.Client(), "example.com", ts.URL)
	if f != nil {
		t.Errorf("expected no finding when response has no 'data' key, got %+v", f)
	}
}

func TestCheckPersistedQueryBypass_Non200Status_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	f := checkPersistedQueryBypass(context.Background(), ts.Client(), "example.com", ts.URL)
	if f != nil {
		t.Errorf("expected no finding on non-200 status, got %+v", f)
	}
}

// --- randomSHA256Hex ---

func TestRandomSHA256Hex_Length(t *testing.T) {
	h := randomSHA256Hex()
	if len(h) != 64 {
		t.Errorf("expected 64-char hex string, got length %d: %q", len(h), h)
	}
}

func TestRandomSHA256Hex_IsHex(t *testing.T) {
	h := randomSHA256Hex()
	for _, c := range h {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("non-hex character %q in hash %q", c, h)
		}
	}
}

func TestRandomSHA256Hex_Uniqueness(t *testing.T) {
	// Two successive calls must produce different hashes (collision prob ~2^-256)
	a, b := randomSHA256Hex(), randomSHA256Hex()
	if a == b {
		t.Errorf("two successive random hashes are identical: %q", a)
	}
}

func TestRandomSHA256Hex_NotAllZeros(t *testing.T) {
	h := randomSHA256Hex()
	if h == strings.Repeat("0", 64) {
		t.Error("random hash should not be all zeros")
	}
}

// --- checkBatchQuery — non-GraphQL JSON array ---

func TestCheckBatchQuery_NonGraphQLJSONArray_NoFinding(t *testing.T) {
	// Server returns a valid JSON array, but elements don't contain "data" or
	// "errors" keys — this is a generic REST response, not a GraphQL batch.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"name":"foo"},{"name":"bar"}]`))
	}))
	defer ts.Close()

	f := checkBatchQuery(context.Background(), ts.Client(), "example.com", ts.URL)
	if f != nil {
		t.Errorf("expected no finding for non-GraphQL JSON array, got %+v", f)
	}
}

func TestCheckBatchQuery_EmptyJSONArray_NoFinding(t *testing.T) {
	// Server returns an empty JSON array.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[]`))
	}))
	defer ts.Close()

	f := checkBatchQuery(context.Background(), ts.Client(), "example.com", ts.URL)
	if f != nil {
		t.Errorf("expected no finding for empty JSON array, got %+v", f)
	}
}

func TestCheckBatchQuery_ArrayWithErrorsKey_FindingEmitted(t *testing.T) {
	// Server returns a JSON array where elements have "errors" — this is a
	// valid GraphQL batch error response and should produce a finding.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"errors":[{"message":"not authorized"}]},{"errors":[{"message":"not authorized"}]}]`))
	}))
	defer ts.Close()

	f := checkBatchQuery(context.Background(), ts.Client(), "example.com", ts.URL)
	if f == nil {
		t.Fatal("expected a batch query finding for array with 'errors' keys, got nil")
	}
	if f.CheckID != finding.CheckGraphQLBatchQuery {
		t.Errorf("expected CheckGraphQLBatchQuery, got %s", f.CheckID)
	}
}

// ---------------------------------------------------------------------------
// Edge: introspection disabled — server returns error/400 on introspection query.
// Scanner must not emit a false positive.
// ---------------------------------------------------------------------------

func TestGraphQLIntrospectionDisabled(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"errors":[{"message":"Introspection is not allowed"}]}`))
	}))
	defer ts.Close()

	exposed, snippet := checkIntrospection(context.Background(), ts.Client(), ts.URL)
	if exposed {
		t.Error("expected introspection NOT detected when server returns 400 error")
	}
	if snippet != "" {
		t.Errorf("expected empty snippet when introspection is disabled, got %q", snippet)
	}
}

// ---------------------------------------------------------------------------
// Edge: truncated JSON response — scanner must not panic
// ---------------------------------------------------------------------------

func TestGraphQLTruncatedResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Truncated JSON: "__schema" is present as a string but the JSON is incomplete.
		w.Write([]byte(`{"data":{"__schema":{"types":[{"name":"Qu`))
	}))
	defer ts.Close()

	// Must not panic. The function may or may not detect introspection depending
	// on whether __schema substring match is enough, but the key assertion is
	// no crash.
	exposed, snippet := checkIntrospection(context.Background(), ts.Client(), ts.URL)
	// Even with truncated JSON, the string "__schema" IS present, so the scanner
	// may detect it as exposed. What matters is it doesn't panic.
	_ = exposed
	_ = snippet
}

// ---------------------------------------------------------------------------
// Edge: checkBatchQuery with truncated/invalid JSON — no panic
// ---------------------------------------------------------------------------

func TestCheckBatchQuery_TruncatedJSON_NoPanic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"data":{"__typename":"Qu`)) // truncated
	}))
	defer ts.Close()

	// Must not panic on invalid JSON.
	f := checkBatchQuery(context.Background(), ts.Client(), "example.com", ts.URL)
	_ = f
}

// ---------------------------------------------------------------------------
// Edge: checkIntrospection with 200 but HTML body (not JSON) — no false positive
// ---------------------------------------------------------------------------

func TestCheckIntrospection_HTMLResponse_ReturnsFalse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body>Not a GraphQL endpoint</body></html>`))
	}))
	defer ts.Close()

	exposed, _ := checkIntrospection(context.Background(), ts.Client(), ts.URL)
	if exposed {
		t.Error("should not detect introspection on HTML response")
	}
}

// Note: Run() cannot be integration-tested at this layer because isHTTPReachable()
// requires the target to accept TCP connections on port 80 or 443. Binding to those
// ports requires privilege and is not feasible in unit tests. All detection logic is
// covered via the helper function tests above (checkIntrospection, checkBatchQuery,
// checkPersistedQueryBypass).
