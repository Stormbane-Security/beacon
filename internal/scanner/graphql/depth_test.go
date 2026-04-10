package graphql

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
)

// ---------------------------------------------------------------------------
// TestDepthAttack
// ---------------------------------------------------------------------------

func TestTestDepthAttack_NoDepthLimit_Vulnerable(t *testing.T) {
	// Server accepts deeply nested queries and returns data.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"__type":{"fields":[{"type":{"fields":[{"type":{"name":"String"}}]}}]}}}`))
	}))
	defer ts.Close()

	result := TestDepthAttack(context.Background(), ts.Client(), ts.URL)
	if !result.Vulnerable {
		t.Error("expected Vulnerable=true when server accepts deep nesting")
	}
	if result.DepthSent != 20 {
		t.Errorf("expected DepthSent=20, got %d", result.DepthSent)
	}
}

func TestTestDepthAttack_DepthLimitEnforced_NotVulnerable(t *testing.T) {
	// Server rejects deep queries with a depth limit error.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Query depth limit of 10 exceeded"}]}`))
	}))
	defer ts.Close()

	result := TestDepthAttack(context.Background(), ts.Client(), ts.URL)
	if result.Vulnerable {
		t.Error("expected Vulnerable=false when server enforces depth limit")
	}
}

func TestTestDepthAttack_ServerError_NotVulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	result := TestDepthAttack(context.Background(), ts.Client(), ts.URL)
	if result.Vulnerable {
		t.Error("expected Vulnerable=false on server error")
	}
}

func TestTestDepthAttack_NullData_NotVulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	defer ts.Close()

	result := TestDepthAttack(context.Background(), ts.Client(), ts.URL)
	if result.Vulnerable {
		t.Error("expected Vulnerable=false when data is null")
	}
}

// ---------------------------------------------------------------------------
// TestAliasAttack
// ---------------------------------------------------------------------------

func TestTestAliasAttack_NoAliasLimit_Vulnerable(t *testing.T) {
	// Server resolves all 1000 aliases.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var sb strings.Builder
		sb.WriteString(`{"data":{`)
		for i := range 1000 {
			if i > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `"a%d":"Query"`, i)
		}
		sb.WriteString(`}}`)
		_, _ = w.Write([]byte(sb.String()))
	}))
	defer ts.Close()

	result := TestAliasAttack(context.Background(), ts.Client(), ts.URL)
	if !result.Vulnerable {
		t.Error("expected Vulnerable=true when server resolves all 1000 aliases")
	}
	if result.AliasesResolved != 1000 {
		t.Errorf("expected AliasesResolved=1000, got %d", result.AliasesResolved)
	}
}

func TestTestAliasAttack_AliasLimitEnforced_NotVulnerable(t *testing.T) {
	// Server only resolves 10 aliases out of 1000.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var sb strings.Builder
		sb.WriteString(`{"data":{`)
		for i := range 10 {
			if i > 0 {
				sb.WriteString(",")
			}
			fmt.Fprintf(&sb, `"a%d":"Query"`, i)
		}
		sb.WriteString(`}}`)
		_, _ = w.Write([]byte(sb.String()))
	}))
	defer ts.Close()

	result := TestAliasAttack(context.Background(), ts.Client(), ts.URL)
	if result.Vulnerable {
		t.Error("expected Vulnerable=false when server limits aliases")
	}
}

func TestTestAliasAttack_ServerRejectsRequest_NotVulnerable(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	result := TestAliasAttack(context.Background(), ts.Client(), ts.URL)
	if result.Vulnerable {
		t.Error("expected Vulnerable=false on 400 response")
	}
}

// ---------------------------------------------------------------------------
// TestBatchAttack
// ---------------------------------------------------------------------------

func TestTestBatchAttack_NoBatchLimit_Vulnerable(t *testing.T) {
	// Server processes all 100 queries in the batch.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var sb strings.Builder
		sb.WriteString("[")
		for i := range 100 {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`{"data":{"__typename":"Query"}}`)
		}
		sb.WriteString("]")
		_, _ = w.Write([]byte(sb.String()))
	}))
	defer ts.Close()

	result := TestBatchAttack(context.Background(), ts.Client(), ts.URL)
	if !result.Vulnerable {
		t.Error("expected Vulnerable=true when server processes all 100 queries")
	}
	if result.QueriesProcessed != 100 {
		t.Errorf("expected QueriesProcessed=100, got %d", result.QueriesProcessed)
	}
}

func TestTestBatchAttack_BatchLimitEnforced_NotVulnerable(t *testing.T) {
	// Server only processes 5 out of 100 queries.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var sb strings.Builder
		sb.WriteString("[")
		for i := range 5 {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`{"data":{"__typename":"Query"}}`)
		}
		sb.WriteString("]")
		_, _ = w.Write([]byte(sb.String()))
	}))
	defer ts.Close()

	result := TestBatchAttack(context.Background(), ts.Client(), ts.URL)
	if result.Vulnerable {
		t.Error("expected Vulnerable=false when server limits batch to 5")
	}
}

func TestTestBatchAttack_NonArrayResponse_NotVulnerable(t *testing.T) {
	// Server returns a single object — no batch support.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Batch queries not supported"}]}`))
	}))
	defer ts.Close()

	result := TestBatchAttack(context.Background(), ts.Client(), ts.URL)
	if result.Vulnerable {
		t.Error("expected Vulnerable=false for non-array response")
	}
}

// ---------------------------------------------------------------------------
// checkNoDepthLimit integration
// ---------------------------------------------------------------------------

func TestCheckNoDepthLimit_Vulnerable_FindingEmitted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":{"__type":{"fields":[{"type":{"name":"String"}}]}}}`))
	}))
	defer ts.Close()

	f := checkNoDepthLimit(context.Background(), ts.Client(), "example.com", ts.URL)
	if f == nil {
		t.Fatal("expected finding for no depth limit, got nil")
	}
	if f.CheckID != finding.CheckGraphQLNoDepthLimit {
		t.Errorf("expected CheckGraphQLNoDepthLimit, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityMedium {
		t.Errorf("expected Medium severity, got %v", f.Severity)
	}
}

func TestCheckNoDepthLimit_Protected_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Query exceeds maximum depth limit"}]}`))
	}))
	defer ts.Close()

	f := checkNoDepthLimit(context.Background(), ts.Client(), "example.com", ts.URL)
	if f != nil {
		t.Errorf("expected no finding when depth limit is enforced, got: %s", f.Title)
	}
}

// ---------------------------------------------------------------------------
// checkBatchNoLimit integration
// ---------------------------------------------------------------------------

func TestCheckBatchNoLimit_Vulnerable_FindingEmitted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		var sb strings.Builder
		sb.WriteString("[")
		for i := range 100 {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`{"data":{"__typename":"Query"}}`)
		}
		sb.WriteString("]")
		_, _ = w.Write([]byte(sb.String()))
	}))
	defer ts.Close()

	f := checkBatchNoLimit(context.Background(), ts.Client(), "example.com", ts.URL)
	if f == nil {
		t.Fatal("expected finding for no batch limit, got nil")
	}
	if f.CheckID != finding.CheckGraphQLBatchNoLimit {
		t.Errorf("expected CheckGraphQLBatchNoLimit, got %s", f.CheckID)
	}
}

func TestCheckBatchNoLimit_Protected_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":[{"message":"Batch limit exceeded"}]}`))
	}))
	defer ts.Close()

	f := checkBatchNoLimit(context.Background(), ts.Client(), "example.com", ts.URL)
	if f != nil {
		t.Errorf("expected no finding when batch limit is enforced, got: %s", f.Title)
	}
}
