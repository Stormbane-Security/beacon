package sqli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestBlindTimeSQLi_MySQL(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		upper := strings.ToUpper(param)
		if strings.Contains(upper, "SLEEP(3)") {
			time.Sleep(3 * time.Second)
		} else if strings.Contains(upper, "SLEEP(5)") {
			time.Sleep(5 * time.Second)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 15 * time.Second}
	result := BlindTimeSQLi(ctx, client, ts.URL, "id")
	if result == nil {
		t.Fatal("expected BlindResult for vulnerable MySQL server, got nil")
	}
	if !result.Vulnerable {
		t.Error("expected Vulnerable=true")
	}
	if result.DBType != "mysql" {
		t.Errorf("expected dbType mysql, got %s", result.DBType)
	}
	if result.DeltaMs < 2500 {
		t.Errorf("expected delta >= 2500ms, got %d", result.DeltaMs)
	}
}

func TestBlindTimeSQLi_Postgres(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		upper := strings.ToUpper(param)
		if strings.Contains(upper, "PG_SLEEP(3)") {
			time.Sleep(3 * time.Second)
		} else if strings.Contains(upper, "PG_SLEEP(5)") {
			time.Sleep(5 * time.Second)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 15 * time.Second}
	result := BlindTimeSQLi(ctx, client, ts.URL, "id")
	if result == nil {
		t.Fatal("expected BlindResult for vulnerable Postgres server, got nil")
	}
	if result.DBType != "postgres" {
		t.Errorf("expected dbType postgres, got %s", result.DBType)
	}
}

func TestBlindTimeSQLi_MSSQL(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		if strings.Contains(param, "WAITFOR DELAY '0:0:3'") {
			time.Sleep(3 * time.Second)
		} else if strings.Contains(param, "WAITFOR DELAY '0:0:5'") {
			time.Sleep(5 * time.Second)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 15 * time.Second}
	result := BlindTimeSQLi(ctx, client, ts.URL, "id")
	if result == nil {
		t.Fatal("expected BlindResult for vulnerable MSSQL server, got nil")
	}
	if result.DBType != "mssql" {
		t.Errorf("expected dbType mssql, got %s", result.DBType)
	}
}

func TestBlindTimeSQLi_NotVulnerable(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := &http.Client{Timeout: 15 * time.Second}
	result := BlindTimeSQLi(ctx, client, ts.URL, "id")
	if result != nil {
		t.Errorf("expected nil for safe server, got %+v", result)
	}
}

func TestBlindTimeSQLi_NilClient(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Passing nil client should use default
	result := BlindTimeSQLi(ctx, nil, ts.URL, "id")
	// Should not panic and should return nil for safe server
	if result != nil {
		t.Errorf("expected nil for safe server with nil client, got %+v", result)
	}
}

func TestBlindResultToFinding(t *testing.T) {
	r := &BlindResult{
		Vulnerable: true,
		Payload:    "' OR SLEEP(3)-- -",
		DBType:     "mysql",
		BaselineMs: 50,
		InjectedMs: 3100,
		DeltaMs:    3050,
		ConfirmMs:  5100,
	}

	f := BlindResultToFinding(r, "example.com", "/search", "q")
	if f.CheckID != finding.CheckWebBlindSQLiTime {
		t.Errorf("expected check ID %s, got %s", finding.CheckWebBlindSQLiTime, f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %s", f.Severity)
	}
	if f.Confidence != finding.ConfidenceVerified {
		t.Errorf("expected Verified confidence, got %s", f.Confidence)
	}
	if f.Evidence["db_type"] != "mysql" {
		t.Errorf("expected db_type mysql, got %v", f.Evidence["db_type"])
	}
	if f.Evidence["parameter"] != "q" {
		t.Errorf("expected parameter q, got %v", f.Evidence["parameter"])
	}
}
