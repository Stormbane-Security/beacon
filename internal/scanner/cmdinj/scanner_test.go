package cmdinj

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/oob"
)

func TestCmdInj_SkipsNonAuthorized(t *testing.T) {
	s := New()
	for _, st := range []module.ScanType{module.ScanSurface, module.ScanDeep} {
		findings, err := s.Run(context.Background(), "example.com", st)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) != 0 {
			t.Errorf("CmdInj scanner should skip scan type %v", st)
		}
	}
}

func TestCmdInj_DetectsTimeBased(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("cmd")
		if strings.Contains(param, "sleep 3") {
			time.Sleep(3 * time.Second)
		} else if strings.Contains(param, "sleep 5") {
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
		t.Fatal("expected command injection finding for vulnerable server")
	}

	f := findings[0]
	if f.CheckID != "web.command_injection" {
		t.Errorf("expected check ID web.command_injection, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected critical severity, got %s", f.Severity)
	}
}

func TestCmdInj_NoFalsePositiveConstantTime(t *testing.T) {
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

func TestBuildPayload_CmdInj(t *testing.T) {
	p := payload{
		name:    "unix-semi",
		os:      "unix",
		prefix:  "; sleep ",
		sleepFn: "%d",
		suffix:  " #",
	}

	got := buildPayload(p, 3)
	want := "; sleep 3 #"
	if got != want {
		t.Errorf("buildPayload() = %q, want %q", got, want)
	}
}

func TestCmdInj_OOBIntegration(t *testing.T) {
	oobSrv := oob.NewServer("oob.test.com", "127.0.0.1:0")
	ctx := oob.WithOOB(context.Background(), oobSrv)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	s := New()
	host := ts.Listener.Addr().String()
	findings, err := s.Run(ctx, host, module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}
	// No findings expected since server doesn't execute commands
	_ = findings
}

func TestMeasureBaseline_CmdInj(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	baseline, err := measureBaseline(context.Background(), client, ts.URL, 5)
	if err != nil {
		t.Fatal(err)
	}

	if baseline > 100*time.Millisecond {
		t.Errorf("baseline %s too high for localhost", baseline)
	}
}
