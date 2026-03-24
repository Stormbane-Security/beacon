package deserial

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

func TestRun_SurfaceMode_ReturnsNil(t *testing.T) {
	s := New()
	findings, err := s.Run(context.Background(), "example.com", module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings in surface mode, got %d", len(findings))
	}
}

func TestRun_DeepMode_NoDeserialEndpoints_NoFindings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected 0 findings when no endpoints, got %d", len(findings))
	}
}

func TestRun_DeepMode_JavaMagicBytesInResponse_FindingEmitted(t *testing.T) {
	// Server returns Java serialized object magic bytes in the response body.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" && r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			// Write Java magic bytes: 0xACED0005
			w.Write([]byte{0xAC, 0xED, 0x00, 0x05, 0x73, 0x72})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var hasDeserial bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebInsecureDeserialize {
			hasDeserial = true
			if f.Severity != finding.SeverityHigh && f.Severity != finding.SeverityCritical {
				t.Errorf("expected High or Critical severity, got %v", f.Severity)
			}
		}
	}
	if !hasDeserial {
		t.Error("expected CheckWebInsecureDeserialize finding for Java magic bytes in response")
	}
}

func TestRun_DeepMode_JavaExceptionOnPost_CriticalFinding(t *testing.T) {
	// Server returns a Java ClassNotFoundException when receiving a serialized POST.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ct := r.Header.Get("Content-Type")
			if strings.Contains(ct, "java-serialized-object") {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("java.io.InvalidClassException: ClassNotFoundException: com.example.Gadget\n\tat java.io.ObjectStreamClass.initNonProxy"))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var hasCritical bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebInsecureDeserialize && f.Severity == finding.SeverityCritical {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Error("expected SeverityCritical finding when Java exception is thrown on deserializing POST")
	}
}

func TestRun_DeepMode_NormalJSONResponse_NoFinding(t *testing.T) {
	// Server returns normal JSON — no serialization indicators.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","data":[]}`))
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanDeep)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebInsecureDeserialize {
			t.Error("expected no deserialization finding for normal JSON response")
		}
	}
}

func TestRun_ContextCancelled_NoPanic(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, _ := s.Run(ctx, host, module.ScanDeep)
	_ = findings
}
