package deserial

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// PHP deserialization
// ---------------------------------------------------------------------------

func TestProbePHPDeserialization_UnserializeError_FindingEmitted(t *testing.T) {
	// Server returns a PHP unserialize() error when it receives a serialized object.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`<b>Warning</b>: unserialize(): Error at offset 0 of 20 bytes in /var/www/app.php on line 42`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probePHPDeserialization(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for PHP unserialize() error, got nil")
	}
	if f.CheckID != finding.CheckWebPHPDeserialization {
		t.Errorf("expected CheckWebPHPDeserialization, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", f.Severity)
	}
}

func TestProbePHPDeserialization_IncompleteClass_FindingEmitted(t *testing.T) {
	// Server returns __PHP_Incomplete_Class in the output.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/session" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`__PHP_Incomplete_Class Object ( [__PHP_Incomplete_Class_Name] => stdClass )`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probePHPDeserialization(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for __PHP_Incomplete_Class, got nil")
	}
	if f.CheckID != finding.CheckWebPHPDeserialization {
		t.Errorf("expected CheckWebPHPDeserialization, got %s", f.CheckID)
	}
}

func TestProbePHPDeserialization_NormalResponse_NoFinding(t *testing.T) {
	// Server returns normal JSON — no PHP deserialization indicators.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probePHPDeserialization(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding for normal response, got: %s", f.Title)
	}
}

func TestProbePHPDeserialization_CookieVector_FindingEmitted(t *testing.T) {
	// Server processes cookies via unserialize — returns __destruct output.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only respond to GET with cookie.
		if r.Method == http.MethodGet && r.URL.Path == "/" {
			for _, c := range r.Cookies() {
				if strings.Contains(c.Value, "stdClass") {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`PHP Fatal error: Call to undefined method stdClass::__destruct()`))
					return
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probePHPDeserialization(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for cookie-based PHP deserialization, got nil")
	}
	method, _ := f.Evidence["method"].(string)
	if method != "cookie" {
		t.Errorf("expected method=cookie, got %s", method)
	}
}

// ---------------------------------------------------------------------------
// Java-specific deserialization (JSESSIONID + binary POST)
// ---------------------------------------------------------------------------

func TestProbeJavaDeserializationSpecific_JSESSIONID_FindingEmitted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Root path sets JSESSIONID.
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "ABC123"})
			w.WriteHeader(http.StatusOK)
			return
		}
		// POST to /api with java-serialized-object content type returns exception.
		if r.Method == http.MethodPost && r.URL.Path == "/api" {
			ct := r.Header.Get("Content-Type")
			if strings.Contains(ct, "java-serialized-object") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("java.io.InvalidClassException: ClassNotFoundException"))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeJavaDeserializationSpecific(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for Java deserialization with JSESSIONID, got nil")
	}
	if f.CheckID != finding.CheckWebJavaDeserialization {
		t.Errorf("expected CheckWebJavaDeserialization, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", f.Severity)
	}
	if f.Evidence["jsessionid"] != true {
		t.Error("expected jsessionid=true in evidence")
	}
}

func TestProbeJavaDeserializationSpecific_NoJSESSIONID_NoFinding(t *testing.T) {
	// Server has no JSESSIONID cookie.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeJavaDeserializationSpecific(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding without JSESSIONID, got: %s", f.Title)
	}
}

func TestProbeJavaDeserializationSpecific_JSESSIONID_NoException_NoFinding(t *testing.T) {
	// Server has JSESSIONID but endpoints return 404, no Java exception.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "ABC123"})
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeJavaDeserializationSpecific(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding when no Java exception, got: %s", f.Title)
	}
}

// ---------------------------------------------------------------------------
// ViewState unprotected (surface-safe)
// ---------------------------------------------------------------------------

func TestProbeViewstateUnprotected_UnencryptedViewState_FindingEmitted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><form>
				<input type="hidden" name="__VIEWSTATE" value="/wEPDwUKMTI2NTAzNjQ3MQ9kFgI=" />
				<input type="submit" />
			</form></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeViewstateUnprotected(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for unprotected ViewState, got nil")
	}
	if f.CheckID != finding.CheckWebViewstateUnprotected {
		t.Errorf("expected CheckWebViewstateUnprotected, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", f.Severity)
	}
	if f.Evidence["unencrypted"] != true {
		t.Error("expected unencrypted=true in evidence")
	}
}

func TestProbeViewstateUnprotected_EncryptedViewState_NoFinding(t *testing.T) {
	// ViewState value does not start with /wE — encrypted.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html><form>
				<input type="hidden" name="__VIEWSTATE" value="dDwxNTQzOTQ0NjAx" />
			</form></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeViewstateUnprotected(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding for encrypted ViewState, got: %s", f.Title)
	}
}

func TestProbeViewstateUnprotected_NoViewState_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body>Hello</body></html>`))
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeViewstateUnprotected(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding without ViewState, got: %s", f.Title)
	}
}

func TestProbeViewstateUnprotected_WithEncryptionHint_NoFinding(t *testing.T) {
	// Page mentions ViewStateEncryptionMode — ViewState is protected.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<html>
				<!-- ViewStateEncryptionMode=Always -->
				<form>
				<input type="hidden" name="__VIEWSTATE" value="/wEPDwUKMTI2NTAzNjQ3MQ9kFgI=" />
				</form>
			</html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeViewstateUnprotected(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding when ViewStateEncryptionMode is present, got: %s", f.Title)
	}
}

// ---------------------------------------------------------------------------
// Integration: Surface mode should still run ViewState check
// ---------------------------------------------------------------------------

func TestRun_SurfaceMode_ViewstateCheck_Runs(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login.aspx" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<form><input type="hidden" name="__VIEWSTATE" value="/wEPDwUKMTI2NTAzNjQ3MQ==" /></form>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	s := New()
	host := strings.TrimPrefix(ts.URL, "http://")
	findings, err := s.Run(context.Background(), host, module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebViewstateUnprotected {
			found = true
		}
	}
	if !found {
		t.Error("expected ViewState finding in surface mode")
	}
}
