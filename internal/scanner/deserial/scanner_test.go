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

// ---------------------------------------------------------------------------
// PHP serialized object detection
// ---------------------------------------------------------------------------

func TestScanResponsesForMagicBytes_PHPSerializedObject_FindingEmitted(t *testing.T) {
	// Server returns a PHP serialize() object pattern in the response body.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`O:4:"User":2:{s:4:"name";s:5:"admin";s:4:"role";s:5:"admin";}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := scanResponsesForMagicBytes(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for PHP serialized object in response, got nil")
	}
	if f.CheckID != finding.CheckWebInsecureDeserialize {
		t.Errorf("expected CheckWebInsecureDeserialize, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", f.Severity)
	}
	lang, ok := f.Evidence["language"].(string)
	if !ok || lang != "PHP" {
		t.Errorf("expected evidence language=PHP, got %v", f.Evidence["language"])
	}
	if !strings.Contains(f.Title, "PHP") {
		t.Errorf("expected title to mention PHP, got %q", f.Title)
	}
}

func TestScanResponsesForMagicBytes_PHPNamespacedClass_FindingEmitted(t *testing.T) {
	// PHP serialized object with a namespaced class name (backslashes).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/session" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`O:22:"App\Models\UserSession":3:{s:2:"id";i:1;s:4:"name";s:3:"bob";s:5:"admin";b:0;}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := scanResponsesForMagicBytes(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for PHP namespaced serialized object, got nil")
	}
	if f.Evidence["language"] != "PHP" {
		t.Errorf("expected language=PHP, got %v", f.Evidence["language"])
	}
}

func TestScanResponsesForMagicBytes_NotPHP_ColonInJSON_NoFinding(t *testing.T) {
	// A JSON response that happens to contain "O:" should NOT match the PHP regex.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"type":"O:thing","count":42}`))
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := scanResponsesForMagicBytes(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding for JSON with O: substring, but got one: %s", f.Title)
	}
}

// ---------------------------------------------------------------------------
// Base64-encoded Java magic bytes detection
// ---------------------------------------------------------------------------

func TestScanResponsesForMagicBytes_Base64JavaMagic_FindingEmitted(t *testing.T) {
	// Server returns a base64-encoded Java serialized object (starts with "rO0AB").
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			// "rO0AB" is the base64 encoding of 0xACED0005 — the scanner checks
			// for this string when raw bytes are not present.
			w.Write([]byte(`{"token":"rO0ABXNyABRqYXZhLnV0aWwuSGFzaE1hcA"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := scanResponsesForMagicBytes(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for base64 Java magic bytes (rO0AB), got nil")
	}
	if f.CheckID != finding.CheckWebInsecureDeserialize {
		t.Errorf("expected CheckWebInsecureDeserialize, got %s", f.CheckID)
	}
	lang, ok := f.Evidence["language"].(string)
	if !ok || lang != "Java" {
		t.Errorf("expected evidence language=Java, got %v", f.Evidence["language"])
	}
}

func TestScanResponsesForMagicBytes_Base64NoMagic_NoFinding(t *testing.T) {
	// A response containing a base64 string that does NOT start with rO0AB.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token":"dGhpcyBpcyBub3QgamF2YQ=="}`))
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := scanResponsesForMagicBytes(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding for generic base64, but got: %s", f.Title)
	}
}

// ---------------------------------------------------------------------------
// .NET ViewState / EventValidation detection
// ---------------------------------------------------------------------------

func TestProbeDotNetDeserialize_ViewStateOnly_FindingEmitted(t *testing.T) {
	// ASP.NET page with __VIEWSTATE but no __EVENTVALIDATION, encrypted value.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body>
				<form method="post">
				<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="dDwxNTQzOTQ0NjAx" />
				<input type="submit" value="Login" />
				</form>
				</body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeDotNetDeserialize(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for __VIEWSTATE, got nil")
	}
	if f.CheckID != finding.CheckWebDotNetDeserialize {
		t.Errorf("expected CheckWebDotNetDeserialize, got %s", f.CheckID)
	}
	// Value does not start with /wE, so it should be treated as encrypted → High not Critical.
	if f.Severity != finding.SeverityHigh {
		t.Errorf("expected SeverityHigh for encrypted ViewState, got %v", f.Severity)
	}
	if f.Evidence["has_viewstate"] != true {
		t.Error("expected has_viewstate=true in evidence")
	}
	if f.Evidence["has_eventvalidation"] != false {
		t.Error("expected has_eventvalidation=false when no __EVENTVALIDATION")
	}
	if f.Evidence["unencrypted"] != false {
		t.Error("expected unencrypted=false for encrypted ViewState value")
	}
}

func TestProbeDotNetDeserialize_ViewStateAndEventValidation_FindingEmitted(t *testing.T) {
	// ASP.NET page with both __VIEWSTATE and __EVENTVALIDATION.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body>
				<form method="post">
				<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="dDwxNTQzOTQ0NjAx" />
				<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="dGVzdHZhbGlk" />
				<input type="submit" value="Login" />
				</form>
				</body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeDotNetDeserialize(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for __VIEWSTATE + __EVENTVALIDATION, got nil")
	}
	if f.Evidence["has_viewstate"] != true {
		t.Error("expected has_viewstate=true")
	}
	if f.Evidence["has_eventvalidation"] != true {
		t.Error("expected has_eventvalidation=true")
	}
	if !strings.Contains(f.Title, "__EVENTVALIDATION") {
		t.Errorf("expected title to mention __EVENTVALIDATION, got %q", f.Title)
	}
	markers, ok := f.Evidence["markers"].(string)
	if !ok || !strings.Contains(markers, "__EVENTVALIDATION") {
		t.Errorf("expected markers to include __EVENTVALIDATION, got %v", f.Evidence["markers"])
	}
}

func TestProbeDotNetDeserialize_UnencryptedViewState_CriticalSeverity(t *testing.T) {
	// Unencrypted ViewState starts with /wE — scanner should flag as Critical.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><body>
				<form method="post">
				<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="/wEPDwUKMTI2NTAzNjQ3MQ9kFgI=" />
				<input type="submit" value="Submit" />
				</form>
				</body></html>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeDotNetDeserialize(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for unencrypted ViewState (/wE prefix), got nil")
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected SeverityCritical for unencrypted ViewState, got %v", f.Severity)
	}
	if f.Evidence["unencrypted"] != true {
		t.Error("expected unencrypted=true for /wE-prefixed ViewState")
	}
	if !strings.Contains(f.Description, "unencrypted") {
		t.Error("expected description to mention 'unencrypted' for /wE ViewState")
	}
}

func TestProbeDotNetDeserialize_NoViewState_NoFinding(t *testing.T) {
	// Normal HTML page without any ASP.NET markers.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><h1>Welcome</h1></body></html>`))
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeDotNetDeserialize(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding for page without ViewState, got: %s", f.Title)
	}
}

func TestProbeDotNetDeserialize_404Page_NoFinding(t *testing.T) {
	// All dotNetPaths return 404 — should not produce a finding even if body
	// coincidentally contains __VIEWSTATE text.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`<html><input type="hidden" name="__VIEWSTATE" value="abc123" /></html>`))
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeDotNetDeserialize(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding for 404 pages, got: %s", f.Title)
	}
}

func TestProbeDotNetDeserialize_LoginAspx_FindingEmitted(t *testing.T) {
	// ViewState found on /login.aspx (not just root path).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login.aspx" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<form><input type="hidden" name="__VIEWSTATE" value="abc123def" /></form>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeDotNetDeserialize(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for ViewState on /login.aspx, got nil")
	}
	url, _ := f.Evidence["url"].(string)
	if !strings.HasSuffix(url, "/login.aspx") {
		t.Errorf("expected evidence url to end with /login.aspx, got %s", url)
	}
}

// ---------------------------------------------------------------------------
// Java version gadget detection
// ---------------------------------------------------------------------------

func TestProbeJavaVersionGadget_Java8WithDeserialEndpoint_CriticalFinding(t *testing.T) {
	// Server exposes Java 8 in headers and returns Java magic bytes on a probe path.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.Header().Set("X-Powered-By", "Servlet/3.1 Java/1.8.0_232")

		if r.URL.Path == "/api" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			// Return Java serialized magic bytes to mark this as a deser endpoint.
			w.Write([]byte{0xAC, 0xED, 0x00, 0x05, 0x73, 0x72})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeJavaVersionGadget(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for Java/1.8 with deserialization endpoint, got nil")
	}
	if f.CheckID != finding.CheckWebInsecureDeserialize {
		t.Errorf("expected CheckWebInsecureDeserialize, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", f.Severity)
	}
	if !strings.Contains(f.Title, "Java/1.8") {
		t.Errorf("expected title to contain Java/1.8, got %q", f.Title)
	}
	gadgets, ok := f.Evidence["gadget_chains"].(string)
	if !ok || !strings.Contains(gadgets, "CommonsBeansutils") {
		t.Errorf("expected gadget_chains to include CommonsBeansutils for Java 8, got %v", f.Evidence["gadget_chains"])
	}
}

func TestProbeJavaVersionGadget_Tomcat9WithDeserialEndpoint_CriticalFinding(t *testing.T) {
	// Server header reveals Tomcat/9 and a deserial endpoint exists.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1 Tomcat/9.0.41")

		if r.URL.Path == "/rpc" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte{0xAC, 0xED, 0x00, 0x05, 0x00, 0x00})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeJavaVersionGadget(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for Tomcat/9 with deserialization endpoint, got nil")
	}
	if !strings.Contains(f.Title, "Tomcat/9") {
		t.Errorf("expected title to contain Tomcat/9, got %q", f.Title)
	}
	if !strings.Contains(f.Description, "CommonsCollections6-7") {
		t.Errorf("expected description to mention CommonsCollections6-7, got %q", f.Description)
	}
}

func TestProbeJavaVersionGadget_NoDeserialEndpoint_NoFinding(t *testing.T) {
	// Server header reveals Java version but no deserialization endpoint exists.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Java/1.8.0_301")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeJavaVersionGadget(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding without deserialization endpoint, got: %s", f.Title)
	}
}

func TestProbeJavaVersionGadget_NoJavaHeaders_NoFinding(t *testing.T) {
	// Server has a deserialization endpoint but no Java version in headers.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.21.0")

		if r.URL.Path == "/api" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte{0xAC, 0xED, 0x00, 0x05, 0x73, 0x72})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeJavaVersionGadget(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding without Java version headers, got: %s", f.Title)
	}
}

func TestProbeJavaVersionGadget_JBossWithDeserialEndpoint_CriticalFinding(t *testing.T) {
	// JBoss/WildFly in server header with deserialization endpoint.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "JBoss-EAP/7.3")

		if r.URL.Path == "/invoke" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte{0xAC, 0xED, 0x00, 0x05, 0x73})
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeJavaVersionGadget(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for JBoss with deserialization endpoint, got nil")
	}
	if !strings.Contains(f.Title, "JBoss") {
		t.Errorf("expected title to contain JBoss, got %q", f.Title)
	}
	gadgets, _ := f.Evidence["gadget_chains"].(string)
	if !strings.Contains(gadgets, "JBossInterceptors1") {
		t.Errorf("expected gadget_chains to include JBossInterceptors1, got %s", gadgets)
	}
}

func TestProbeJavaVersionGadget_Base64MagicOnProbePath_FindingEmitted(t *testing.T) {
	// Deserialization endpoint returns base64-encoded Java magic (rO0AB) instead
	// of raw bytes — version gadget check should still detect the endpoint.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "WebLogic/14.1.1")

		if r.URL.Path == "/execute" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`rO0ABXNyABRqYXZhLnV0aWwuSGFzaE1hcA==`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeJavaVersionGadget(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for WebLogic with base64 Java magic, got nil")
	}
	if !strings.Contains(f.Title, "WebLogic") {
		t.Errorf("expected title to contain WebLogic, got %q", f.Title)
	}
	gadgets, _ := f.Evidence["gadget_chains"].(string)
	if !strings.Contains(gadgets, "T3/IIOP") {
		t.Errorf("expected gadget_chains to include T3/IIOP for WebLogic, got %s", gadgets)
	}
}

// ---------------------------------------------------------------------------
// Java deserialization POST probe — additional exception patterns
// ---------------------------------------------------------------------------

func TestProbeJavaDeserialization_StreamCorruptedException_FindingEmitted(t *testing.T) {
	// Server returns StreamCorruptedException (another Java deser error class).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			ct := r.Header.Get("Content-Type")
			if strings.Contains(ct, "java-serialized-object") {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("java.io.StreamCorruptedException: invalid stream header: 72303041"))
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeJavaDeserialization(context.Background(), http.DefaultClient, host, ts.URL)
	if f == nil {
		t.Fatal("expected finding for StreamCorruptedException, got nil")
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected SeverityCritical, got %v", f.Severity)
	}
}

func TestProbeJavaDeserialization_200OK_NoFinding(t *testing.T) {
	// Server returns 200 OK (not 500) even with Java class names in the body.
	// Only 500 + exception pattern should trigger.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("java.io.StreamCorruptedException: this is just documentation"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	host := strings.TrimPrefix(ts.URL, "http://")
	f := probeJavaDeserialization(context.Background(), http.DefaultClient, host, ts.URL)
	if f != nil {
		t.Errorf("expected no finding when status is 200 (not 500), got: %s", f.Title)
	}
}

// ---------------------------------------------------------------------------
// Integration: full Run() with PHP, .NET, and version gadgets together
// ---------------------------------------------------------------------------

func TestRun_DeepMode_PHPObjectInResponse_FindingEmitted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/session" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`O:7:"Session":1:{s:4:"data";s:6:"foobar";}`))
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
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebInsecureDeserialize {
			found = true
			lang, _ := f.Evidence["language"].(string)
			if lang != "PHP" {
				t.Errorf("expected language=PHP, got %s", lang)
			}
		}
	}
	if !found {
		t.Error("expected CheckWebInsecureDeserialize finding for PHP serialized response")
	}
}

func TestRun_DeepMode_DotNetViewState_FindingEmitted(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/default.aspx" && r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`<html><form><input type="hidden" name="__VIEWSTATE" value="/wEPDwUKMTI=" /></form></html>`))
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
	var found bool
	for _, f := range findings {
		if f.CheckID == finding.CheckWebDotNetDeserialize {
			found = true
			if f.Severity != finding.SeverityCritical {
				t.Errorf("expected SeverityCritical for /wE-prefixed ViewState, got %v", f.Severity)
			}
		}
	}
	if !found {
		t.Error("expected CheckWebDotNetDeserialize finding for .NET ViewState page")
	}
}
