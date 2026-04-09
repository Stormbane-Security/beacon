package jsendpoints

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseBundle_FetchEndpoints(t *testing.T) {
	js := `
		fetch("/api/v1/users")
		fetch("/api/v2/orders", {method: "POST"})
		fetch('/api/v1/products')
	`
	bf := ParseBundle(js, "app.js")
	if len(bf.APIEndpoints) == 0 {
		t.Fatal("expected API endpoints from fetch calls")
	}
	found := make(map[string]bool)
	for _, ep := range bf.APIEndpoints {
		found[ep.Path] = true
	}
	for _, want := range []string{"/api/v1/users", "/api/v2/orders", "/api/v1/products"} {
		if !found[want] {
			t.Errorf("missing endpoint %q, found: %v", want, found)
		}
	}
}

func TestParseBundle_AxiosEndpoints(t *testing.T) {
	js := `
		axios.get("/api/v1/profile")
		axios.post("/api/v1/login", data)
		axios.delete("/api/v1/session")
	`
	bf := ParseBundle(js, "app.js")
	if len(bf.APIEndpoints) < 3 {
		t.Fatalf("expected at least 3 axios endpoints, got %d", len(bf.APIEndpoints))
	}
	// Build method+path set to check that axios-specific method detection works.
	// The restAPI pattern may also match the same paths with empty method.
	type key struct{ method, path string }
	found := make(map[key]bool)
	for _, ep := range bf.APIEndpoints {
		found[key{ep.Method, ep.Path}] = true
	}
	if !found[key{"GET", "/api/v1/profile"}] {
		t.Error("expected GET /api/v1/profile from axios pattern")
	}
	if !found[key{"POST", "/api/v1/login"}] {
		t.Error("expected POST /api/v1/login from axios pattern")
	}
	if !found[key{"DELETE", "/api/v1/session"}] {
		t.Error("expected DELETE /api/v1/session from axios pattern")
	}
}

func TestParseBundle_XHREndpoints(t *testing.T) {
	js := `
		var xhr = new XMLHttpRequest();
		xhr.open("POST", "/api/v1/upload");
		xhr.open("GET", "/api/v2/status");
	`
	bf := ParseBundle(js, "app.js")
	if len(bf.APIEndpoints) < 2 {
		t.Fatalf("expected at least 2 XHR endpoints, got %d", len(bf.APIEndpoints))
	}
	type key struct{ method, path string }
	found := make(map[key]bool)
	for _, ep := range bf.APIEndpoints {
		found[key{ep.Method, ep.Path}] = true
	}
	if !found[key{"POST", "/api/v1/upload"}] {
		t.Error("expected POST /api/v1/upload from XHR pattern")
	}
	if !found[key{"GET", "/api/v2/status"}] {
		t.Error("expected GET /api/v2/status from XHR pattern")
	}
}

func TestParseBundle_JQueryAjax(t *testing.T) {
	js := `
		$.ajax({url: "/api/v1/data", method: "GET"})
		$.get("/api/v1/items")
		$.post("/api/v1/submit")
	`
	bf := ParseBundle(js, "app.js")
	if len(bf.APIEndpoints) < 3 {
		t.Fatalf("expected 3 jQuery endpoints, got %d: %+v", len(bf.APIEndpoints), bf.APIEndpoints)
	}
}

func TestParseBundle_GraphQLEndpoint(t *testing.T) {
	js := `
		fetch("/graphql", {method: "POST", body: JSON.stringify({query: "{ users { id name } }"})})
		const endpoint = "https://api.example.com/graphql"
	`
	bf := ParseBundle(js, "app.js")
	foundGraphQL := false
	for _, ep := range bf.APIEndpoints {
		if ep.Path == "/graphql" || ep.Path == "https://api.example.com/graphql" {
			foundGraphQL = true
			break
		}
	}
	if !foundGraphQL {
		t.Error("expected to find GraphQL endpoint")
	}
}

func TestParseBundle_WebSocketEndpoints(t *testing.T) {
	js := `
		var ws = new WebSocket("wss://api.example.com/ws/live");
		const socket = new WebSocket("ws://localhost:8080/events");
	`
	bf := ParseBundle(js, "app.js")
	if len(bf.WebSockets) < 2 {
		t.Fatalf("expected 2 WebSocket endpoints, got %d", len(bf.WebSockets))
	}
	found := make(map[string]bool)
	for _, ws := range bf.WebSockets {
		found[ws] = true
	}
	if !found["wss://api.example.com/ws/live"] {
		t.Error("missing wss://api.example.com/ws/live")
	}
	if !found["ws://localhost:8080/events"] {
		t.Error("missing ws://localhost:8080/events")
	}
}

func TestParseBundle_AWSKey(t *testing.T) {
	js := `const awsKey = "AKIAIOSFODNN7EXAMPLE";`
	bf := ParseBundle(js, "app.js")
	if len(bf.HardcodedSecrets) == 0 {
		t.Fatal("expected AWS key detection")
	}
	if bf.HardcodedSecrets[0].Type != "aws_key" {
		t.Errorf("expected type aws_key, got %s", bf.HardcodedSecrets[0].Type)
	}
}

func TestParseBundle_JWT(t *testing.T) {
	js := `const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";`
	bf := ParseBundle(js, "app.js")
	if len(bf.HardcodedSecrets) == 0 {
		t.Fatal("expected JWT detection")
	}
	foundJWT := false
	for _, s := range bf.HardcodedSecrets {
		if s.Type == "jwt" {
			foundJWT = true
			break
		}
	}
	if !foundJWT {
		t.Error("expected jwt type secret")
	}
}

func TestParseBundle_APIKey(t *testing.T) {
	js := `const config = { api_key: "abcdefghijklmnopqrstuvwxyz1234567890" };`
	bf := ParseBundle(js, "app.js")
	if len(bf.HardcodedSecrets) == 0 {
		t.Fatal("expected API key detection")
	}
}

func TestParseBundle_FirebaseConfig(t *testing.T) {
	js := `const firebaseConfig = { apiKey: "AIzaSyD-FAKE-KEY-1234567890abcdefghijkl" };`
	bf := ParseBundle(js, "app.js")
	if len(bf.HardcodedSecrets) == 0 {
		t.Fatal("expected Firebase key detection")
	}
	foundFirebase := false
	for _, s := range bf.HardcodedSecrets {
		if s.Type == "firebase" {
			foundFirebase = true
			break
		}
	}
	if !foundFirebase {
		t.Errorf("expected firebase type, got types: %+v", bf.HardcodedSecrets)
	}
}

func TestParseBundle_InternalURLs(t *testing.T) {
	js := `
		const devAPI = "http://localhost:3000/api";
		const staging = "https://api.staging.example.dev:8443/v1";
		const internal = "http://192.168.1.50:9200/elasticsearch";
		const backend = "http://10.0.0.5:8080/internal/admin";
	`
	bf := ParseBundle(js, "app.js")
	if len(bf.InternalURLs) < 3 {
		t.Fatalf("expected at least 3 internal URLs, got %d: %v", len(bf.InternalURLs), bf.InternalURLs)
	}
}

func TestParseBundle_SourceMaps(t *testing.T) {
	js := `console.log("app");
//# sourceMappingURL=app.js.map`
	bf := ParseBundle(js, "app.js")
	if len(bf.SourceMaps) == 0 {
		t.Fatal("expected source map reference")
	}
	if bf.SourceMaps[0] != "app.js.map" {
		t.Errorf("expected app.js.map, got %s", bf.SourceMaps[0])
	}
}

func TestParseBundle_NoFalsePositives(t *testing.T) {
	js := `
		console.log("hello world");
		var x = 42;
		function add(a, b) { return a + b; }
	`
	bf := ParseBundle(js, "app.js")
	if bf.HasFindings() {
		t.Errorf("expected no findings on benign JS, got: endpoints=%d, ws=%d, secrets=%d, internal=%d, maps=%d",
			len(bf.APIEndpoints), len(bf.WebSockets), len(bf.HardcodedSecrets), len(bf.InternalURLs), len(bf.SourceMaps))
	}
}

func TestParseBundle_Deduplication(t *testing.T) {
	js := `
		fetch("/api/v1/users")
		fetch("/api/v1/users")
		fetch("/api/v1/users")
	`
	bf := ParseBundle(js, "app.js")
	// fetch pattern + restAPI pattern both match, but same method+path should dedup
	count := 0
	for _, ep := range bf.APIEndpoints {
		if ep.Path == "/api/v1/users" && ep.Method == "" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected deduplication, got %d copies of /api/v1/users", count)
	}
}

func TestParseBundle_Merge(t *testing.T) {
	a := &BundleFindings{
		APIEndpoints: []APIEndpoint{{Path: "/a"}},
		WebSockets:   []string{"ws://a"},
	}
	b := &BundleFindings{
		APIEndpoints: []APIEndpoint{{Path: "/b"}},
		InternalURLs: []string{"http://localhost:3000"},
	}
	a.Merge(b)
	if len(a.APIEndpoints) != 2 {
		t.Errorf("expected 2 endpoints after merge, got %d", len(a.APIEndpoints))
	}
	if len(a.WebSockets) != 1 {
		t.Errorf("expected 1 websocket after merge, got %d", len(a.WebSockets))
	}
	if len(a.InternalURLs) != 1 {
		t.Errorf("expected 1 internal URL after merge, got %d", len(a.InternalURLs))
	}
}

func TestParseBundle_HasFindings(t *testing.T) {
	empty := &BundleFindings{}
	if empty.HasFindings() {
		t.Error("empty BundleFindings should not HasFindings")
	}

	withEndpoint := &BundleFindings{APIEndpoints: []APIEndpoint{{Path: "/api"}}}
	if !withEndpoint.HasFindings() {
		t.Error("BundleFindings with endpoint should HasFindings")
	}
}

func TestParseBundleFromURL_ServerDown(t *testing.T) {
	bf := ParseBundleFromURL(context.Background(), http.DefaultClient, "http://127.0.0.1:1/nonexistent.js")
	if bf.HasFindings() {
		t.Error("expected no findings from unreachable server")
	}
}

func TestParseBundleFromURL_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(`fetch("/api/v1/users"); const key = "AKIAIOSFODNN7EXAMPLE";`))
	}))
	defer srv.Close()

	bf := ParseBundleFromURL(context.Background(), srv.Client(), srv.URL+"/app.js")
	if len(bf.APIEndpoints) == 0 {
		t.Error("expected API endpoints")
	}
	if len(bf.HardcodedSecrets) == 0 {
		t.Error("expected hardcoded secrets")
	}
}

func TestParseBundle_RestAPIPattern(t *testing.T) {
	js := `
		"/api/v1/users"
		"/api/v3/orders/history"
		"/api/v10/admin/settings"
	`
	bf := ParseBundle(js, "app.js")
	if len(bf.APIEndpoints) < 3 {
		t.Fatalf("expected 3 REST API endpoints, got %d", len(bf.APIEndpoints))
	}
}

func TestParseBundle_SourceAttributed(t *testing.T) {
	js := `fetch("/api/v1/test")`
	bf := ParseBundle(js, "https://example.com/bundle.js")
	if len(bf.APIEndpoints) == 0 {
		t.Fatal("expected endpoint")
	}
	if bf.APIEndpoints[0].Source != "https://example.com/bundle.js" {
		t.Errorf("expected source attribution, got %q", bf.APIEndpoints[0].Source)
	}
}

func TestParseBundle_PrivateKey(t *testing.T) {
	js := `const pk = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...";`
	bf := ParseBundle(js, "app.js")
	if len(bf.HardcodedSecrets) == 0 {
		t.Fatal("expected private key detection")
	}
	if bf.HardcodedSecrets[0].Type != "private_key" {
		t.Errorf("expected private_key type, got %s", bf.HardcodedSecrets[0].Type)
	}
}
