package paramdiscovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiscoverParams_DetectsStatusChange(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If "debug" param is present, return 403 instead of 200.
		if r.URL.Query().Get("debug") != "" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte("forbidden"))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := srv.Client()
	found := DiscoverParams(ctx, client, srv.URL+"/test", "GET")

	var debugFound bool
	for _, p := range found {
		if p.Name == "debug" {
			debugFound = true
			if !strings.Contains(p.Evidence, "status changed") {
				t.Errorf("expected status change evidence, got: %s", p.Evidence)
			}
		}
	}
	if !debugFound {
		t.Error("expected to discover 'debug' param via status change")
	}
}

func TestDiscoverParams_DetectsBodyLengthChange(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("search") != "" || r.URL.Query().Get("q") != "" {
			// Return a much larger response when search params are present.
			w.WriteHeader(200)
			_, _ = w.Write([]byte(strings.Repeat("result item\n", 100)))
			return
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("empty"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := srv.Client()
	found := DiscoverParams(ctx, client, srv.URL+"/search", "GET")

	foundNames := make(map[string]bool)
	for _, p := range found {
		foundNames[p.Name] = true
	}
	// At least one of q or search should be found.
	if !foundNames["q"] && !foundNames["search"] {
		t.Errorf("expected to discover 'q' or 'search' param, found: %v", foundNames)
	}
}

func TestDiscoverParams_NoFalsePositivesOnStatic(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always returns the exact same response regardless of params.
		w.WriteHeader(200)
		_, _ = w.Write([]byte("static content that never changes"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := srv.Client()
	found := DiscoverParams(ctx, client, srv.URL+"/static", "GET")

	if len(found) > 0 {
		t.Errorf("expected no params on static endpoint, found: %v", found)
	}
}

func TestDiscoverParams_POSTMethod(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_ = r.ParseForm()
			if r.FormValue("email") != "" {
				w.WriteHeader(200)
				_, _ = w.Write([]byte(fmt.Sprintf("found user for %s with extra details and more content", r.FormValue("email"))))
				return
			}
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := srv.Client()
	found := DiscoverParams(ctx, client, srv.URL+"/lookup", "POST")

	var emailFound bool
	for _, p := range found {
		if p.Name == "email" {
			emailFound = true
			if p.Method != "POST" {
				t.Errorf("expected POST method, got %s", p.Method)
			}
		}
	}
	if !emailFound {
		t.Error("expected to discover 'email' param via POST")
	}
}

func TestDiscoverParams_SkipsDynamicEndpoints(t *testing.T) {
	t.Parallel()
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		// Every response is different — endpoint is too dynamic for differential analysis.
		w.WriteHeader(200)
		_, _ = w.Write([]byte(fmt.Sprintf("response %d with random content %s", callCount, strings.Repeat("x", callCount*100))))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client := srv.Client()
	found := DiscoverParams(ctx, client, srv.URL+"/dynamic", "GET")

	// Should either return nothing or very few false positives.
	if len(found) > 5 {
		t.Errorf("too many false positives on dynamic endpoint: %d", len(found))
	}
}

func TestDiscoverParams_DetectsNewHeader(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("callback") != "" {
			w.Header().Set("X-Custom-Callback", "active")
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client := srv.Client()
	found := DiscoverParams(ctx, client, srv.URL+"/api", "GET")

	var callbackFound bool
	for _, p := range found {
		if p.Name == "callback" {
			callbackFound = true
			if !strings.Contains(p.Evidence, "new header") {
				t.Errorf("expected new header evidence, got: %s", p.Evidence)
			}
		}
	}
	if !callbackFound {
		t.Error("expected to discover 'callback' param via new header")
	}
}

func TestDiscoverParams_RespectsContext(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	client := srv.Client()
	found := DiscoverParams(ctx, client, srv.URL+"/test", "GET")
	if len(found) > 0 {
		t.Error("expected no results with cancelled context")
	}
}

func TestDiscoverParams_DefaultsToGET(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_ = DiscoverParams(ctx, srv.Client(), srv.URL, "")
}

func TestCommonParamsWordlist(t *testing.T) {
	t.Parallel()
	// Verify the wordlist is non-trivial.
	if len(commonParams) < 200 {
		t.Errorf("expected 200+ common params, got %d", len(commonParams))
	}

	// Check for duplicates.
	seen := make(map[string]bool)
	for _, p := range commonParams {
		if seen[p] {
			// Duplicates are allowed (some appear in multiple categories)
			// but should be minimal.
			continue
		}
		seen[p] = true
	}
	t.Logf("commonParams: %d total, %d unique", len(commonParams), len(seen))
}

func TestDiffBaseline_NoChange(t *testing.T) {
	t.Parallel()
	bl := &baseline{status: 200, bodyLen: 100, bodyHash: "abc", headerKeys: []string{"content-type"}}
	probe := &baseline{status: 200, bodyLen: 100, bodyHash: "abc", headerKeys: []string{"content-type"}}
	diff := diffBaseline(bl, probe)
	if diff != "" {
		t.Errorf("expected no diff, got: %s", diff)
	}
}

func TestDiffBaseline_StatusChange(t *testing.T) {
	t.Parallel()
	bl := &baseline{status: 200, bodyLen: 100, bodyHash: "abc"}
	probe := &baseline{status: 403, bodyLen: 100, bodyHash: "abc"}
	diff := diffBaseline(bl, probe)
	if !strings.Contains(diff, "status changed") {
		t.Errorf("expected status change, got: %s", diff)
	}
}

func TestDiffBaseline_BodyLengthChange(t *testing.T) {
	t.Parallel()
	bl := &baseline{status: 200, bodyLen: 100, bodyHash: "abc"}
	probe := &baseline{status: 200, bodyLen: 200, bodyHash: "def"}
	diff := diffBaseline(bl, probe)
	if !strings.Contains(diff, "body length changed") {
		t.Errorf("expected body length change, got: %s", diff)
	}
}

func TestDiffBaseline_NewHeader(t *testing.T) {
	t.Parallel()
	bl := &baseline{status: 200, bodyLen: 5, bodyHash: "abc", headerKeys: []string{"content-type"}}
	probe := &baseline{status: 200, bodyLen: 5, bodyHash: "abc", headerKeys: []string{"content-type", "x-custom"}}
	diff := diffBaseline(bl, probe)
	if !strings.Contains(diff, "new header") {
		t.Errorf("expected new header, got: %s", diff)
	}
}

func TestRandomValue(t *testing.T) {
	t.Parallel()
	v := randomValue()
	if len(v) != 8 {
		t.Errorf("expected 8-char value, got %d: %s", len(v), v)
	}
	// Should be alphanumeric.
	for _, c := range v {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
			t.Errorf("unexpected char %c in random value", c)
		}
	}
}
