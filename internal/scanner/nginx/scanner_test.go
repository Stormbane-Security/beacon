package nginx

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// TestNginx_AliasTraversal verifies that a server returning /etc/passwd content
// via a traversal path produces a Critical CheckWebNginxAliasTraversal finding.
func TestNginx_AliasTraversal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate an Nginx alias traversal vulnerability: paths containing
		// "etc/passwd" return the passwd file content.
		if strings.Contains(r.URL.Path, "etc/passwd") {
			fmt.Fprintln(w, "root:x:0:0:root:/root:/bin/bash")
			fmt.Fprintln(w, "bin:x:1:1:bin:/bin:/sbin/nologin")
			fmt.Fprintln(w, "daemon:x:2:2:daemon:/sbin:/sbin/nologin")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	var traversalFindings []finding.Finding
	for _, f := range findings {
		if f.CheckID == finding.CheckWebNginxAliasTraversal {
			traversalFindings = append(traversalFindings, f)
		}
	}
	if len(traversalFindings) == 0 {
		t.Fatal("expected at least 1 CheckWebNginxAliasTraversal finding, got none")
	}
	for _, f := range traversalFindings {
		if f.Severity != finding.SeverityCritical {
			t.Errorf("expected Critical severity, got %s", f.Severity)
		}
	}
}

// TestNginx_IISShortname verifies that an IIS server returning 400 on /~1/
// produces a Medium CheckWebIISShortname finding.
func TestNginx_IISShortname(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/~1/" {
			w.Header().Set("Server", "Microsoft-IIS/10.0")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "Bad Request")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	var iisFindings []finding.Finding
	for _, f := range findings {
		if f.CheckID == finding.CheckWebIISShortname {
			iisFindings = append(iisFindings, f)
		}
	}
	if len(iisFindings) == 0 {
		t.Fatal("expected at least 1 CheckWebIISShortname finding, got none")
	}
	for _, f := range iisFindings {
		if f.Severity != finding.SeverityMedium {
			t.Errorf("expected Medium severity, got %s", f.Severity)
		}
	}
}

// TestNginx_NormalServer verifies that a normal server with no vulnerabilities
// produces no findings.
func TestNginx_NormalServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Normal server: 404 for everything unusual, 200 for root.
		if r.URL.Path == "/" {
			fmt.Fprintln(w, "Welcome to our website!")
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	asset := strings.TrimPrefix(srv.URL, "http://")
	findings, err := New().Run(context.Background(), asset, module.ScanSurface)
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	for _, f := range findings {
		if f.CheckID == finding.CheckWebNginxAliasTraversal || f.CheckID == finding.CheckWebIISShortname {
			t.Errorf("unexpected finding on normal server: %+v", f)
		}
	}
}
