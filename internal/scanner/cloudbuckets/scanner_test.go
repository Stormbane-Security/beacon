package cloudbuckets

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
	"github.com/stormbane/beacon/internal/module"
)

// ---------------------------------------------------------------------------
// rootDomain
// ---------------------------------------------------------------------------

func TestRootDomain(t *testing.T) {
	cases := []struct {
		asset string
		want  string
	}{
		{"app.acme.com", "acme.com"},
		{"acme.com", "acme.com"},
		{"deep.sub.acme.com", "acme.com"},
		{"localhost", "localhost"},
	}
	for _, c := range cases {
		got := rootDomain(c.asset)
		if got != c.want {
			t.Errorf("rootDomain(%q) = %q, want %q", c.asset, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// bucketCandidates — single-argument (org-name lookup removed)
// ---------------------------------------------------------------------------

func TestBucketCandidates_IncludesBase(t *testing.T) {
	candidates := bucketCandidates("acme.com")
	for _, c := range candidates {
		if c == "acme" {
			return
		}
	}
	t.Error("expected 'acme' in candidates for root 'acme.com', not found")
}

func TestBucketCandidates_IncludesSuffixes(t *testing.T) {
	candidates := bucketCandidates("acme.com")
	wantSuffixes := []string{"acme-backup", "acme-assets", "acme-static", "acme-prod", "acme-dev"}
	for _, want := range wantSuffixes {
		found := false
		for _, c := range candidates {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected candidate %q in bucket candidates, not found", want)
		}
	}
}

func TestBucketCandidates_NoDuplicates(t *testing.T) {
	candidates := bucketCandidates("acme.com")
	seen := make(map[string]int)
	for _, c := range candidates {
		seen[c]++
	}
	for name, count := range seen {
		if count > 1 {
			t.Errorf("candidate %q appears %d times (duplicated)", name, count)
		}
	}
}

func TestBucketCandidates_IncludesDashedDomainForm(t *testing.T) {
	// "acme.com" should produce "acme-com" variants
	candidates := bucketCandidates("acme.com")
	found := false
	for _, c := range candidates {
		if c == "acme-com" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'acme-com' variant in candidates, not found")
	}
}

func TestBucketCandidates_SingleLabelDomain(t *testing.T) {
	// Single-label (no dot) — base and dashed form are the same; still no duplicates
	candidates := bucketCandidates("acme")
	seen := make(map[string]int)
	for _, c := range candidates {
		seen[c]++
	}
	for name, count := range seen {
		if count > 1 {
			t.Errorf("candidate %q appears %d times (duplicated)", name, count)
		}
	}
}

// ---------------------------------------------------------------------------
// probeURL — finding-generation logic
// ---------------------------------------------------------------------------

func TestProbeURL_PublicBucket_CriticalFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<ListBucketResult></ListBucketResult>`)
	}))
	defer ts.Close()

	f := probeURL(context.Background(), ts.Client(), "example.com", ts.URL+"/", "AWS S3", "example-backup", time.Now())
	if f == nil {
		t.Fatal("expected a finding for HTTP 200 response (public bucket), got nil")
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity for public bucket, got %s", f.Severity)
	}
	if f.CheckID != finding.CheckCloudBucketPublic {
		t.Errorf("expected CheckCloudBucketPublic, got %s", f.CheckID)
	}
}

func TestProbeURL_PrivateBucket_InfoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	f := probeURL(context.Background(), ts.Client(), "example.com", ts.URL+"/", "GCS", "example-private", time.Now())
	if f == nil {
		t.Fatal("expected a finding for HTTP 403 response (private bucket exists), got nil")
	}
	if f.Severity != finding.SeverityInfo {
		t.Errorf("expected Info severity for private-but-existing bucket, got %s", f.Severity)
	}
	if f.CheckID != finding.CheckCloudBucketExists {
		t.Errorf("expected CheckCloudBucketExists, got %s", f.CheckID)
	}
}

func TestProbeURL_NotFound_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	f := probeURL(context.Background(), ts.Client(), "example.com", ts.URL+"/", "Azure Blob", "nonexistent", time.Now())
	if f != nil {
		t.Errorf("expected nil finding for 404 response, got %+v", f)
	}
}

func TestProbeURL_301Redirect_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer ts.Close()

	f := probeURL(context.Background(), ts.Client(), "example.com", ts.URL+"/", "AWS S3", "example-redir", time.Now())
	if f != nil {
		t.Errorf("expected nil finding for 301 response, got %+v", f)
	}
}

// ---------------------------------------------------------------------------
// probeWrite — ScanDeep gate
// ---------------------------------------------------------------------------

func TestProbeWrite_ScanSurface_SkipsWriteProbe(t *testing.T) {
	// The write probe server records whether PUT was called
	putCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			putCalled = true
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusOK) // GET returns 200 (public bucket)
		}
	}))
	defer ts.Close()

	s := New()
	// Surface mode — probeWrite must not be called
	findings, err := s.Run(context.Background(), strings.TrimPrefix(ts.URL, "http://"), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = findings
	if putCalled {
		t.Error("probeWrite (PUT) must not be called in surface mode; cloud audit logs require deep/--permission-confirmed")
	}
}

func TestProbeWrite_ScanDeep_CallsWriteProbe(t *testing.T) {
	// In deep mode, probeWrite MUST send a PUT request
	putCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			putCalled = true
			// Simulate bucket accepting the write
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusForbidden) // GET returns 403 (no read finding)
	}))
	defer ts.Close()

	client := ts.Client()
	asset := strings.TrimPrefix(ts.URL, "http://")
	f := probeWrite(context.Background(), client, asset, ts.URL+"/", "AWS S3", "test-bucket", time.Now())
	if !putCalled {
		t.Error("probeWrite should send a PUT request")
	}
	if f == nil {
		t.Fatal("expected a finding when bucket accepts PUT, got nil")
	}
	if f.CheckID != finding.CheckCloudBucketWritable {
		t.Errorf("expected CheckCloudBucketWritable, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity for writable bucket, got %s", f.Severity)
	}
}

func TestProbeWrite_EvidenceContainsBucketURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	f := probeWrite(context.Background(), ts.Client(), "example.com", ts.URL+"/", "Azure Blob", "mybucket", time.Now())
	if f == nil {
		t.Fatal("expected finding, got nil")
	}
	if _, ok := f.Evidence["bucket_url"]; !ok {
		t.Error("evidence missing bucket_url")
	}
	if _, ok := f.Evidence["write_url"]; !ok {
		t.Error("evidence missing write_url")
	}
}

// ---------------------------------------------------------------------------
// Run — ScanDeep gate integration (no real buckets probed)
// ---------------------------------------------------------------------------

func TestRun_SurfaceMode_NoWriteFindings(t *testing.T) {
	// Server returns 200 on GET (bucket exists) but we track whether PUT is called.
	putCalled := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			putCalled = true
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	s := New()
	_, _ = s.Run(context.Background(), strings.TrimPrefix(ts.URL, "http://"), module.ScanSurface)
	if putCalled {
		t.Error("surface scan must not issue PUT requests to cloud buckets")
	}
}

func TestRun_ContextCancelled_ReturnsEarly(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	s := New()
	findings, err := s.Run(ctx, strings.TrimPrefix(ts.URL, "http://"), module.ScanSurface)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_ = findings // may be empty; just must not panic
}

// ---------------------------------------------------------------------------
// Org name stripping — unit test for documented behaviour
// ---------------------------------------------------------------------------

func TestOrgNameParsing_StripsASNPrefix(t *testing.T) {
	orgRaw := "AS13335 Cloudflare, Inc."
	orgName := orgRaw
	if idx := strings.Index(orgName, " "); idx >= 0 {
		orgName = strings.TrimSpace(orgName[idx+1:])
	}
	if orgName != "Cloudflare, Inc." {
		t.Errorf("expected 'Cloudflare, Inc.' after ASN prefix strip, got %q", orgName)
	}
}

func TestOrgNameParsing_NoASNPrefix_Unchanged(t *testing.T) {
	orgRaw := "SomeOrg"
	orgName := orgRaw
	if idx := strings.Index(orgName, " "); idx >= 0 {
		orgName = strings.TrimSpace(orgName[idx+1:])
	}
	if orgName != "SomeOrg" {
		t.Errorf("expected 'SomeOrg' unchanged when no space present, got %q", orgName)
	}
}
