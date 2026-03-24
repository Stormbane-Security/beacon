package cloudbuckets

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stormbane/beacon/internal/finding"
)

// TestProbeWrite_Writable_CriticalFinding verifies that a bucket accepting
// unauthenticated PUT returns a Critical finding and attempts a DELETE cleanup.
func TestProbeWrite_Writable_CriticalFinding(t *testing.T) {
	var deleteCalled bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			deleteCalled = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer ts.Close()

	f := probeWrite(context.Background(), ts.Client(), "example.com", ts.URL+"/", "AWS S3", "example-bucket", time.Now())
	if f == nil {
		t.Fatal("expected a finding for publicly writable bucket, got nil")
	}
	if f.CheckID != finding.CheckCloudBucketWritable {
		t.Errorf("expected CheckCloudBucketWritable, got %s", f.CheckID)
	}
	if f.Severity != finding.SeverityCritical {
		t.Errorf("expected Critical severity, got %s", f.Severity)
	}
	if !deleteCalled {
		t.Error("expected DELETE request to clean up test object, but none was made")
	}
}

// TestProbeWrite_NoContent_CriticalFinding verifies that HTTP 204 (S3-style
// successful PUT) is also treated as a writable bucket.
func TestProbeWrite_NoContent_CriticalFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer ts.Close()

	f := probeWrite(context.Background(), ts.Client(), "example.com", ts.URL+"/", "GCS", "example-bucket", time.Now())
	if f == nil {
		t.Fatal("expected a finding for 204 PUT response, got nil")
	}
	if f.CheckID != finding.CheckCloudBucketWritable {
		t.Errorf("expected CheckCloudBucketWritable, got %s", f.CheckID)
	}
}

// TestProbeWrite_Forbidden_NoFinding verifies that a 403 response (write denied)
// produces no finding.
func TestProbeWrite_Forbidden_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer ts.Close()

	f := probeWrite(context.Background(), ts.Client(), "example.com", ts.URL+"/", "AWS S3", "example-bucket", time.Now())
	if f != nil {
		t.Errorf("expected nil finding for 403 PUT response, got %+v", f)
	}
}

// TestProbeWrite_NotFound_NoFinding verifies that a 404 response produces no finding.
func TestProbeWrite_NotFound_NoFinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	f := probeWrite(context.Background(), ts.Client(), "example.com", ts.URL+"/", "GCS", "example-bucket", time.Now())
	if f != nil {
		t.Errorf("expected nil finding for 404 PUT response, got %+v", f)
	}
}

// TestProbeWrite_NetworkError_NoFinding verifies graceful handling of connection failure.
func TestProbeWrite_NetworkError_NoFinding(t *testing.T) {
	f := probeWrite(context.Background(), &http.Client{}, "example.com", "http://127.0.0.1:1/", "AWS S3", "x", time.Now())
	if f != nil {
		t.Errorf("expected nil finding on network error, got %+v", f)
	}
}

// TestProbeWrite_WriteURLContainsTestKey verifies the evidence includes the write URL.
func TestProbeWrite_WriteURLContainsTestKey(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	f := probeWrite(context.Background(), ts.Client(), "example.com", ts.URL+"/", "AWS S3", "example-bucket", time.Now())
	if f == nil {
		t.Fatal("expected finding")
	}
	writeURL, _ := f.Evidence["write_url"].(string)
	if writeURL == "" {
		t.Error("expected write_url in evidence")
	}
	const testKey = "beacon-scanner-write-test"
	if len(writeURL) < len(testKey) || writeURL[len(writeURL)-len(testKey):] != testKey {
		t.Errorf("write_url %q does not end with test key %q", writeURL, testKey)
	}
}
