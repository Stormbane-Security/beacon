package scan

import (
	"context"
	"net/http"
	"testing"

	"github.com/stormbane-security/beacon/internal/module"
)

func TestScanContextInjectRetrieve(t *testing.T) {
	sctx := NewContext("example.com", module.ScanDeep)
	ctx := sctx.Inject(context.Background())

	got, ok := FromContext(ctx)
	if !ok {
		t.Fatal("FromContext returned false")
	}
	if got.Asset() != "example.com" {
		t.Errorf("Asset() = %q, want %q", got.Asset(), "example.com")
	}
	if got.ScanType() != module.ScanDeep {
		t.Errorf("ScanType() = %q, want %q", got.ScanType(), module.ScanDeep)
	}
}

func TestScanContextDefaultHTTPClient(t *testing.T) {
	sctx := NewContext("example.com", module.ScanSurface)
	c := sctx.HTTPClient()
	if c == nil {
		t.Fatal("HTTPClient() returned nil")
	}
}

func TestScanContextCustomHTTPClient(t *testing.T) {
	custom := &http.Client{}
	sctx := NewContext("example.com", module.ScanSurface).WithHTTPClient(custom)
	if sctx.HTTPClient() != custom {
		t.Error("HTTPClient() did not return injected client")
	}
}

func TestScanContextIsDeep(t *testing.T) {
	tests := []struct {
		st   module.ScanType
		deep bool
		auth bool
	}{
		{module.ScanSurface, false, false},
		{module.ScanDeep, true, false},
		{module.ScanAuthorized, true, true},
	}
	for _, tt := range tests {
		sctx := NewContext("x", tt.st)
		if sctx.IsDeep() != tt.deep {
			t.Errorf("IsDeep(%s) = %v, want %v", tt.st, sctx.IsDeep(), tt.deep)
		}
		if sctx.IsAuthorized() != tt.auth {
			t.Errorf("IsAuthorized(%s) = %v, want %v", tt.st, sctx.IsAuthorized(), tt.auth)
		}
	}
}

func TestFromContextMissing(t *testing.T) {
	_, ok := FromContext(context.Background())
	if ok {
		t.Error("FromContext should return false for plain context")
	}
}
