// Package scan provides the shared scanning context, result types, and
// scanner registry used across all beacon scanners.
//
// ScanContext carries per-scan metadata (asset, scan type, HTTP client) through
// the standard context.Context chain. Scanners retrieve it via FromContext:
//
//	func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
//	    if sctx, ok := scan.FromContext(ctx); ok {
//	        client := sctx.HTTPClient()  // auth-wrapped client if configured
//	    }
//	}
package scan

import (
	"context"
	"net/http"
	"time"

	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/playbook"
)

type contextKey struct{}

// ScanContext carries per-scan metadata alongside the standard context.
// It is injected by the surface module before scanner execution and retrieved
// by scanners via FromContext.
type ScanContext struct {
	asset       string
	scanType    module.ScanType
	client      *http.Client
	evidence    *playbook.Evidence
	authHeaders map[string]string // raw auth headers for subprocess tools (katana, ffuf, etc.)
}

// NewContext creates a ScanContext for the given asset and scan type.
func NewContext(asset string, scanType module.ScanType) *ScanContext {
	return &ScanContext{
		asset:    asset,
		scanType: scanType,
	}
}

// WithHTTPClient sets the authenticated HTTP client.
func (sc *ScanContext) WithHTTPClient(c *http.Client) *ScanContext {
	sc.client = c
	return sc
}

// WithEvidence attaches the classify-phase evidence to the context.
func (sc *ScanContext) WithEvidence(ev *playbook.Evidence) *ScanContext {
	sc.evidence = ev
	return sc
}

// Inject stores this ScanContext inside a standard context.Context.
func (sc *ScanContext) Inject(ctx context.Context) context.Context {
	return context.WithValue(ctx, contextKey{}, sc)
}

// FromContext retrieves the ScanContext from a standard context.
// Returns nil, false if no ScanContext was injected.
func FromContext(ctx context.Context) (*ScanContext, bool) {
	sc, ok := ctx.Value(contextKey{}).(*ScanContext)
	return sc, ok
}

// Asset returns the target hostname being scanned.
func (sc *ScanContext) Asset() string { return sc.asset }

// ScanType returns the scan depth (surface, deep, authorized).
func (sc *ScanContext) ScanType() module.ScanType { return sc.scanType }

// HTTPClient returns the auth-wrapped HTTP client, or a default 15s-timeout
// client if none was injected.
func (sc *ScanContext) HTTPClient() *http.Client {
	if sc.client != nil {
		return sc.client
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// Evidence returns the classify-phase evidence for this asset, or nil
// if not yet available.
func (sc *ScanContext) Evidence() *playbook.Evidence { return sc.evidence }

// Scheme returns the HTTP scheme ("https" or "http") discovered during
// classification. Falls back to "https" if evidence is unavailable.
func (sc *ScanContext) Scheme() string {
	if sc.evidence != nil && sc.evidence.Scheme != "" {
		return sc.evidence.Scheme
	}
	return "https"
}

// BaseURL returns scheme + "://" + asset using the classified scheme.
func (sc *ScanContext) BaseURL(asset string) string {
	return sc.Scheme() + "://" + asset
}

// IsDeep returns true for ScanDeep and ScanAuthorized.
func (sc *ScanContext) IsDeep() bool {
	return sc.scanType == module.ScanDeep || sc.scanType == module.ScanAuthorized
}

// IsAuthorized returns true only for ScanAuthorized.
func (sc *ScanContext) IsAuthorized() bool {
	return sc.scanType == module.ScanAuthorized
}

// WithAuthHeaders stores raw auth headers for subprocess tools that can't
// use the Go HTTP client (katana, ffuf, etc.).
func (sc *ScanContext) WithAuthHeaders(headers map[string]string) *ScanContext {
	sc.authHeaders = headers
	return sc
}

// AuthHeaders returns the raw auth headers, or nil if no auth is configured.
func (sc *ScanContext) AuthHeaders() map[string]string { return sc.authHeaders }
