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
	asset    string
	scanType module.ScanType
	client   *http.Client
	evidence *playbook.Evidence
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

// IsDeep returns true for ScanDeep and ScanAuthorized.
func (sc *ScanContext) IsDeep() bool {
	return sc.scanType == module.ScanDeep || sc.scanType == module.ScanAuthorized
}

// IsAuthorized returns true only for ScanAuthorized.
func (sc *ScanContext) IsAuthorized() bool {
	return sc.scanType == module.ScanAuthorized
}
