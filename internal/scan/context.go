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
	"sync"
	"time"

	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/oob"
	"github.com/stormbane-security/beacon/internal/playbook"
)

type contextKey struct{}

// ScanContext carries per-scan metadata alongside the standard context.
// It is injected by the surface module before scanner execution and retrieved
// by scanners via FromContext.
type ScanContext struct {
	asset        string
	scanType     module.ScanType
	client       *http.Client
	evidence     *playbook.Evidence
	authHeaders  map[string]string // raw auth headers for subprocess tools (katana, ffuf, etc.)
	wordlistPath string            // custom wordlist file path for brute-force scanners

	screenshotEnabled bool // true when --screenshots is set

	honeypotDetected bool // true when the honeypot scanner identifies the asset as a honeypot

	// oobServer is the out-of-band callback server, lazily initialized on
	// first call to OOBServer(). Scanners use it to generate callback URLs
	// for blind SSRF, blind XXE, blind SQLi OOB, etc.
	oobOnce   sync.Once
	oobServer *oob.Server

	// responseCache is lazily initialized on first call to ResponseCache().
	responseCacheOnce sync.Once
	responseCache     *ResponseCache

	// hostTimeouts tracks consecutive HTTP timeouts per host. When a host
	// exceeds the threshold, remaining probes are skipped to avoid wasting
	// minutes on unresponsive targets.
	hostTimeoutOnce    sync.Once
	hostTimeoutTracker *HostTimeoutTracker
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
// client using the shared connection-pooled transport if none was injected.
func (sc *ScanContext) HTTPClient() *http.Client {
	if sc.client != nil {
		return sc.client
	}
	return SharedClient(15 * time.Second)
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

// WithWordlist sets a custom wordlist file path for brute-force scanners
// (directory brute-force, subdomain brute-force, parameter discovery).
func (sc *ScanContext) WithWordlist(path string) *ScanContext {
	sc.wordlistPath = path
	return sc
}

// WordlistPath returns the custom wordlist file path, or "" if none was set.
func (sc *ScanContext) WordlistPath() string { return sc.wordlistPath }

// WithScreenshots marks the scan as having screenshots enabled.
func (sc *ScanContext) WithScreenshots(enabled bool) *ScanContext {
	sc.screenshotEnabled = enabled
	return sc
}

// ScreenshotsEnabled reports whether the --screenshots flag was set.
func (sc *ScanContext) ScreenshotsEnabled() bool { return sc.screenshotEnabled }

// SetHoneypotDetected marks the asset as a honeypot so downstream scanners
// (chain engine, exploit playbooks) can skip exploitation to avoid detection.
func (sc *ScanContext) SetHoneypotDetected(v bool) { sc.honeypotDetected = v }

// HoneypotDetected reports whether the honeypot scanner flagged this asset.
func (sc *ScanContext) HoneypotDetected() bool { return sc.honeypotDetected }

// SharedClient returns a pooled HTTP client using the shared transport.
// When no auth client is configured, this avoids redundant TCP+TLS handshakes
// across scanners hitting the same target.
func (sc *ScanContext) SharedClient() *http.Client {
	if sc.client != nil {
		return sc.client
	}
	return SharedClient(15 * time.Second)
}

// OOBServer returns the out-of-band callback server, lazily initializing it
// on first call. Scanners use it to generate unique callback tokens and URLs
// for blind vulnerability confirmation (SSRF, XXE, SQLi OOB, etc.).
// Returns nil if the server cannot be started.
func (sc *ScanContext) OOBServer() *oob.Server {
	sc.oobOnce.Do(func() {
		srv := oob.NewServer("oob.beacon.local", "127.0.0.1:0")
		if err := srv.Start(context.Background()); err != nil {
			return
		}
		sc.oobServer = srv
	})
	return sc.oobServer
}

// WithOOBServer sets an externally-configured OOB server (e.g., one with a
// public domain and tunnel). Overrides the lazy-init default.
func (sc *ScanContext) WithOOBServer(srv *oob.Server) *ScanContext {
	sc.oobServer = srv
	sc.oobOnce.Do(func() {}) // mark as initialized
	return sc
}

// ResponseCache returns the per-scan response cache (lazily initialized).
// Multiple scanners sharing a cache avoid duplicate fetches of the same URL.
func (sc *ScanContext) ResponseCache() *ResponseCache {
	sc.responseCacheOnce.Do(func() {
		sc.responseCache = NewResponseCache(sc.SharedClient())
	})
	return sc.responseCache
}

// HostTimeouts returns the per-scan host timeout tracker (lazily initialized).
// Scanners and transport layers use this to bail early on hosts that are
// consistently timing out, avoiding minutes of wasted probes.
func (sc *ScanContext) HostTimeouts() *HostTimeoutTracker {
	sc.hostTimeoutOnce.Do(func() {
		sc.hostTimeoutTracker = NewHostTimeoutTracker()
	})
	return sc.hostTimeoutTracker
}

// WithHostTimeoutTracker injects an externally-created tracker. Used when
// the tracker needs to be shared across scan contexts (e.g., across Phase A
// and Phase B of the same asset).
func (sc *ScanContext) WithHostTimeoutTracker(t *HostTimeoutTracker) *ScanContext {
	sc.hostTimeoutTracker = t
	sc.hostTimeoutOnce.Do(func() {}) // mark as initialized
	return sc
}
