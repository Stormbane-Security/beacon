package scan

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanlog"
)

// Scanner is the interface every individual scanner implements.
// This is the canonical definition — internal/scanner/types.go re-exports it
// as a type alias for backward compatibility.
type Scanner interface {
	Name() string
	Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error)
}

// Metrics captures scanner execution telemetry.
type Metrics struct {
	// Duration is the wall-clock time the scanner took.
	Duration time.Duration

	// ScannerName is the name of the scanner that produced this result.
	ScannerName string

	// Asset is the target that was scanned.
	Asset string

	// ScanType is the scan depth used.
	ScanType module.ScanType
}

// Result captures the complete output of a single scanner execution:
// findings, any error, and execution metrics. Module.go uses this to
// aggregate scanner health and emit observability data.
type Result struct {
	// Findings produced by the scanner (may be empty).
	Findings []finding.Finding

	// Error is non-nil if the scanner returned an error or panicked.
	Error error

	// Panicked is true if the scanner was recovered from a panic.
	Panicked bool

	// Metrics captures timing and metadata.
	Metrics Metrics
}

// OK returns true if the scanner completed without error.
func (r *Result) OK() bool { return r.Error == nil }

// AdaptFunc wraps a bare Run-signature function as a Scanner, useful for
// one-off adapters like OriginScanner.RunWithOriginIP.
func AdaptFunc(name string, fn func(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error)) Scanner {
	return &funcScanner{name: name, fn: fn}
}

type funcScanner struct {
	name string
	fn   func(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error)
}

func (f *funcScanner) Name() string { return f.name }
func (f *funcScanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	return f.fn(ctx, asset, scanType)
}

// ScannerTimeout returns the per-scanner execution timeout for the given
// scanner name. When a scanner exceeds its time budget on a single asset,
// the context is cancelled and it returns whatever findings it has so far.
//
// Default timeouts by scanner category:
//   - Injection scanners (cmdinj, sqli, ssti, crlf, openredir, hpp, xxe, etc.): 5 min
//   - Port scan: 3 min
//   - Nuclei: 10 min (runs many templates internally)
//   - All other scanners: 2 min
func ScannerTimeout(name string) time.Duration {
	if injectionScanners[name] {
		return 5 * time.Minute
	}
	switch name {
	case "portscan":
		return 3 * time.Minute
	case "nuclei":
		return 10 * time.Minute
	}
	return 2 * time.Minute
}

// injectionScanners enumerates scanners that perform parameter fuzzing
// and need a longer timeout due to the combinatorial probe space.
var injectionScanners = map[string]bool{
	"cmdinj":        true,
	"sqli":          true,
	"nosqli":        true,
	"ssti":          true,
	"crlf":          true,
	"openredir":     true,
	"hpp":           true,
	"xxe":           true,
	"rxss":          true,
	"ssrf":          true,
	"pathtraversal": true,
	"elinjection":   true,
	"pdfssrf":       true,
	"apifuzz":       true,
	"authfuzz":      true,
}

// IsInjectionScanner reports whether the named scanner is an injection/fuzzing
// scanner. Exported for use by the module layer.
func IsInjectionScanner(name string) bool {
	return injectionScanners[name]
}

// Execute runs a scanner with panic recovery, per-scanner timeout, and timing,
// returning a Result. This is the standard way module.go should call scanners
// — it never lets a scanner panic crash the scan, and it always captures duration.
//
// Each scanner gets a context with a timeout derived from ScannerTimeout(). If
// the parent context already has a tighter deadline, that deadline wins.
func Execute(s Scanner, ctx context.Context, asset string, scanType module.ScanType) (result *Result) {
	result = &Result{
		Metrics: Metrics{
			ScannerName: s.Name(),
			Asset:       asset,
			ScanType:    scanType,
		},
	}

	log := scanlog.FromContext(ctx)

	// Fast bail: if the host has been marked unresponsive due to consecutive
	// timeouts, skip this scanner entirely to avoid wasting time.
	if sctx, ok := FromContext(ctx); ok {
		if sctx.HostTimeouts().ShouldSkip(asset) {
			log.ScannerStart(s.Name(), asset)
			log.ScannerComplete(s.Name(), asset, 0, 0)
			result.Error = fmt.Errorf("scanner %s skipped: host %s bailed (consecutive timeouts)", s.Name(), asset)
			return result
		}
	}

	defer func() {
		if r := recover(); r != nil {
			result.Error = fmt.Errorf("scanner %s panicked: %v\n%s", s.Name(), r, debug.Stack())
			result.Panicked = true
			log.ScannerError(s.Name(), asset, result.Error)
		}
	}()

	// Per-scanner timeout — the scanner's context is cancelled when the
	// budget expires, and whatever findings have been collected so far are
	// returned. Scanners that check ctx.Err() in their probe loops will
	// exit cleanly; others will be interrupted on the next HTTP request.
	timeout := ScannerTimeout(s.Name())
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	log.ScannerStart(s.Name(), asset)
	start := time.Now()
	findings, err := s.Run(scanCtx, asset, scanType)
	result.Metrics.Duration = time.Since(start)
	result.Findings = findings
	result.Error = err

	// If the scanner was interrupted by the per-scanner timeout (not the
	// parent context), downgrade to a warning rather than a hard error so
	// partial findings are still included in the report.
	if scanCtx.Err() != nil && ctx.Err() == nil {
		result.Error = fmt.Errorf("scanner %s timed out after %s on %s (%d findings collected)", s.Name(), timeout, asset, len(findings))
		log.ScannerError(s.Name(), asset, result.Error)
	} else if err != nil {
		log.ScannerError(s.Name(), asset, err)
	}
	log.ScannerComplete(s.Name(), asset, len(findings), result.Metrics.Duration)

	return result
}
