package scan

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
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

// Execute runs a scanner with panic recovery and timing, returning a Result.
// This is the standard way module.go should call scanners — it never lets
// a scanner panic crash the scan, and it always captures duration.
func Execute(s Scanner, ctx context.Context, asset string, scanType module.ScanType) (result *Result) {
	result = &Result{
		Metrics: Metrics{
			ScannerName: s.Name(),
			Asset:       asset,
			ScanType:    scanType,
		},
	}

	defer func() {
		if r := recover(); r != nil {
			result.Error = fmt.Errorf("scanner %s panicked: %v\n%s", s.Name(), r, debug.Stack())
			result.Panicked = true
		}
	}()

	start := time.Now()
	findings, err := s.Run(ctx, asset, scanType)
	result.Metrics.Duration = time.Since(start)
	result.Findings = findings
	result.Error = err

	return result
}
