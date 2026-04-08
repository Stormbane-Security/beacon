// Package scanlog provides structured logging for beacon scan operations.
// Every finding, scanner lifecycle event, and post-exploit chain step is
// logged as a JSON line, enabling offline analysis and debugging.
//
// Usage:
//
//	logger := scanlog.New("scan.log", slog.LevelDebug)
//	defer logger.Close()
//	ctx = scanlog.WithLogger(ctx, logger)
//
//	// Later, anywhere in the scan pipeline:
//	scanlog.FromContext(ctx).Finding(f)
//	scanlog.FromContext(ctx).ScannerStart("cors", "example.com")
package scanlog

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

type ctxKey struct{}

// Logger wraps slog.Logger with scan-specific convenience methods.
type Logger struct {
	*slog.Logger
	closer io.Closer
}

// New creates a Logger that writes structured JSON to the given file path.
// If path is empty, logs go to stderr. If path is "-", logs go to stdout.
func New(path string, level slog.Level) *Logger {
	opts := &slog.HandlerOptions{Level: level}
	var w io.Writer
	var closer io.Closer

	switch path {
	case "":
		w = os.Stderr
	case "-":
		w = os.Stdout
	default:
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			// Fall back to stderr if we can't open the file.
			w = os.Stderr
		} else {
			w = f
			closer = f
		}
	}

	handler := slog.NewJSONHandler(w, opts)
	return &Logger{
		Logger: slog.New(handler),
		closer: closer,
	}
}

// Close flushes and closes the underlying log file.
func (l *Logger) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// WithLogger returns a new context carrying the given Logger.
func WithLogger(ctx context.Context, l *Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, l)
}

// FromContext returns the Logger from the context, or a no-op logger
// if none was set.
func FromContext(ctx context.Context) *Logger {
	if l, ok := ctx.Value(ctxKey{}).(*Logger); ok && l != nil {
		return l
	}
	return nopLogger
}

// nopLogger discards all output.
var nopLogger = &Logger{
	Logger: slog.New(slog.NewJSONHandler(io.Discard, nil)),
}

// --- Scan lifecycle events ---

// ScanStart logs the beginning of a scan session.
func (l *Logger) ScanStart(domain, scanType string, assets []string) {
	l.Info("scan.start",
		slog.String("domain", domain),
		slog.String("scan_type", scanType),
		slog.Int("asset_count", len(assets)),
		slog.Time("started_at", time.Now()),
	)
}

// ScanComplete logs the end of a scan session.
func (l *Logger) ScanComplete(domain string, findingCount int, duration time.Duration) {
	l.Info("scan.complete",
		slog.String("domain", domain),
		slog.Int("finding_count", findingCount),
		slog.Duration("duration", duration),
	)
}

// ScannerStart logs a scanner beginning work on an asset.
func (l *Logger) ScannerStart(scanner, asset string) {
	l.Debug("scanner.start",
		slog.String("scanner", scanner),
		slog.String("asset", asset),
	)
}

// ScannerComplete logs a scanner finishing work.
func (l *Logger) ScannerComplete(scanner, asset string, findingCount int, duration time.Duration) {
	l.Debug("scanner.complete",
		slog.String("scanner", scanner),
		slog.String("asset", asset),
		slog.Int("finding_count", findingCount),
		slog.Duration("duration", duration),
	)
}

// ScannerError logs a scanner error.
func (l *Logger) ScannerError(scanner, asset string, err error) {
	l.Warn("scanner.error",
		slog.String("scanner", scanner),
		slog.String("asset", asset),
		slog.String("error", err.Error()),
	)
}

// --- Finding events ---

// Finding logs a discovered finding with full structured evidence.
func (l *Logger) Finding(f finding.Finding) {
	attrs := []any{
		slog.String("check_id", string(f.CheckID)),
		slog.String("scanner", f.Scanner),
		slog.String("asset", f.Asset),
		slog.String("severity", f.Severity.String()),
		slog.String("title", f.Title),
		slog.String("module", f.Module),
		slog.Bool("deep_only", f.DeepOnly),
	}
	if f.ProofCommand != "" {
		attrs = append(attrs, slog.String("proof_command", f.ProofCommand))
	}
	// Log evidence keys at top level for easy filtering
	for k, v := range f.Evidence {
		attrs = append(attrs, slog.Any("evidence."+k, v))
	}
	l.Info("finding.discovered", attrs...)
}

// --- Post-exploit events ---

// ExploitChainStart logs the beginning of a post-exploitation chain.
func (l *Logger) ExploitChainStart(scanner, asset, entryPoint string) {
	l.Info("exploit.chain_start",
		slog.String("scanner", scanner),
		slog.String("asset", asset),
		slog.String("entry_point", entryPoint),
	)
}

// ExploitChainStep logs an individual step in a post-exploitation chain.
func (l *Logger) ExploitChainStep(scanner, asset, step, target string, success bool) {
	l.Debug("exploit.chain_step",
		slog.String("scanner", scanner),
		slog.String("asset", asset),
		slog.String("step", step),
		slog.String("target", target),
		slog.Bool("success", success),
	)
}

// ExploitChainComplete logs the completion of a post-exploitation chain.
func (l *Logger) ExploitChainComplete(scanner, asset string, findingCount int) {
	l.Info("exploit.chain_complete",
		slog.String("scanner", scanner),
		slog.String("asset", asset),
		slog.Int("finding_count", findingCount),
	)
}

// --- Network/probe events ---

// ProbeAttempt logs an individual probe (HTTP request, TCP connection, etc.)
func (l *Logger) ProbeAttempt(scanner, target, probeType string, success bool, detail string) {
	l.Debug("probe.attempt",
		slog.String("scanner", scanner),
		slog.String("target", target),
		slog.String("probe_type", probeType),
		slog.Bool("success", success),
		slog.String("detail", detail),
	)
}

// ProbeTimed logs a probe with its duration for performance analysis.
func (l *Logger) ProbeTimed(scanner, target, probe string, duration time.Duration, status int, err error) {
	attrs := []any{
		slog.String("scanner", scanner),
		slog.String("target", target),
		slog.String("probe", probe),
		slog.Duration("duration", duration),
	}
	if status > 0 {
		attrs = append(attrs, slog.Int("status", status))
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	l.Debug("probe.timed", attrs...)
}

// ParseLevel converts a string level name to slog.Level.
func ParseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
