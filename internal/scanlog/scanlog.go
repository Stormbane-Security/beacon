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

// --- Probe execution events ---

// ProbeResult logs a completed probe with findings summary.
func (l *Logger) ProbeResult(probeName string, port int, duration time.Duration, findingCount int, version string, skipped bool, skipReason string) {
	attrs := []any{
		slog.String("probe", probeName),
		slog.Int("port", port),
		slog.Duration("duration", duration),
		slog.Int("finding_count", findingCount),
	}
	if version != "" {
		attrs = append(attrs, slog.String("version", version))
	}
	if skipped {
		attrs = append(attrs, slog.Bool("skipped", true))
		attrs = append(attrs, slog.String("skip_reason", skipReason))
	}
	l.Debug("probe.result", attrs...)
}

// ProbeSkipped logs a probe that was skipped due to category mismatch.
func (l *Logger) ProbeSkipped(probeName string, port int, reason string) {
	l.Debug("probe.skipped",
		slog.String("probe", probeName),
		slog.Int("port", port),
		slog.String("reason", reason),
	)
}

// --- CVE version check events ---

// CVEVersionCheckStart logs the start of a CVE version check.
func (l *Logger) CVEVersionCheckStart(service, version string) {
	l.Debug("cve.version_check_start",
		slog.String("service", service),
		slog.String("version", version),
	)
}

// CVEVersionRuleEvaluated logs a single CVE rule evaluation.
func (l *Logger) CVEVersionRuleEvaluated(service, version, cve, checkID string, matched bool, reason string) {
	l.Debug("cve.rule_evaluated",
		slog.String("service", service),
		slog.String("version", version),
		slog.String("cve", cve),
		slog.String("check_id", checkID),
		slog.Bool("matched", matched),
		slog.String("reason", reason),
	)
}

// CVEVersionCheckComplete logs the completion of CVE version checking.
func (l *Logger) CVEVersionCheckComplete(service, version string, rulesChecked, matched int) {
	l.Debug("cve.version_check_complete",
		slog.String("service", service),
		slog.String("version", version),
		slog.Int("rules_checked", rulesChecked),
		slog.Int("matched", matched),
	)
}

// --- Chain engine events ---

// ChainEvaluate logs a finding being evaluated for chain routing.
func (l *Logger) ChainEvaluate(checkID, asset, routeType, playbookName string, cveChainCount int) {
	attrs := []any{
		slog.String("check_id", checkID),
		slog.String("asset", asset),
		slog.String("route_type", routeType),
		slog.String("playbook", playbookName),
	}
	if cveChainCount > 0 {
		attrs = append(attrs, slog.Int("cve_chain_count", cveChainCount))
	}
	l.Debug("chain.evaluate", attrs...)
}

// ChainTriggered logs a chain being triggered by a finding.
func (l *Logger) ChainTriggered(chainName, checkID, asset string) {
	l.Debug("chain.triggered",
		slog.String("chain", chainName),
		slog.String("check_id", checkID),
		slog.String("asset", asset),
	)
}

// ChainNoMatch logs that no chain matched a finding.
func (l *Logger) ChainNoMatch(checkID, asset string) {
	l.Debug("chain.no_match",
		slog.String("check_id", checkID),
		slog.String("asset", asset),
	)
}

// --- Exploit chain step events ---

// ExploitStepResult logs an individual exploit step execution.
func (l *Logger) ExploitStepResult(stepName, method, path string, success bool, statusCode int, patternMatched bool, duration time.Duration) {
	attrs := []any{
		slog.String("step", stepName),
		slog.String("method", method),
		slog.String("path", path),
		slog.Bool("success", success),
		slog.Duration("duration", duration),
	}
	if statusCode > 0 {
		attrs = append(attrs, slog.Int("status_code", statusCode))
	}
	attrs = append(attrs, slog.Bool("pattern_matched", patternMatched))
	l.Debug("exploit.step_result", attrs...)
}

// --- Post-exploit module events ---

// PostExploitModuleStart logs a post-exploit module starting.
func (l *Logger) PostExploitModuleStart(moduleName, host string, port int) {
	l.Debug("postexploit.module_start",
		slog.String("module", moduleName),
		slog.String("host", host),
		slog.Int("port", port),
	)
}

// PostExploitModuleComplete logs a post-exploit module finishing.
func (l *Logger) PostExploitModuleComplete(moduleName, host string, port int, findingCount int, dataSummary string, duration time.Duration) {
	attrs := []any{
		slog.String("module", moduleName),
		slog.String("host", host),
		slog.Int("port", port),
		slog.Int("finding_count", findingCount),
		slog.Duration("duration", duration),
	}
	if dataSummary != "" {
		attrs = append(attrs, slog.String("data_summary", dataSummary))
	}
	l.Debug("postexploit.module_complete", attrs...)
}

// --- Phase timing events ---

// PhaseComplete logs the duration of a major scan phase.
func (l *Logger) PhaseComplete(phase, asset string, duration time.Duration, detail string) {
	attrs := []any{
		slog.String("phase", phase),
		slog.Duration("duration", duration),
	}
	if asset != "" {
		attrs = append(attrs, slog.String("asset", asset))
	}
	if detail != "" {
		attrs = append(attrs, slog.String("detail", detail))
	}
	l.Debug("phase.complete", attrs...)
}

// --- Utility ---

// IsDebug returns true if the logger is configured at debug level or below.
// Use this to gate expensive debug-only computation (e.g. building summary strings).
func (l *Logger) IsDebug() bool {
	return l.Enabled(context.Background(), slog.LevelDebug)
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
