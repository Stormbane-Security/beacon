package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/visibility"
)

//go:embed template/report.html.tmpl
var reportTemplateSource string

var reportTmpl = template.Must(
	template.New("report.html.tmpl").
		Funcs(template.FuncMap{
			"severityClass":   severityClass,
			"severityLabel":   SeverityLabel,
			"scanTypeLabel":   scanTypeLabel,
			"riskScore":       riskScore,
			"riskClass":       riskClass,
			"riskDescription": riskDescription,
			"duration":        fmtDuration,
			"truncate":        truncateStr,
			"hasEvidence":     hasEvidence,
			"joinStrings":     strings.Join,
			"inc":             func(i int) int { return i + 1 },
			"lower":           strings.ToLower,
		}).
		Parse(reportTemplateSource),
)

func render(data templateData) (string, error) {
	var buf bytes.Buffer
	if err := reportTmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func severityClass(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "critical"
	case finding.SeverityHigh:
		return "high"
	case finding.SeverityMedium:
		return "medium"
	case finding.SeverityLow:
		return "low"
	default:
		return "info"
	}
}

func scanTypeLabel(st module.ScanType) string {
	s := string(st)
	switch s {
	case "surface":
		return "Surface Scan"
	case "deep":
		return "Deep Scan"
	case "authorized":
		return "Authorized Scan"
	default:
		return "Scan"
	}
}

// riskScore computes a 0-100 risk score from severity counts.
// Weights: critical=25, high=10, medium=3, low=1. Capped at 100.
func riskScore(sc visibility.SeverityCount) int {
	score := sc.Critical*25 + sc.High*10 + sc.Medium*3 + sc.Low*1
	if score > 100 {
		score = 100
	}
	return score
}

func riskClass(sc visibility.SeverityCount) string {
	score := riskScore(sc)
	switch {
	case score >= 75:
		return "risk-critical"
	case score >= 50:
		return "risk-high"
	case score >= 25:
		return "risk-medium"
	case score > 0:
		return "risk-low"
	default:
		return "risk-info"
	}
}

func riskDescription(sc visibility.SeverityCount) string {
	score := riskScore(sc)
	switch {
	case score >= 75:
		return "Critical risk level. Immediate remediation required for critical and high-severity findings."
	case score >= 50:
		return "High risk level. Several significant findings require prompt attention."
	case score >= 25:
		return "Moderate risk level. Address medium-severity findings to strengthen the security posture."
	case score > 0:
		return "Low risk level. Minor findings identified; review at next maintenance window."
	default:
		return "No actionable findings detected. Continue monitoring."
	}
}

func fmtDuration(start, end time.Time) string {
	d := end.Sub(start)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func hasEvidence(f finding.Finding) bool {
	for k := range f.Evidence {
		if k != "image_b64" {
			return true
		}
	}
	return false
}
