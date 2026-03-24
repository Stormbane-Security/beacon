package report

import (
	"bytes"
	_ "embed"
	"html/template"

	"github.com/stormbane/beacon/internal/finding"
)

//go:embed template/report.html.tmpl
var reportTemplateSource string

var reportTmpl = template.Must(
	template.New("report.html.tmpl").
		Funcs(template.FuncMap{
			"severityClass": severityClass,
			"severityLabel": SeverityLabel,
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
