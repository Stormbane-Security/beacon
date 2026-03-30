package finding

import "testing"

func TestParseSeverity_CaseInsensitive(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{"critical", SeverityCritical},
		{"Critical", SeverityCritical},
		{"CRITICAL", SeverityCritical},
		{"high", SeverityHigh},
		{"HIGH", SeverityHigh},
		{"High", SeverityHigh},
		{"medium", SeverityMedium},
		{"MEDIUM", SeverityMedium},
		{"low", SeverityLow},
		{"LOW", SeverityLow},
		{"info", SeverityInfo},
		{"INFO", SeverityInfo},
		{"unknown", SeverityInfo},
		{"", SeverityInfo},
	}
	for _, tc := range tests {
		got := ParseSeverity(tc.input)
		if got != tc.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestSeverity_String(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityCritical, "critical"},
		{SeverityHigh, "high"},
		{SeverityMedium, "medium"},
		{SeverityLow, "low"},
		{SeverityInfo, "info"},
		{Severity(99), "info"},
	}
	for _, tc := range tests {
		if got := tc.sev.String(); got != tc.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tc.sev, got, tc.want)
		}
	}
}

func TestSeverity_Weight(t *testing.T) {
	if SeverityCritical.Weight() <= SeverityHigh.Weight() {
		t.Error("critical weight should be greater than high")
	}
	if SeverityHigh.Weight() <= SeverityMedium.Weight() {
		t.Error("high weight should be greater than medium")
	}
	if SeverityMedium.Weight() <= SeverityLow.Weight() {
		t.Error("medium weight should be greater than low")
	}
	if SeverityLow.Weight() <= SeverityInfo.Weight() {
		t.Error("low weight should be greater than info")
	}
	if SeverityInfo.Weight() != 0 {
		t.Error("info weight should be 0")
	}
}
