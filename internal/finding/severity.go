package finding

// Severity represents the risk level of a finding.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityCritical:
		return "critical"
	case SeverityHigh:
		return "high"
	case SeverityMedium:
		return "medium"
	case SeverityLow:
		return "low"
	default:
		return "info"
	}
}

func (s Severity) Weight() int {
	switch s {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 75
	case SeverityMedium:
		return 40
	case SeverityLow:
		return 10
	default:
		return 0
	}
}

// ParseSeverity converts a string to Severity. Returns SeverityInfo if unknown.
func ParseSeverity(s string) Severity {
	switch s {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityInfo
	}
}

// ConversionValue reflects how compelling a finding is as a reason to upgrade.
type ConversionValue int

const (
	ConversionLow ConversionValue = iota
	ConversionMedium
	ConversionHigh
)

func (c ConversionValue) Weight() int {
	switch c {
	case ConversionHigh:
		return 30
	case ConversionMedium:
		return 15
	default:
		return 0
	}
}

// FounderClarity reflects how understandable a finding is to a non-technical reader.
type FounderClarity int

const (
	ClarityLow FounderClarity = iota
	ClarityMedium
	ClarityHigh
)

func (f FounderClarity) Weight() int {
	switch f {
	case ClarityHigh:
		return 20
	case ClarityMedium:
		return 10
	default:
		return 0
	}
}
