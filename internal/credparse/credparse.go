// Package credparse extracts and classifies credentials from arbitrary text.
//
// Any scanner that dumps data (database query results, config files, Redis
// values, environment variables, API responses) can feed it through
// credparse to identify actionable credentials without hardcoding what
// to look for. The classifier returns structured results that the pivot
// engine can use to determine next hops.
package credparse

import (
	"regexp"
	"strings"
)

// Credential represents an extracted credential with enough context
// to attempt a pivot.
type Credential struct {
	Type     string // aws_access_key, database_url, api_token, ssh_key, etc.
	Service  string // inferred service: aws, redis, postgres, stripe, github, etc.
	Value    string // the credential value itself
	Endpoint string // target endpoint if identifiable (host:port, URL)
	Username string // associated username/identity if found
	Context  string // surrounding text for attribution
}

// DataClass represents the classification of extracted data.
type DataClass struct {
	Type       string   // pii, credentials, secrets, application_data
	Indicators []string // which patterns matched
}

// pattern pairs a compiled regex with metadata about what it matches.
type pattern struct {
	re       *regexp.Regexp
	credType string
	service  string
}

var credPatterns = []pattern{
	// AWS
	{re: regexp.MustCompile(`(?:^|[^A-Z0-9])((AKIA|ASIA)[A-Z0-9]{16})(?:[^A-Z0-9]|$)`), credType: "aws_access_key", service: "aws"},
	{re: regexp.MustCompile(`(?i)(?:aws_?secret_?access_?key|secret_?key)['":\s=]+['"]?([A-Za-z0-9/+=]{40,})['"]?`), credType: "aws_secret_key", service: "aws"},

	// GCP
	{re: regexp.MustCompile(`(?i)(?:private_key_id|key_id)['":\s=]+['"]?([a-f0-9]{40})['"]?`), credType: "gcp_service_account_key", service: "gcp"},

	// GitHub
	{re: regexp.MustCompile(`(ghp_[A-Za-z0-9_]{20,})`), credType: "github_pat", service: "github"},
	{re: regexp.MustCompile(`(github_pat_[A-Za-z0-9_]{22,})`), credType: "github_pat_fine", service: "github"},
	{re: regexp.MustCompile(`(gho_[A-Za-z0-9]{20,})`), credType: "github_oauth", service: "github"},
	{re: regexp.MustCompile(`(ghs_[A-Za-z0-9]{20,})`), credType: "github_app", service: "github"},

	// Slack
	{re: regexp.MustCompile(`(xox[baprs]-[A-Za-z0-9\-]+)`), credType: "slack_token", service: "slack"},

	// Stripe
	{re: regexp.MustCompile(`(sk_(?:live|test)_[A-Za-z0-9]{24,})`), credType: "stripe_secret", service: "stripe"},
	{re: regexp.MustCompile(`(rk_(?:live|test)_[A-Za-z0-9]{24,})`), credType: "stripe_restricted", service: "stripe"},
	{re: regexp.MustCompile(`(whsec_[A-Za-z0-9]{24,})`), credType: "stripe_webhook_secret", service: "stripe"},

	// JWT / Bearer tokens
	{re: regexp.MustCompile(`(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})`), credType: "jwt", service: "jwt"},

	// Generic API keys (common patterns)
	{re: regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|api[_-]?token)['":\s=]+['"]?([A-Za-z0-9_\-]{20,})['"]?`), credType: "api_key", service: "unknown"},
	{re: regexp.MustCompile(`(?i)(?:auth[_-]?token|bearer[_-]?token|access[_-]?token)['":\s=]+['"]?([A-Za-z0-9_\-\.]{20,})['"]?`), credType: "auth_token", service: "unknown"},

	// Database connection strings
	{re: regexp.MustCompile(`(?i)((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s'"]+)`), credType: "database_url", service: "database"},

	// SSH private keys
	{re: regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)`), credType: "ssh_private_key", service: "ssh"},

	// Google OAuth
	{re: regexp.MustCompile(`(ya29\.[A-Za-z0-9_-]{30,})`), credType: "google_oauth", service: "google"},

	// SendGrid
	{re: regexp.MustCompile(`(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})`), credType: "sendgrid_api_key", service: "sendgrid"},

	// Twilio
	{re: regexp.MustCompile(`(SK[a-f0-9]{32})`), credType: "twilio_api_key", service: "twilio"},

	// Mailgun
	{re: regexp.MustCompile(`(key-[A-Za-z0-9]{32})`), credType: "mailgun_api_key", service: "mailgun"},

	// Heroku
	{re: regexp.MustCompile(`(?i)heroku['":\s=_]+['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?`), credType: "heroku_api_key", service: "heroku"},

	// Generic passwords in structured data (JSON, YAML, env var formats)
	{re: regexp.MustCompile(`(?i)(?:"password"|'password'|password)\s*['":\s=]+\s*['"]?([^\s'"}{,\]]{6,})['"]?`), credType: "password", service: "unknown"},
}

// Patterns for identifying service endpoints from extracted data.
var endpointPatterns = []struct {
	re      *regexp.Regexp
	service string
}{
	{re: regexp.MustCompile(`(?i)(?:host|endpoint|url|server)['":\s=]+['"]?((?:\w[\w.-]+):\d{2,5})['"]?`), service: ""},
	{re: regexp.MustCompile(`(?i)(https?://[^\s'"}{,\]]+)`), service: "http"},
	{re: regexp.MustCompile(`(?i)(?:redis|cache)['":\s=_]*(?:host|url|endpoint)?['":\s=]+['"]?([^\s'"}{,\]]+:\d{2,5})['"]?`), service: "redis"},
	{re: regexp.MustCompile(`(?i)s3://([^\s'"}{,\]]+)`), service: "s3"},
}

// PII indicators for data classification.
var piiIndicators = []string{
	"ssn", "social_security", "social security",
	"credit_card", "creditcard", "credit card", "card_number",
	"date_of_birth", "dob", "birth_date",
	"passport", "driver_license", "drivers_license",
	"phone_number", "phone", "mobile",
	"address", "zip_code", "zipcode", "postal",
	"national_id", "tax_id", "tin",
}

// SSN/CC format patterns for detecting PII by value shape, not just field name.
var piiValuePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),                                     // SSN
	regexp.MustCompile(`\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`),                   // Credit card
	regexp.MustCompile(`\b[A-Z]{1,2}\d{6,9}\b`),                                      // Passport
	regexp.MustCompile(`\b\d{3}[- ]?\d{3}[- ]?\d{4}\b`),                              // Phone (US)
	regexp.MustCompile(`(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`),              // Email
}

// ExtractCredentials scans arbitrary text for credential patterns and returns
// all matches with classification. This is the main entry point — any scanner
// that extracts data from a target feeds it through here.
func ExtractCredentials(data string) []Credential {
	var creds []Credential
	seen := make(map[string]bool)

	for _, p := range credPatterns {
		matches := p.re.FindAllStringSubmatch(data, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			val := m[1]
			key := p.credType + ":" + val
			if seen[key] {
				continue
			}
			seen[key] = true

			cred := Credential{
				Type:    p.credType,
				Service: p.service,
				Value:   val,
				Context: extractContext(data, m[0], 80),
			}

			// Try to find associated endpoint.
			if p.credType == "database_url" {
				cred.Endpoint = val
				cred.Service = inferServiceFromURL(val)
			} else {
				cred.Endpoint = findNearbyEndpoint(data, m[0])
			}

			// Try to find associated username.
			cred.Username = findNearbyUsername(data, m[0])

			creds = append(creds, cred)
		}
	}

	return creds
}

// ClassifyData determines whether extracted data contains PII, credentials,
// secrets, or just application data. Returns the highest-severity classification.
func ClassifyData(data string) DataClass {
	lower := strings.ToLower(data)

	// Check for PII by field name.
	var indicators []string
	for _, indicator := range piiIndicators {
		if strings.Contains(lower, indicator) {
			indicators = append(indicators, indicator)
		}
	}

	// Check for PII by value patterns.
	for _, p := range piiValuePatterns {
		if p.MatchString(data) {
			indicators = append(indicators, "value_pattern:"+p.String()[:20])
		}
	}

	if len(indicators) > 0 {
		return DataClass{Type: "pii", Indicators: indicators}
	}

	// Check for credentials.
	creds := ExtractCredentials(data)
	if len(creds) > 0 {
		for _, c := range creds {
			indicators = append(indicators, c.Type)
		}
		return DataClass{Type: "credentials", Indicators: indicators}
	}

	// Check for generic secret indicators.
	secretWords := []string{"secret", "private_key", "token", "bearer", "authorization"}
	for _, word := range secretWords {
		if strings.Contains(lower, word) {
			indicators = append(indicators, word)
		}
	}
	if len(indicators) > 0 {
		return DataClass{Type: "secrets", Indicators: indicators}
	}

	return DataClass{Type: "application_data"}
}

// extractContext returns surrounding text around a match for attribution.
func extractContext(data, match string, radius int) string {
	idx := strings.Index(data, match)
	if idx < 0 {
		return ""
	}
	start := idx - radius
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + radius
	if end > len(data) {
		end = len(data)
	}
	return data[start:end]
}

// findNearbyEndpoint looks for host:port or URL patterns near a credential match.
func findNearbyEndpoint(data, match string) string {
	// Look in a window around the match.
	idx := strings.Index(data, match)
	if idx < 0 {
		return ""
	}
	start := idx - 200
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + 200
	if end > len(data) {
		end = len(data)
	}
	window := data[start:end]

	for _, ep := range endpointPatterns {
		m := ep.re.FindStringSubmatch(window)
		if len(m) >= 2 {
			return m[1]
		}
	}
	return ""
}

// findNearbyUsername looks for username/user patterns near a credential match.
func findNearbyUsername(data, match string) string {
	idx := strings.Index(data, match)
	if idx < 0 {
		return ""
	}
	start := idx - 200
	if start < 0 {
		start = 0
	}
	end := idx + len(match) + 200
	if end > len(data) {
		end = len(data)
	}
	window := data[start:end]

	re := regexp.MustCompile(`(?i)(?:"user(?:name)?"|'user(?:name)?'|user(?:name)?\s*[:=])\s*['"]?([^\s'"}{,\]]{2,})['"]?`)
	m := re.FindStringSubmatch(window)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// inferServiceFromURL extracts the service type from a connection string URL.
func inferServiceFromURL(url string) string {
	lower := strings.ToLower(url)
	switch {
	case strings.HasPrefix(lower, "postgres"):
		return "postgres"
	case strings.HasPrefix(lower, "mysql"):
		return "mysql"
	case strings.HasPrefix(lower, "mongodb"):
		return "mongodb"
	case strings.HasPrefix(lower, "redis"):
		return "redis"
	case strings.HasPrefix(lower, "amqp"):
		return "rabbitmq"
	default:
		return "database"
	}
}
