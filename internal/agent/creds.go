package agent

import (
	"regexp"
	"strings"
)

// credPatterns match common credential patterns in environment variables and files.
var credPatterns = []struct {
	name    string
	credType string
	pattern *regexp.Regexp
}{
	{"AWS Access Key", "api_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"AWS Secret Key", "api_key", regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)\s*[=:]\s*([A-Za-z0-9/+=]{40})`)},
	{"GitHub Token", "token", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{"GitHub OAuth", "token", regexp.MustCompile(`gho_[A-Za-z0-9]{36}`)},
	{"GitHub PAT", "token", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`)},
	{"GitLab Token", "token", regexp.MustCompile(`glpat-[A-Za-z0-9\-]{20,}`)},
	{"Slack Token", "token", regexp.MustCompile(`xox[bpors]-[0-9]{10,}-[A-Za-z0-9-]+`)},
	{"Stripe Key", "api_key", regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`)},
	{"Stripe Test Key", "api_key", regexp.MustCompile(`sk_test_[A-Za-z0-9]{24,}`)},
	{"Heroku API Key", "api_key", regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)},
	{"Generic API Key", "api_key", regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?([A-Za-z0-9]{20,})['"]?`)},
	{"Generic Password", "password", regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]{4,})['"]?`)},
	{"Generic Secret", "password", regexp.MustCompile(`(?i)(secret|secret_key)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?`)},
	{"Database URL", "connection_string", regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^\s'"]+`)},
	{"Connection String", "connection_string", regexp.MustCompile(`(?i)(jdbc|amqp|redis)://[^\s'"]+`)},
	{"Private Key Header", "ssh_key", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`)},
	{"Bearer Token", "token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*`)},
}

// sensitiveEnvKeys are environment variable names that commonly hold secrets.
var sensitiveEnvKeys = []string{
	"PASSWORD", "PASSWD", "PWD",
	"SECRET", "SECRET_KEY",
	"API_KEY", "APIKEY",
	"TOKEN", "AUTH_TOKEN", "ACCESS_TOKEN",
	"DATABASE_URL", "DB_PASSWORD", "DB_PASS",
	"REDIS_URL", "REDIS_PASSWORD",
	"MONGO_URL", "MONGODB_URI",
	"AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
	"GITHUB_TOKEN", "GH_TOKEN",
	"GITLAB_TOKEN",
	"SLACK_TOKEN", "SLACK_WEBHOOK",
	"STRIPE_SECRET_KEY",
	"SENDGRID_API_KEY",
	"TWILIO_AUTH_TOKEN",
	"PRIVATE_KEY",
	"ENCRYPTION_KEY",
	"JWT_SECRET",
	"SESSION_SECRET",
	"COOKIE_SECRET",
}

// extractCredentials searches environment variables and file contents for credentials.
func extractCredentials(env map[string]string, files []FileEvidence) []Credential {
	var creds []Credential
	seen := make(map[string]bool) // dedup by value

	// Check environment variables by name.
	for _, key := range sensitiveEnvKeys {
		for envKey, envVal := range env {
			if strings.EqualFold(envKey, key) || strings.Contains(strings.ToUpper(envKey), key) {
				if envVal != "" && !seen[envVal] {
					seen[envVal] = true
					creds = append(creds, Credential{
						Source:   "env:" + envKey,
						Type:     classifyEnvCredType(envKey),
						Username: envKey,
						Value:    envVal,
					})
				}
			}
		}
	}

	// Apply regex patterns to all environment values.
	for envKey, envVal := range env {
		for _, pat := range credPatterns {
			if matches := pat.pattern.FindString(envVal); matches != "" && !seen[matches] {
				seen[matches] = true
				creds = append(creds, Credential{
					Source: "env:" + envKey,
					Type:   pat.credType,
					Value:  matches,
				})
			}
		}
	}

	// Apply regex patterns to file contents.
	for _, f := range files {
		if f.Content == "" {
			continue
		}
		for _, pat := range credPatterns {
			matches := pat.pattern.FindAllString(f.Content, 5) // limit matches per file
			for _, m := range matches {
				if !seen[m] {
					seen[m] = true
					creds = append(creds, Credential{
						Source: "file:" + f.Path,
						Type:   pat.credType,
						Value:  m,
					})
				}
			}
		}
	}

	return creds
}

func classifyEnvCredType(key string) string {
	upper := strings.ToUpper(key)
	switch {
	case strings.Contains(upper, "PASSWORD") || strings.Contains(upper, "PASSWD") || strings.Contains(upper, "SECRET"):
		return "password"
	case strings.Contains(upper, "TOKEN"):
		return "token"
	case strings.Contains(upper, "KEY"):
		return "api_key"
	case strings.Contains(upper, "URL") || strings.Contains(upper, "URI"):
		return "connection_string"
	default:
		return "password"
	}
}
