package credparse

import (
	"testing"
)

func TestExtractCredentials_AWSKeys(t *testing.T) {
	data := `{"access_key":"AKIAIOSFODNN7EXAMPLE","secret_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`
	creds := ExtractCredentials(data)

	var foundAccess, foundSecret bool
	for _, c := range creds {
		if c.Type == "aws_access_key" && c.Value == "AKIAIOSFODNN7EXAMPLE" {
			foundAccess = true
		}
		if c.Type == "aws_secret_key" {
			foundSecret = true
		}
	}
	if !foundAccess {
		t.Error("did not find AWS access key")
	}
	if !foundSecret {
		t.Error("did not find AWS secret key")
	}
}

func TestExtractCredentials_AWSTemporarySTS(t *testing.T) {
	data := `{"access_key":"ASIAJEXAMPLETMPCREDS","secret_key":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`
	creds := ExtractCredentials(data)

	var found bool
	for _, c := range creds {
		if c.Type == "aws_access_key" && c.Value == "ASIAJEXAMPLETMPCREDS" {
			found = true
		}
	}
	if !found {
		t.Error("did not find AWS temporary STS access key (ASIA prefix)")
	}
}

func TestExtractCredentials_GitHubPAT(t *testing.T) {
	data := `token: ghp_ExampleGitHubPAT0000000000000000000`
	creds := ExtractCredentials(data)

	found := false
	for _, c := range creds {
		if c.Type == "github_pat" && c.Service == "github" {
			found = true
		}
	}
	if !found {
		t.Error("did not find GitHub PAT")
	}
}

func TestExtractCredentials_SlackToken(t *testing.T) {
	data := `"slack": "xoxb-example-slack-bot-token"`
	creds := ExtractCredentials(data)

	found := false
	for _, c := range creds {
		if c.Type == "slack_token" && c.Service == "slack" {
			found = true
		}
	}
	if !found {
		t.Error("did not find Slack token")
	}
}

func TestExtractCredentials_StripeKey(t *testing.T) {
	data := `{"api_key":"sk_test_FAKE00000000000000000000000"}`
	creds := ExtractCredentials(data)

	found := false
	for _, c := range creds {
		if c.Type == "stripe_secret" && c.Service == "stripe" {
			found = true
		}
	}
	if !found {
		t.Error("did not find Stripe secret key")
	}
}

func TestExtractCredentials_JWT(t *testing.T) {
	data := `"token":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.fakesignaturehere"`
	creds := ExtractCredentials(data)

	found := false
	for _, c := range creds {
		if c.Type == "jwt" {
			found = true
		}
	}
	if !found {
		t.Error("did not find JWT")
	}
}

func TestExtractCredentials_DatabaseURL(t *testing.T) {
	data := `DATABASE_URL=postgres://admin:secret@db.internal:5432/production`
	creds := ExtractCredentials(data)

	found := false
	for _, c := range creds {
		if c.Type == "database_url" && c.Service == "postgres" {
			found = true
			if c.Endpoint == "" {
				t.Error("database_url should have endpoint set")
			}
		}
	}
	if !found {
		t.Error("did not find database URL")
	}
}

func TestExtractCredentials_RedisURL(t *testing.T) {
	data := `REDIS_URL=redis://default:authtoken@redis:6379/0`
	creds := ExtractCredentials(data)

	found := false
	for _, c := range creds {
		if c.Type == "database_url" && c.Service == "redis" {
			found = true
		}
	}
	if !found {
		t.Error("did not find Redis URL")
	}
}

func TestExtractCredentials_SSHKey(t *testing.T) {
	data := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3...
-----END RSA PRIVATE KEY-----`
	creds := ExtractCredentials(data)

	found := false
	for _, c := range creds {
		if c.Type == "ssh_private_key" && c.Service == "ssh" {
			found = true
		}
	}
	if !found {
		t.Error("did not find SSH key")
	}
}

func TestExtractCredentials_Password(t *testing.T) {
	data := `{"host":"db.internal","port":5432,"user":"app_rw","password":"Pr0d_DB_P@ss!","database":"production"}`
	creds := ExtractCredentials(data)

	var foundPwd bool
	for _, c := range creds {
		if c.Type == "password" {
			foundPwd = true
			if c.Value != "Pr0d_DB_P@ss!" {
				t.Errorf("unexpected password value: %s", c.Value)
			}
		}
	}
	if !foundPwd {
		t.Error("did not find password")
	}
}

func TestExtractCredentials_NearbyEndpoint(t *testing.T) {
	data := `{"service":"internal-api","endpoint":"http://internal-api:8080","api_key":"sk_test_FAKE0TestKeyForInternalAPI0"}`
	creds := ExtractCredentials(data)

	for _, c := range creds {
		if c.Type == "stripe_secret" {
			if c.Endpoint == "" {
				t.Error("should find nearby endpoint for Stripe key")
			}
		}
	}
}

func TestExtractCredentials_Dedup(t *testing.T) {
	data := `key=AKIAIOSFODNN7EXAMPLE and again AKIAIOSFODNN7EXAMPLE`
	creds := ExtractCredentials(data)

	count := 0
	for _, c := range creds {
		if c.Type == "aws_access_key" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 deduped AWS key, got %d", count)
	}
}

func TestExtractCredentials_NoFalsePositives(t *testing.T) {
	// Normal application data should not trigger credential patterns.
	data := `{"name":"John","city":"Portland","status":"active","count":42}`
	creds := ExtractCredentials(data)
	if len(creds) > 0 {
		t.Errorf("expected no credentials, got %d: %v", len(creds), creds)
	}
}

func TestClassifyData_PII(t *testing.T) {
	data := `{"name":"Alice","ssn":"123-45-6789","credit_card":"4111-1111-1111-1111"}`
	class := ClassifyData(data)
	if class.Type != "pii" {
		t.Errorf("expected pii, got %s", class.Type)
	}
}

func TestClassifyData_PII_ByValuePattern(t *testing.T) {
	// No field names hint at PII, but value patterns match SSN format.
	data := `{"id":"123-45-6789","ref":"4111111111111111"}`
	class := ClassifyData(data)
	if class.Type != "pii" {
		t.Errorf("expected pii from value patterns, got %s", class.Type)
	}
}

func TestClassifyData_Credentials(t *testing.T) {
	data := `{"key":"AKIAIOSFODNN7EXAMPLE"}`
	class := ClassifyData(data)
	if class.Type != "credentials" {
		t.Errorf("expected credentials, got %s", class.Type)
	}
}

func TestClassifyData_Secrets(t *testing.T) {
	data := `{"authorization":"Bearer some-long-token-value"}`
	class := ClassifyData(data)
	if class.Type != "secrets" {
		t.Errorf("expected secrets, got %s", class.Type)
	}
}

func TestClassifyData_ApplicationData(t *testing.T) {
	data := `{"name":"Product","price":29.99,"category":"electronics"}`
	class := ClassifyData(data)
	if class.Type != "application_data" {
		t.Errorf("expected application_data, got %s", class.Type)
	}
}

func TestExtractCredentials_GrafanaQueryResult(t *testing.T) {
	// Simulates what comes back from a Grafana datasource proxy query
	// of a service_credentials table. Grafana returns column arrays —
	// values are positional, not labeled. credparse can only find
	// credentials with distinctive patterns (AKIA prefix, URL schemes).
	// Unlabeled generic passwords require structured parsing by the caller.
	data := `{"results":{"A":{"frames":[{"data":{"values":[
		["internal-api","redis-cache","s3-backup"],
		["api_admin","","AKIAIOSFODNN7EXAMPLE"],
		["SuperSecretAPIKey123!","redis_auth_token_xyz","wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
		["http://internal-api:8080","redis://redis:6379","s3://customer-backups"]
	]}}]}}}`

	creds := ExtractCredentials(data)

	types := make(map[string]bool)
	for _, c := range creds {
		types[c.Type] = true
	}

	if !types["aws_access_key"] {
		t.Error("should find AWS access key in query result")
	}
	if !types["database_url"] {
		t.Error("should find Redis URL in query result")
	}
	// Note: unlabeled passwords and AWS secret keys (no "secret_key": prefix)
	// won't be caught by pattern matching alone. The calling scanner should
	// parse Grafana's structured column schema to label values before feeding
	// them to credparse.
}

func TestExtractCredentials_GoogleOAuth(t *testing.T) {
	data := `"google": "ya29.example-google-oauth-access-token"`
	creds := ExtractCredentials(data)
	found := false
	for _, c := range creds {
		if c.Type == "google_oauth" {
			found = true
		}
	}
	if !found {
		t.Error("did not find Google OAuth token")
	}
}
