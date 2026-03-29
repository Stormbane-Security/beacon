package jenkins

import (
	"testing"
)

// ── isJenkinsCLIVulnerable ──────────────────────────────────────────────────
// CVE-2024-23897: mainline < 2.442, LTS < 2.426.3

func TestIsJenkinsCLIVulnerable(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		// ── Mainline (two-component) vulnerable ──
		{name: "mainline 2.441 (just below fix)", version: "2.441", want: true},
		{name: "mainline 2.440", version: "2.440", want: true},
		{name: "mainline 2.400", version: "2.400", want: true},
		{name: "mainline 2.300", version: "2.300", want: true},
		{name: "mainline 2.100", version: "2.100", want: true},
		{name: "mainline 2.1", version: "2.1", want: true},
		{name: "mainline 2.0", version: "2.0", want: true},

		// ── Mainline (two-component) NOT vulnerable ──
		{name: "mainline 2.442 (exact fix version)", version: "2.442", want: false},
		{name: "mainline 2.443 (above fix)", version: "2.443", want: false},
		{name: "mainline 2.500", version: "2.500", want: false},
		{name: "mainline 2.460", version: "2.460", want: false},

		// ── LTS (three-component) vulnerable ──
		{name: "LTS 2.426.2 (just below fix)", version: "2.426.2", want: true},
		{name: "LTS 2.426.1", version: "2.426.1", want: true},
		{name: "LTS 2.426.0", version: "2.426.0", want: true},
		{name: "LTS 2.401.3", version: "2.401.3", want: true},
		{name: "LTS 2.400.1", version: "2.400.1", want: true},
		{name: "LTS 2.346.3", version: "2.346.3", want: true},
		{name: "LTS 2.200.1", version: "2.200.1", want: true},
		{name: "LTS 2.0.0", version: "2.0.0", want: true},

		// ── LTS (three-component) NOT vulnerable ──
		{name: "LTS 2.426.3 (exact fix version)", version: "2.426.3", want: false},
		{name: "LTS 2.426.4", version: "2.426.4", want: false},
		{name: "LTS 2.440.1 (post-fix LTS line)", version: "2.440.1", want: false},
		{name: "LTS 2.452.1", version: "2.452.1", want: false},

		// ── LTS in-between range (minor 427..439 flagged as vulnerable) ──
		{name: "LTS 2.427.1 (between 426 and 440)", version: "2.427.1", want: true},
		{name: "LTS 2.430.2 (between 426 and 440)", version: "2.430.2", want: true},
		{name: "LTS 2.439.1 (just below 440 threshold)", version: "2.439.1", want: true},

		// ── Edge cases ──
		{name: "empty string", version: "", want: false},
		{name: "single component", version: "2", want: false},
		{name: "non-2 major version", version: "1.650", want: false},
		{name: "non-2 major three-component", version: "3.0.0", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isJenkinsCLIVulnerable(tt.version)
			if got != tt.want {
				t.Errorf("isJenkinsCLIVulnerable(%q) = %v; want %v", tt.version, got, tt.want)
			}
		})
	}
}

// ── isJenkinsStaplerRCEVulnerable ───────────────────────────────────────────
// CVE-2018-1000861: mainline ≤ 2.153, LTS ≤ 2.138.3

func TestIsJenkinsStaplerRCEVulnerable(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		// ── Mainline (two-component) vulnerable ──
		{name: "mainline 2.153 (boundary, vulnerable)", version: "2.153", want: true},
		{name: "mainline 2.152", version: "2.152", want: true},
		{name: "mainline 2.100", version: "2.100", want: true},
		{name: "mainline 2.1", version: "2.1", want: true},
		{name: "mainline 2.0", version: "2.0", want: true},

		// ── Mainline (two-component) NOT vulnerable ──
		{name: "mainline 2.154 (just above fix)", version: "2.154", want: false},
		{name: "mainline 2.200", version: "2.200", want: false},
		{name: "mainline 2.300", version: "2.300", want: false},
		{name: "mainline 2.442", version: "2.442", want: false},

		// ── LTS (three-component) vulnerable ──
		{name: "LTS 2.138.3 (boundary, vulnerable)", version: "2.138.3", want: true},
		{name: "LTS 2.138.2", version: "2.138.2", want: true},
		{name: "LTS 2.138.1", version: "2.138.1", want: true},
		{name: "LTS 2.138.0", version: "2.138.0", want: true},
		{name: "LTS 2.100.5", version: "2.100.5", want: true},
		{name: "LTS 2.50.1", version: "2.50.1", want: true},
		{name: "LTS 2.0.0", version: "2.0.0", want: true},
		{name: "LTS 2.137.99 (minor < 138)", version: "2.137.99", want: true},

		// ── LTS (three-component) NOT vulnerable ──
		{name: "LTS 2.138.4 (patch above boundary)", version: "2.138.4", want: false},
		{name: "LTS 2.139.1 (minor above 138)", version: "2.139.1", want: false},
		{name: "LTS 2.150.1", version: "2.150.1", want: false},
		{name: "LTS 2.200.3", version: "2.200.3", want: false},
		{name: "LTS 2.426.3", version: "2.426.3", want: false},

		// ── Edge cases ──
		{name: "empty string", version: "", want: false},
		{name: "single component", version: "2", want: false},
		{name: "non-2 major version", version: "1.153", want: false},
		{name: "non-2 major three-component", version: "3.138.3", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isJenkinsStaplerRCEVulnerable(tt.version)
			if got != tt.want {
				t.Errorf("isJenkinsStaplerRCEVulnerable(%q) = %v; want %v", tt.version, got, tt.want)
			}
		})
	}
}

// ── variants ────────────────────────────────────────────────────────────────

func TestVariants(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantFirst  string
		wantSecond string
	}{
		{
			name:       "converts https URL to https and http pair",
			input:      "https://example.com/script",
			wantFirst:  "https://example.com/script",
			wantSecond: "http://example.com/script",
		},
		{
			name:       "preserves port in URL",
			input:      "https://example.com:8443/script",
			wantFirst:  "https://example.com:8443/script",
			wantSecond: "http://example.com:8443/script",
		},
		{
			name:       "preserves path components",
			input:      "https://ci.example.com/jenkins/script",
			wantFirst:  "https://ci.example.com/jenkins/script",
			wantSecond: "http://ci.example.com/jenkins/script",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := variants(tt.input)
			if len(got) != 2 {
				t.Fatalf("variants(%q) returned %d items; want 2", tt.input, len(got))
			}
			if got[0] != tt.wantFirst {
				t.Errorf("variants(%q)[0] = %q; want %q", tt.input, got[0], tt.wantFirst)
			}
			if got[1] != tt.wantSecond {
				t.Errorf("variants(%q)[1] = %q; want %q", tt.input, got[1], tt.wantSecond)
			}
		})
	}
}

// ── scriptEndpoint ──────────────────────────────────────────────────────────

func TestScriptEndpoint(t *testing.T) {
	tests := []struct {
		name  string
		asset string
		want  string
	}{
		{
			name:  "simple hostname",
			asset: "jenkins.example.com",
			want:  "https://jenkins.example.com/script",
		},
		{
			name:  "hostname with port",
			asset: "jenkins.example.com:8080",
			want:  "https://jenkins.example.com:8080/script",
		},
		{
			name:  "IP address",
			asset: "192.168.1.100",
			want:  "https://192.168.1.100/script",
		},
		{
			name:  "IP address with port",
			asset: "10.0.0.1:8443",
			want:  "https://10.0.0.1:8443/script",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scriptEndpoint(tt.asset)
			if got != tt.want {
				t.Errorf("scriptEndpoint(%q) = %q; want %q", tt.asset, got, tt.want)
			}
		})
	}
}
