package finding

import (
	"testing"
)

func TestMapNucleiTemplate_KnownTemplates(t *testing.T) {
	tests := []struct {
		templateID string
		want       CheckID
	}{
		{"ssl-dns-names", CheckTLSCertHostnameMismatch},
		{"expired-ssl", CheckTLSCertExpiry7d},
		{"missing-csp", CheckHeadersMissingCSP},
		{"git-config", CheckExposureGitExposed},
		{"subdomain-takeover", CheckSubdomainTakeover},
		{"cors-misconfig", CheckNucleiMisconfiguredCORS},
		{"xss", CheckWebXSS},
		{"sqli", CheckWebSQLi},
		{"graphql-introspection", CheckGraphQLIntrospection},
		{"spring-actuator", CheckExposureSpringActuator},
	}

	for _, tt := range tests {
		t.Run(tt.templateID, func(t *testing.T) {
			got := MapNucleiTemplate(tt.templateID)
			if got != tt.want {
				t.Errorf("MapNucleiTemplate(%q) = %q, want %q", tt.templateID, got, tt.want)
			}
		})
	}
}

func TestMapNucleiTemplate_UnknownTemplate(t *testing.T) {
	got := MapNucleiTemplate("unknown-thing")
	want := CheckID("nuclei.unknown-thing")
	if got != want {
		t.Errorf("MapNucleiTemplate(%q) = %q, want %q", "unknown-thing", got, want)
	}
}

func TestMapNucleiTemplate_EmptyTemplateID(t *testing.T) {
	got := MapNucleiTemplate("")
	want := CheckID("nuclei.")
	if got != want {
		t.Errorf("MapNucleiTemplate(%q) = %q, want %q", "", got, want)
	}
}

func TestMapNucleiTemplate_TemplateIDWithSpaces(t *testing.T) {
	got := MapNucleiTemplate("my custom template")
	want := CheckID("nuclei.my-custom-template")
	if got != want {
		t.Errorf("MapNucleiTemplate(%q) = %q, want %q", "my custom template", got, want)
	}
}

func TestMapNucleiTemplate_TemplateIDUppercase(t *testing.T) {
	got := MapNucleiTemplate("My-Custom-Template")
	want := CheckID("nuclei.my-custom-template")
	if got != want {
		t.Errorf("MapNucleiTemplate(%q) = %q, want %q", "My-Custom-Template", got, want)
	}
}

func TestMapNucleiTemplate_AllMappedTemplatesReturnCorrectCheckID(t *testing.T) {
	for templateID, expectedCheckID := range NucleiTemplateToCheckID {
		got := MapNucleiTemplate(templateID)
		if got != expectedCheckID {
			t.Errorf("MapNucleiTemplate(%q) = %q, want %q", templateID, got, expectedCheckID)
		}
	}
}
