package chainengine

import (
	"context"
	"testing"

	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
)

func TestNucleiTemplateToService_TagMatch(t *testing.T) {
	tests := []struct {
		name    string
		tags    []string
		want    string
	}{
		{"redis tag", []string{"redis", "database"}, "redis"},
		{"mongodb tag", []string{"nosql", "mongodb"}, "mongodb"},
		{"jenkins tag", []string{"ci", "jenkins"}, "jenkins"},
		{"grafana tag", []string{"monitoring", "grafana"}, "grafana"},
		{"activemq tag", []string{"activemq", "apache"}, "activemq"},
		{"kubernetes tag", []string{"kubernetes", "k8s"}, "kubernetes"},
		{"jupyter tag", []string{"jupyter", "ml"}, "jupyter"},
		{"spring tag", []string{"spring", "java"}, "spring-actuator"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := finding.Finding{
				Scanner: "nuclei",
				Evidence: map[string]any{
					"tags": tt.tags,
				},
			}
			got := nucleiTemplateToService(f)
			if got != tt.want {
				t.Errorf("nucleiTemplateToService() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNucleiTemplateToService_TemplateIDMatch(t *testing.T) {
	tests := []struct {
		name       string
		templateID string
		want       string
	}{
		{"ActiveMQ RCE", "CVE-2023-46604", "activemq"},
		{"Log4Shell", "CVE-2021-44228", "log4shell"},
		{"Spring4Shell", "CVE-2022-22965", "spring4shell"},
		{"GhostCat", "CVE-2020-1938", "tomcat"},
		{"PAN-OS RCE", "CVE-2024-3400", "paloalto"},
		{"Superset SECRET_KEY", "CVE-2023-27524", "superset"},
		{"TeamCity auth bypass", "CVE-2023-42793", "teamcity"},
		{"GitLab RCE", "CVE-2021-22205", "gitlab"},
		{"Pulse Secure", "CVE-2019-11510", "pulse_vpn"},
		{"Confluence admin create", "CVE-2023-22515", "confluence"},
		{"Ivanti RCE", "CVE-2024-21887", "ivanti"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := finding.Finding{
				Scanner: "nuclei",
				Evidence: map[string]any{
					"template_id": tt.templateID,
				},
			}
			got := nucleiTemplateToService(f)
			if got != tt.want {
				t.Errorf("nucleiTemplateToService() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNucleiTemplateToService_TemplateIDPriority(t *testing.T) {
	// Template ID should take priority over tags.
	f := finding.Finding{
		Scanner: "nuclei",
		Evidence: map[string]any{
			"template_id": "CVE-2023-46604",
			"tags":        []string{"redis"}, // misleading tag
		},
	}
	got := nucleiTemplateToService(f)
	if got != "activemq" {
		t.Errorf("template ID should take priority over tags, got %q, want %q", got, "activemq")
	}
}

func TestNucleiTemplateToService_UnknownTag(t *testing.T) {
	f := finding.Finding{
		Scanner: "nuclei",
		Evidence: map[string]any{
			"tags": []string{"unknown-service", "misc"},
		},
	}
	got := nucleiTemplateToService(f)
	if got != "" {
		t.Errorf("unknown tag should return empty string, got %q", got)
	}
}

func TestNucleiTemplateToService_NoEvidence(t *testing.T) {
	f := finding.Finding{
		Scanner:  "nuclei",
		Evidence: map[string]any{},
	}
	got := nucleiTemplateToService(f)
	if got != "" {
		t.Errorf("no evidence should return empty string, got %q", got)
	}
}

func TestIsExploitableNucleiTemplate(t *testing.T) {
	tests := []struct {
		name     string
		evidence map[string]any
		want     bool
	}{
		{
			"exploitable by tag",
			map[string]any{"tags": []string{"redis"}},
			true,
		},
		{
			"exploitable by template ID",
			map[string]any{"template_id": "CVE-2021-44228"},
			true,
		},
		{
			"not exploitable",
			map[string]any{"tags": []string{"info", "tech"}},
			false,
		},
		{
			"no evidence",
			map[string]any{},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := finding.Finding{Scanner: "nuclei", Evidence: tt.evidence}
			got := isExploitableNucleiTemplate(f)
			if got != tt.want {
				t.Errorf("isExploitableNucleiTemplate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNucleiToExploitChain_MatchesOnlyNuclei(t *testing.T) {
	// Non-nuclei finding should not match, even with matching tags.
	nonNuclei := finding.Finding{
		Scanner:  "nmap",
		Evidence: map[string]any{"tags": []string{"redis"}},
	}
	if nucleiToExploitChain.Matches(nonNuclei) {
		t.Error("chain should not match non-nuclei findings")
	}

	// Nuclei finding without exploitable template should not match.
	nucleiNoExploit := finding.Finding{
		Scanner:  "nuclei",
		Evidence: map[string]any{"tags": []string{"info", "tech"}},
	}
	if nucleiToExploitChain.Matches(nucleiNoExploit) {
		t.Error("chain should not match nuclei findings without exploitable template")
	}

	// Nuclei finding with exploitable template should match.
	nucleiExploit := finding.Finding{
		Scanner:  "nuclei",
		Evidence: map[string]any{"tags": []string{"redis"}},
	}
	if !nucleiToExploitChain.Matches(nucleiExploit) {
		t.Error("chain should match nuclei findings with exploitable template")
	}
}

func TestExtractHostPort(t *testing.T) {
	tests := []struct {
		name     string
		evidence map[string]any
		asset    string
		wantHost string
		wantPort int
	}{
		{
			"matched_at URL with port",
			map[string]any{"matched_at": "https://10.0.0.1:8443/admin"},
			"10.0.0.1",
			"10.0.0.1", 8443,
		},
		{
			"matched_at URL without port",
			map[string]any{"matched_at": "https://example.com/path"},
			"example.com",
			"example.com", 443,
		},
		{
			"matched_at HTTP",
			map[string]any{"matched_at": "http://target.local/"},
			"target.local",
			"target.local", 80,
		},
		{
			"fallback to asset",
			map[string]any{},
			"http://redis.internal:6379",
			"redis.internal", 6379,
		},
		{
			"bare hostname asset",
			map[string]any{},
			"db.internal",
			"db.internal", 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := finding.Finding{
				Evidence: tt.evidence,
				Asset:    tt.asset,
			}
			host, port := extractHostPort(f)
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
			if port != tt.wantPort {
				t.Errorf("port = %d, want %d", port, tt.wantPort)
			}
		})
	}
}

func TestNucleiToExploitChain_ExecuteInAuthorizedMode(t *testing.T) {
	// Create an engine in authorized mode.
	e, err := New(module.ScanAuthorized)
	if err != nil {
		t.Fatal(err)
	}

	// Feed a nuclei finding for a service that has a playbook (redis).
	// The playbook will fail to connect (no real redis), but the chain
	// should at least attempt execution without panicking.
	f := finding.Finding{
		Scanner: "nuclei",
		CheckID: "nuclei.redis_unauth",
		Asset:   "http://127.0.0.1:16379",
		Evidence: map[string]any{
			"template_id": "redis-unauthenticated-access",
			"tags":        []string{"redis", "database"},
			"matched_at":  "http://127.0.0.1:16379",
		},
	}

	ctx := context.Background()
	results := nucleiToExploitChain.Execute(ctx, e, f)

	// We expect no results since there's no real redis server,
	// but the important thing is no panic and clean execution.
	_ = results
}

func TestLookupPlaybook(t *testing.T) {
	// These services should all have playbooks.
	services := []string{
		"redis", "mongodb", "mysql", "postgresql", "elasticsearch",
		"jenkins", "grafana", "consul", "activemq", "rabbitmq",
	}
	for _, svc := range services {
		pb := lookupPlaybook(svc)
		if pb == nil {
			t.Errorf("lookupPlaybook(%q) returned nil, expected a playbook", svc)
		}
	}

	// Non-existent service should return nil.
	if pb := lookupPlaybook("nonexistent_service_xyz"); pb != nil {
		t.Errorf("lookupPlaybook for nonexistent service should return nil, got %+v", pb)
	}
}
