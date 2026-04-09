package dirbust_test

import (
	"testing"

	"github.com/stormbane-security/beacon/internal/scanner/dirbust"
)

func TestTechStackWordlist_PHP(t *testing.T) {
	evidence := map[string]any{
		"framework": "PHP",
	}
	paths := dirbust.TechStackWordlist(evidence)
	if len(paths) == 0 {
		t.Fatal("expected paths for PHP framework, got none")
	}
	assertContains(t, paths, "/phpinfo.php")
	assertContains(t, paths, "/phpmyadmin/")
}

func TestTechStackWordlist_WordPress(t *testing.T) {
	evidence := map[string]any{
		"cms": "WordPress",
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/wp-admin/")
	assertContains(t, paths, "/wp-login.php")
	assertContains(t, paths, "/xmlrpc.php")
}

func TestTechStackWordlist_Django(t *testing.T) {
	evidence := map[string]any{
		"framework": "Django",
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/admin/")
	assertContains(t, paths, "/static/admin/")
	assertContains(t, paths, "/requirements.txt")
}

func TestTechStackWordlist_Flask(t *testing.T) {
	evidence := map[string]any{
		"framework": "Flask",
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/console")
}

func TestTechStackWordlist_Spring(t *testing.T) {
	evidence := map[string]any{
		"framework": "Spring",
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/actuator")
	assertContains(t, paths, "/actuator/env")
	assertContains(t, paths, "/swagger-ui.html")
	assertContains(t, paths, "/h2-console")
}

func TestTechStackWordlist_Rails(t *testing.T) {
	evidence := map[string]any{
		"framework": "Rails",
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/rails/info")
	assertContains(t, paths, "/sidekiq")
}

func TestTechStackWordlist_ASPNET(t *testing.T) {
	evidence := map[string]any{
		"framework": "ASP.NET",
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/web.config")
	assertContains(t, paths, "/elmah.axd")
	assertContains(t, paths, "/trace.axd")
}

func TestTechStackWordlist_Go(t *testing.T) {
	evidence := map[string]any{
		"language": "Go",
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/debug/pprof/")
	assertContains(t, paths, "/healthz")
	assertContains(t, paths, "/metrics")
}

func TestTechStackWordlist_NodeJS(t *testing.T) {
	evidence := map[string]any{
		"runtime": "Node.js",
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/package.json")
	assertContains(t, paths, "/.env")
	assertContains(t, paths, "/.npmrc")
}

func TestTechStackWordlist_Kubernetes(t *testing.T) {
	evidence := map[string]any{
		"platform": "Kubernetes",
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/healthz")
	assertContains(t, paths, "/readyz")
	assertContains(t, paths, "/livez")
}

func TestTechStackWordlist_Docker(t *testing.T) {
	evidence := map[string]any{
		"platform": "Docker",
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/v2/_catalog")
}

func TestTechStackWordlist_Git(t *testing.T) {
	evidence := map[string]any{
		"technology": "Git",
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/.git/config")
	assertContains(t, paths, "/.git/HEAD")
}

func TestTechStackWordlist_CICD(t *testing.T) {
	evidence := map[string]any{
		"technology": "CI",
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/Jenkinsfile")
	assertContains(t, paths, "/.gitlab-ci.yml")
	assertContains(t, paths, "/Dockerfile")
}

func TestTechStackWordlist_EmptyEvidence(t *testing.T) {
	paths := dirbust.TechStackWordlist(nil)
	if len(paths) != 0 {
		t.Errorf("expected no paths for nil evidence, got %d", len(paths))
	}

	paths = dirbust.TechStackWordlist(map[string]any{})
	if len(paths) != 0 {
		t.Errorf("expected no paths for empty evidence, got %d", len(paths))
	}
}

func TestTechStackWordlist_UnknownTech(t *testing.T) {
	evidence := map[string]any{
		"framework": "SomeObscureFramework",
	}
	paths := dirbust.TechStackWordlist(evidence)
	if len(paths) != 0 {
		t.Errorf("expected no paths for unknown tech, got %d", len(paths))
	}
}

func TestTechStackWordlist_MultipleTechs(t *testing.T) {
	evidence := map[string]any{
		"framework": "Django",
		"technology": "Git",
	}
	paths := dirbust.TechStackWordlist(evidence)
	// Should have Django AND Git paths.
	assertContains(t, paths, "/admin/")
	assertContains(t, paths, "/.git/config")
}

func TestTechStackWordlist_NoDuplicates(t *testing.T) {
	// Both "php" and "wordpress" include /wp-admin/ — should not duplicate.
	evidence := map[string]any{
		"framework": "PHP",
		"cms":       "WordPress",
	}
	paths := dirbust.TechStackWordlist(evidence)
	count := 0
	for _, p := range paths {
		if p == "/wp-admin/" {
			count++
		}
	}
	if count > 1 {
		t.Errorf("expected /wp-admin/ once, found %d times", count)
	}
}

func TestTechStackWordlist_StringSliceEvidence(t *testing.T) {
	evidence := map[string]any{
		"technology": []string{"Git", "Docker"},
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/.git/config")
	assertContains(t, paths, "/v2/_catalog")
}

func TestTechStackWordlist_AnySliceEvidence(t *testing.T) {
	evidence := map[string]any{
		"technology": []any{"Git", "Docker"},
	}
	paths := dirbust.TechStackWordlist(evidence)
	assertContains(t, paths, "/.git/config")
	assertContains(t, paths, "/v2/_catalog")
}

func assertContains(t *testing.T, paths []string, want string) {
	t.Helper()
	for _, p := range paths {
		if p == want {
			return
		}
	}
	t.Errorf("expected paths to contain %q, got %v", want, paths)
}
