package dirbust

import (
	"strings"

	"github.com/stormbane-security/beacon/internal/playbook"
)

// TechStackWordlist returns additional paths to probe based on the detected
// technology stack. The evidence map comes from the classify/fingerprint phase
// and may contain keys like "framework", "server", "technology", "cms", etc.
//
// This avoids generic wordlist noise: instead of probing every possible path,
// we only add paths relevant to the technologies actually detected on the target.
func TechStackWordlist(evidence map[string]any) []string {
	if len(evidence) == 0 {
		return nil
	}

	// Build a set of technology signals from all evidence fields.
	var signals []string
	for _, key := range []string{"framework", "server", "technology", "cms", "language", "runtime", "platform"} {
		if v, ok := evidence[key]; ok {
			switch val := v.(type) {
			case string:
				signals = append(signals, strings.ToLower(val))
			case []string:
				for _, s := range val {
					signals = append(signals, strings.ToLower(s))
				}
			case []any:
				for _, s := range val {
					if str, ok := s.(string); ok {
						signals = append(signals, strings.ToLower(str))
					}
				}
			}
		}
	}

	// Also check "headers" evidence for server-type clues.
	if hdrs, ok := evidence["headers"]; ok {
		if hdrMap, ok := hdrs.(map[string]string); ok {
			if server := strings.ToLower(hdrMap["Server"]); server != "" {
				signals = append(signals, server)
			}
			if powered := strings.ToLower(hdrMap["X-Powered-By"]); powered != "" {
				signals = append(signals, powered)
			}
		}
	}

	seen := make(map[string]bool)
	var paths []string

	add := func(pp []string) {
		for _, p := range pp {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}

	for _, sig := range signals {
		for tech, pp := range techPaths {
			if strings.Contains(sig, tech) {
				add(pp)
			}
		}
	}

	return paths
}

// techPaths maps technology keywords to targeted discovery paths.
// Keys are lowercase substrings matched against evidence signals.
var techPaths = map[string][]string{
	// PHP ecosystem
	"php": {
		"/wp-admin/", "/wp-login.php", "/administrator/",
		"/phpmyadmin/", "/adminer.php", "/info.php",
		"/phpinfo.php", "/config.php.bak",
	},
	"wordpress": {
		"/wp-admin/", "/wp-login.php", "/wp-content/",
		"/wp-includes/", "/xmlrpc.php", "/wp-json/wp/v2/users",
		"/wp-config.php.bak", "/wp-config.php~",
	},
	"drupal": {
		"/admin/", "/user/login", "/core/install.php",
		"/sites/default/settings.php", "/CHANGELOG.txt",
	},
	"joomla": {
		"/administrator/", "/configuration.php.bak",
		"/htaccess.txt", "/web.config.txt",
	},
	"laravel": {
		"/.env", "/storage/logs/laravel.log",
		"/telescope", "/horizon",
	},

	// Node.js ecosystem
	"node": {
		"/package.json", "/node_modules/", "/.env",
		"/server.js", "/app.js", "/.npmrc",
	},
	"express": {
		"/package.json", "/.env", "/server.js", "/app.js",
	},
	"nextjs": {
		"/_next/", "/api/", "/.env", "/.env.local",
		"/next.config.js",
	},
	"nuxt": {
		"/_nuxt/", "/api/", "/.env", "/nuxt.config.js",
	},

	// Python ecosystem
	"django": {
		"/admin/", "/static/admin/", "/settings.py",
		"/__pycache__/", "/manage.py", "/requirements.txt",
	},
	"flask": {
		"/console", "/static/", "/instance/",
		"/requirements.txt",
	},
	"python": {
		"/requirements.txt", "/__pycache__/", "/.env",
	},

	// Java ecosystem
	"spring": {
		"/actuator", "/actuator/env", "/actuator/health",
		"/actuator/beans", "/actuator/configprops",
		"/swagger-ui.html", "/h2-console",
		"/v2/api-docs", "/v3/api-docs",
	},
	"java": {
		"/actuator", "/swagger-ui.html", "/h2-console",
		"/WEB-INF/web.xml",
	},
	"tomcat": {
		"/manager/html", "/host-manager/html",
		"/WEB-INF/web.xml", "/status",
	},

	// Ruby ecosystem
	"rails": {
		"/rails/info", "/rails/mailers", "/sidekiq",
		"/admin", "/rails/info/routes",
	},
	"ruby": {
		"/Gemfile", "/Gemfile.lock", "/config/database.yml",
	},

	// .NET ecosystem
	"asp": {
		"/web.config", "/elmah.axd", "/trace.axd", "/_framework/",
	},
	"aspnet": {
		"/web.config", "/elmah.axd", "/trace.axd", "/_framework/",
	},
	"dotnet": {
		"/web.config", "/elmah.axd", "/_framework/",
	},
	"iis": {
		"/web.config", "/elmah.axd", "/trace.axd",
		"/iisstart.htm", "/_vti_bin/",
	},

	// Go ecosystem
	"go": {
		"/debug/pprof/", "/debug/vars", "/healthz",
		"/readyz", "/metrics",
	},
	"gin": {
		"/debug/pprof/", "/healthz", "/metrics",
	},

	// Infrastructure
	"kubernetes": {
		"/healthz", "/readyz", "/livez",
		"/metrics", "/debug/pprof",
	},
	"k8s": {
		"/healthz", "/readyz", "/livez",
		"/metrics",
	},
	"docker": {
		"/v1.24/containers/json", "/v2/_catalog",
		"/_ping",
	},

	// Version control
	"git": {
		"/.git/config", "/.git/HEAD", "/.gitignore",
		"/.git/logs/HEAD",
	},

	// CI/CD
	"jenkins": {
		"/Jenkinsfile", "/script", "/manage",
		"/api/json",
	},
	"github": {
		"/.github/workflows/", "/.github/dependabot.yml",
	},
	"gitlab": {
		"/.gitlab-ci.yml", "/api/v4/projects",
	},
	"ci": {
		"/Jenkinsfile", "/.github/workflows/", "/.gitlab-ci.yml",
		"/Dockerfile", "/.circleci/config.yml",
	},

	// Containers
	"dockerfile": {
		"/Dockerfile", "/docker-compose.yml",
		"/docker-compose.yaml",
	},

	// Monitoring/observability
	"grafana": {
		"/api/dashboards", "/api/org", "/api/admin/stats",
	},
	"prometheus": {
		"/metrics", "/api/v1/targets", "/api/v1/status/config",
	},
}

// buildTechEvidence converts a playbook.Evidence struct into the generic
// map[string]any format expected by TechStackWordlist. This bridges the
// typed classify-phase evidence to the keyword-based tech matching.
func buildTechEvidence(ev *playbook.Evidence) map[string]any {
	if ev == nil {
		return nil
	}
	m := make(map[string]any)
	if ev.Framework != "" {
		m["framework"] = ev.Framework
	}
	if ev.CloudProvider != "" {
		m["platform"] = ev.CloudProvider
	}
	if ev.IsKubernetes {
		m["platform"] = "Kubernetes"
	}
	if ev.ProxyType != "" {
		m["server"] = ev.ProxyType
	}
	if len(ev.Headers) > 0 {
		m["headers"] = ev.Headers
	}
	// Extract technology hints from ServiceVersions.
	if len(ev.ServiceVersions) > 0 {
		var techs []string
		for _, v := range ev.ServiceVersions {
			techs = append(techs, v)
		}
		m["technology"] = techs
	}
	return m
}
