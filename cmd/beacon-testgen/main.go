// beacon-testgen reads nuclei templates and generates drydock test YAML files.
// These auto-generated tests serve as a roadmap for exploit chain coverage.
//
// Usage:
//
//	beacon-testgen --templates-dir /path/to/nuclei-templates \
//	  --output-dir tests/scanners/generated/ \
//	  --filter severity:critical,high
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Nuclei template model (only the fields we care about)
// ---------------------------------------------------------------------------

type NucleiTemplate struct {
	ID   string     `yaml:"id"`
	Info NucleiInfo `yaml:"info"`
}

type NucleiInfo struct {
	Name      string            `yaml:"name"`
	Severity  string            `yaml:"severity"`
	Tags      string            `yaml:"tags"`
	Reference []string          `yaml:"reference"`
	Metadata  map[string]string `yaml:"metadata"`
}

func (n *NucleiInfo) TagList() []string {
	if n.Tags == "" {
		return nil
	}
	parts := strings.Split(n.Tags, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Vulnerability class mapping
// ---------------------------------------------------------------------------

type VulnClass struct {
	Name    string // human label
	CheckID string // beacon check_id for exploit assertion
	Scanner string // beacon scanner to invoke
}

var tagToClass = map[string]VulnClass{
	"sqli":              {Name: "SQLi", CheckID: "exploit.sqli", Scanner: "nuclei"},
	"rce":               {Name: "RCE", CheckID: "exploit.code_execution", Scanner: "nuclei"},
	"cmdi":              {Name: "CmdInj", CheckID: "exploit.code_execution", Scanner: "nuclei"},
	"command-injection": {Name: "CmdInj", CheckID: "exploit.code_execution", Scanner: "nuclei"},
	"ssrf":              {Name: "SSRF", CheckID: "exploit.ssrf", Scanner: "nuclei"},
	"ssti":              {Name: "SSTI", CheckID: "exploit.ssti", Scanner: "nuclei"},
	"xxe":               {Name: "XXE", CheckID: "exploit.xxe", Scanner: "nuclei"},
	"lfi":               {Name: "LFI", CheckID: "exploit.lfi", Scanner: "nuclei"},
	"traversal":         {Name: "LFI", CheckID: "exploit.lfi", Scanner: "nuclei"},
	"fileread":          {Name: "LFI", CheckID: "exploit.lfi", Scanner: "nuclei"},
}

// Tags that produce detection-only tests (no exploit chain assertion).
var detectionOnlyTags = map[string]bool{
	"xss":           true,
	"default-login": true,
}

func classifyTemplate(tags []string) (vc VulnClass, exploitable bool) {
	for _, t := range tags {
		if c, ok := tagToClass[t]; ok {
			return c, true
		}
	}
	// Check for detection-only.
	for _, t := range tags {
		if detectionOnlyTags[t] {
			return VulnClass{Name: t, Scanner: "nuclei"}, false
		}
	}
	return VulnClass{Name: "unknown", Scanner: "nuclei"}, false
}

// ---------------------------------------------------------------------------
// Product → Docker image mapping
// ---------------------------------------------------------------------------

type ImageInfo struct {
	Image       string // e.g. "nginx"
	DefaultPort int    // container-internal port
}

var productImages = map[string]ImageInfo{
	"nginx":         {Image: "nginx", DefaultPort: 80},
	"apache":        {Image: "httpd", DefaultPort: 80},
	"httpd":         {Image: "httpd", DefaultPort: 80},
	"tomcat":        {Image: "tomcat", DefaultPort: 8080},
	"jenkins":       {Image: "jenkins/jenkins", DefaultPort: 8080},
	"wordpress":     {Image: "wordpress", DefaultPort: 80},
	"joomla":        {Image: "joomla", DefaultPort: 80},
	"drupal":        {Image: "drupal", DefaultPort: 80},
	"grafana":       {Image: "grafana/grafana", DefaultPort: 3000},
	"gitlab":        {Image: "gitlab/gitlab-ce", DefaultPort: 80},
	"gitea":         {Image: "gitea/gitea", DefaultPort: 3000},
	"minio":         {Image: "minio/minio", DefaultPort: 9000},
	"redis":         {Image: "redis", DefaultPort: 6379},
	"mongodb":       {Image: "mongo", DefaultPort: 27017},
	"mysql":         {Image: "mysql", DefaultPort: 3306},
	"postgres":      {Image: "postgres", DefaultPort: 5432},
	"postgresql":    {Image: "postgres", DefaultPort: 5432},
	"rabbitmq":      {Image: "rabbitmq", DefaultPort: 15672},
	"elasticsearch": {Image: "elasticsearch", DefaultPort: 9200},
	"kibana":        {Image: "kibana", DefaultPort: 5601},
	"consul":        {Image: "hashicorp/consul", DefaultPort: 8500},
	"vault":         {Image: "hashicorp/vault", DefaultPort: 8200},
	"sonarqube":     {Image: "sonarqube", DefaultPort: 9000},
	"confluence":    {Image: "atlassian/confluence", DefaultPort: 8090},
	"jira":          {Image: "atlassian/jira-software", DefaultPort: 8080},
	"bitbucket":     {Image: "atlassian/bitbucket", DefaultPort: 7990},
	"harbor":        {Image: "goharbor/harbor-core", DefaultPort: 8080},
	"nexus":         {Image: "sonatype/nexus3", DefaultPort: 8081},
	"artifactory":   {Image: "releases-docker.jfrog.io/jfrog/artifactory-oss", DefaultPort: 8082},
	"teamcity":      {Image: "jetbrains/teamcity-server", DefaultPort: 8111},
	"activemq":      {Image: "apache/activemq-classic", DefaultPort: 8161},
	"kafka":         {Image: "confluentinc/cp-kafka", DefaultPort: 9092},
	"zookeeper":     {Image: "zookeeper", DefaultPort: 2181},
	"prometheus":    {Image: "prom/prometheus", DefaultPort: 9090},
	"airflow":       {Image: "apache/airflow", DefaultPort: 8080},
	"superset":      {Image: "apache/superset", DefaultPort: 8088},
	"keycloak":      {Image: "quay.io/keycloak/keycloak", DefaultPort: 8080},
	"portainer":     {Image: "portainer/portainer-ce", DefaultPort: 9000},
	"phpmyadmin":    {Image: "phpmyadmin", DefaultPort: 80},
	"adminer":       {Image: "adminer", DefaultPort: 8080},
	"solr":          {Image: "solr", DefaultPort: 8983},
	"couchdb":       {Image: "couchdb", DefaultPort: 5984},
}

// resolveImage tries metadata.product, then scans tags for a known product.
func resolveImage(tmpl NucleiTemplate) (ImageInfo, string, bool) {
	product := strings.ToLower(tmpl.Info.Metadata["product"])
	if product != "" {
		if img, ok := productImages[product]; ok {
			return img, product, true
		}
	}
	// Fallback: check tags.
	for _, t := range tmpl.Info.TagList() {
		if img, ok := productImages[t]; ok {
			return img, t, true
		}
	}
	return ImageInfo{}, "", false
}

// ---------------------------------------------------------------------------
// WordPress plugin helpers
// ---------------------------------------------------------------------------

// isWordPressPlugin returns true when the template targets a WordPress plugin.
func isWordPressPlugin(tmpl NucleiTemplate) bool {
	fw := strings.ToLower(tmpl.Info.Metadata["framework"])
	product := strings.ToLower(tmpl.Info.Metadata["product"])
	if fw == "wordpress" && product != "" && product != "wordpress" {
		return true
	}
	return false
}

// wpPluginSlug extracts the plugin directory name from the zoomeye-query
// metadata field (e.g. `http.body="wp-content/plugins/wd-google-maps"` →
// "wd-google-maps"). Falls back to converting the product slug (underscores
// to hyphens).
func wpPluginSlug(tmpl NucleiTemplate) string {
	zq := tmpl.Info.Metadata["zoomeye-query"]
	if zq != "" {
		re := regexp.MustCompile(`wp-content/plugins/([a-zA-Z0-9_-]+)`)
		if m := re.FindStringSubmatch(zq); len(m) == 2 {
			return m[1]
		}
	}
	// Fallback: product field with underscores → hyphens.
	return strings.ReplaceAll(strings.ToLower(tmpl.Info.Metadata["product"]), "_", "-")
}

// wpVulnVersion parses a version constraint like "< 1.0.73" from the
// template name and returns the last vulnerable version by decrementing
// the final component (→ "1.0.72"). Returns "" if no version can be parsed.
func wpVulnVersion(tmpl NucleiTemplate) string {
	// Look for patterns like "< 1.0.73" or "<= 1.0.73" in the template name.
	re := regexp.MustCompile(`<[=]?\s*(\d+(?:\.\d+)*)`)
	m := re.FindStringSubmatch(tmpl.Info.Name)
	if len(m) < 2 {
		return ""
	}
	parts := strings.Split(m[1], ".")
	last, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil || last <= 0 {
		return ""
	}
	parts[len(parts)-1] = strconv.Itoa(last - 1)
	return strings.Join(parts, ".")
}

// wpDockerfileContent builds a Dockerfile that installs a specific
// vulnerable WordPress plugin version.
func wpDockerfileContent(pluginSlug, version string) string {
	return fmt.Sprintf(`FROM wordpress:latest
RUN apt-get update && apt-get install -y unzip && rm -rf /var/lib/apt/lists/*
ADD https://downloads.wordpress.org/plugin/%s.%s.zip /tmp/plugin.zip
RUN unzip /tmp/plugin.zip -d /var/www/html/wp-content/plugins/ && rm /tmp/plugin.zip
`, pluginSlug, version)
}

// ---------------------------------------------------------------------------
// Drydock YAML generation
// ---------------------------------------------------------------------------

type TestSpec struct {
	SourceID    string
	Name        string
	Description string
	Tags        string // comma-separated for YAML array
	Image       string
	HostPort    int
	ContPort    int
	ReadyURL    string
	NucleiCheck string // nuclei.<id>
	HasExploit  bool
	ExploitSpec *ExploitAssertion
	Timeout     string

	// WordPress plugin fields
	IsWPPlugin    bool
	WPFixtureDir  string // relative path like ./fixtures/cve-2024-xxxx/
}

type ExploitAssertion struct {
	Scanner string
	CheckID string
}

// Deterministic port assignment: 30000 + hash(id) mod 30000.
func hostPort(id string) int {
	h := 0
	for _, c := range id {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return 30000 + (h % 30000)
}

var drydockTmpl = template.Must(template.New("drydock").Parse(`# AUTO-GENERATED from nuclei template {{.SourceID}}
name: {{.Name}}
description: "Auto-generated: {{.Description}}"
tags: [{{.Tags}}]

services:
  target:
    image: {{.Image}}
    ports: ["{{.HostPort}}:{{.ContPort}}"]

ready:
  cmd: "curl -sf {{.ReadyURL}} -o /dev/null"
  timeout: 120s
  interval: 5s

assertions:
  - name: nuclei-detects
    type: beacon
    target: localhost:{{.HostPort}}
    args: ["--no-enrich", "--no-nmap", "--scanners", "nuclei"]
    expect:
      check_id: {{.NucleiCheck}}
{{- if .HasExploit}}

  - name: exploit-chain
    type: beacon
    target: localhost:{{.HostPort}}
    args: ["--no-enrich", "--no-nmap", "--scanners", "nuclei", "--scanners", "{{.ExploitSpec.Scanner}}", "--authorized", "--yes"]
    expect:
      check_id: {{.ExploitSpec.CheckID}}
{{- end}}

timeout: {{.Timeout}}
`))

var drydockWPTmpl = template.Must(template.New("drydock-wp").Parse(`# AUTO-GENERATED from nuclei template {{.SourceID}}
name: {{.Name}}
description: "Auto-generated: {{.Description}}"
tags: [{{.Tags}}]

services:
  db:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: testpass
      MYSQL_DATABASE: wordpress

  wordpress:
    build: {{.WPFixtureDir}}
    ports: ["{{.HostPort}}:80"]
    depends_on: [db]
    environment:
      WORDPRESS_DB_HOST: db
      WORDPRESS_DB_PASSWORD: testpass

ready:
  cmd: "curl -sf {{.ReadyURL}} -o /dev/null"
  timeout: 120s
  interval: 5s

assertions:
  - name: nuclei-detects
    type: beacon
    target: localhost:{{.HostPort}}
    args: ["--no-enrich", "--no-nmap", "--scanners", "nuclei"]
    expect:
      check_id: {{.NucleiCheck}}
{{- if .HasExploit}}

  - name: exploit-chain
    type: beacon
    target: localhost:{{.HostPort}}
    args: ["--no-enrich", "--no-nmap", "--scanners", "nuclei", "--scanners", "{{.ExploitSpec.Scanner}}", "--authorized", "--yes"]
    expect:
      check_id: {{.ExploitSpec.CheckID}}
{{- end}}

timeout: {{.Timeout}}
`))

// ---------------------------------------------------------------------------
// Filter parsing
// ---------------------------------------------------------------------------

type Filter struct {
	Severities map[string]bool
}

// parseFilterFlag splits "severity:critical,high" into the Filter struct.
// It handles both "severity:critical,high" and "severity:critical,severity:high".
func parseFilterFlag(raw string) Filter {
	f := Filter{Severities: map[string]bool{}}
	if raw == "" {
		return f
	}
	// Strip leading key if present.
	s := strings.TrimPrefix(raw, "severity:")
	for _, v := range strings.Split(s, ",") {
		v = strings.TrimSpace(strings.ToLower(v))
		v = strings.TrimPrefix(v, "severity:")
		if v != "" {
			f.Severities[v] = true
		}
	}
	return f
}

func (f Filter) Match(severity string) bool {
	if len(f.Severities) == 0 {
		return true // no filter = match all
	}
	return f.Severities[strings.ToLower(severity)]
}

// ---------------------------------------------------------------------------
// Summary report
// ---------------------------------------------------------------------------

type Summary struct {
	Total     int
	Generated int
	Skipped   int
	ByClass   map[string]int
	SkipNoImg int
	SkipFilter int
}

func (s *Summary) Print() {
	fmt.Println("\n=== beacon-testgen summary ===")
	fmt.Printf("Templates scanned : %d\n", s.Total)
	fmt.Printf("Tests generated   : %d\n", s.Generated)
	fmt.Printf("Skipped (total)   : %d\n", s.Skipped)
	fmt.Printf("  - no image map  : %d\n", s.SkipNoImg)
	fmt.Printf("  - filtered out  : %d\n", s.SkipFilter)
	fmt.Println()

	if len(s.ByClass) > 0 {
		fmt.Println("By vulnerability class:")
		// Sort for deterministic output.
		keys := make([]string, 0, len(s.ByClass))
		for k := range s.ByClass {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("  %-20s %d\n", k, s.ByClass[k])
		}
	}
	fmt.Println()
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	templatesDir := flag.String("templates-dir", "", "Path to nuclei-templates directory (required)")
	outputDir := flag.String("output-dir", "tests/scanners/generated", "Output directory for generated test YAML files")
	filterRaw := flag.String("filter", "", "Filter templates, e.g. severity:critical,high")
	dryRun := flag.Bool("dry-run", false, "Print summary without writing files")
	flag.Parse()

	if *templatesDir == "" {
		fmt.Fprintln(os.Stderr, "error: --templates-dir is required")
		flag.Usage()
		os.Exit(1)
	}

	filter := parseFilterFlag(*filterRaw)

	// Collect all YAML files under templates dir.
	var yamlFiles []string
	err := filepath.Walk(*templatesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" {
			yamlFiles = append(yamlFiles, path)
		}
		return nil
	})
	if err != nil {
		log.Fatalf("walking templates dir: %v", err)
	}

	summary := Summary{ByClass: map[string]int{}}

	if !*dryRun {
		if err := os.MkdirAll(*outputDir, 0o755); err != nil {
			log.Fatalf("creating output dir: %v", err)
		}
	}

	for _, path := range yamlFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var tmpl NucleiTemplate
		if err := yaml.Unmarshal(data, &tmpl); err != nil {
			continue
		}
		if tmpl.ID == "" || tmpl.Info.Name == "" {
			continue // not a valid nuclei template
		}

		summary.Total++

		// Apply severity filter.
		if !filter.Match(tmpl.Info.Severity) {
			summary.Skipped++
			summary.SkipFilter++
			continue
		}

		// Resolve Docker image.
		imgInfo, _, found := resolveImage(tmpl)
		if !found {
			summary.Skipped++
			summary.SkipNoImg++
			continue
		}

		// Classify vulnerability.
		tags := tmpl.Info.TagList()
		vc, exploitable := classifyTemplate(tags)

		hp := hostPort(tmpl.ID)

		// Build tag list for the test YAML.
		testTags := []string{"generated"}
		if tmpl.Info.Severity != "" {
			testTags = append(testTags, tmpl.Info.Severity)
		}
		if vc.Name != "unknown" {
			testTags = append(testTags, strings.ToLower(vc.Name))
		}
		// Add "cve" tag if id starts with CVE-.
		if strings.HasPrefix(strings.ToUpper(tmpl.ID), "CVE-") {
			testTags = append(testTags, "cve")
		}

		safeName := "gen-" + strings.ToLower(strings.ReplaceAll(tmpl.ID, "_", "-"))

		readyURL := fmt.Sprintf("http://localhost:%d/", hp)

		// Detect WordPress plugin templates and handle them specially.
		wpPlugin := isWordPressPlugin(tmpl)
		var wpSlug, wpVersion string
		if wpPlugin {
			wpSlug = wpPluginSlug(tmpl)
			wpVersion = wpVulnVersion(tmpl)
			if wpVersion == "" {
				// Cannot determine installable version; fall back to generic.
				wpPlugin = false
			}
			testTags = append(testTags, "wordpress")
		}

		spec := TestSpec{
			SourceID:    tmpl.ID,
			Name:        safeName,
			Description: escapeYAMLString(tmpl.Info.Name + " (" + tmpl.ID + ")"),
			Tags:        strings.Join(testTags, ", "),
			Image:       imgInfo.Image + ":latest",
			HostPort:    hp,
			ContPort:    imgInfo.DefaultPort,
			ReadyURL:    readyURL,
			NucleiCheck: "nuclei." + tmpl.ID,
			HasExploit:  exploitable,
			Timeout:     "5m",
			IsWPPlugin:  wpPlugin,
		}

		if wpPlugin {
			spec.WPFixtureDir = "./fixtures/" + safeName + "/"
			spec.ContPort = 80
		}

		if exploitable {
			spec.ExploitSpec = &ExploitAssertion{
				Scanner: vc.Scanner,
				CheckID: vc.CheckID,
			}
		}

		summary.Generated++
		summary.ByClass[vc.Name]++

		if *dryRun {
			continue
		}

		// For WordPress plugin templates, create a fixture directory with Dockerfile.
		if wpPlugin {
			fixtureDir := filepath.Join(*outputDir, "fixtures", safeName)
			if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
				log.Printf("warning: cannot create fixture dir %s: %v", fixtureDir, err)
				continue
			}
			dfPath := filepath.Join(fixtureDir, "Dockerfile")
			if err := os.WriteFile(dfPath, []byte(wpDockerfileContent(wpSlug, wpVersion)), 0o644); err != nil {
				log.Printf("warning: cannot write Dockerfile %s: %v", dfPath, err)
				continue
			}
		}

		outPath := filepath.Join(*outputDir, safeName+".yaml")
		f, err := os.Create(outPath)
		if err != nil {
			log.Printf("warning: cannot create %s: %v", outPath, err)
			continue
		}
		tmplToUse := drydockTmpl
		if wpPlugin {
			tmplToUse = drydockWPTmpl
		}
		if err := tmplToUse.Execute(f, spec); err != nil {
			log.Printf("warning: template exec for %s: %v", tmpl.ID, err)
		}
		_ = f.Close()
	}

	summary.Print()
}

// escapeYAMLString does minimal escaping for double-quoted YAML strings.
func escapeYAMLString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
