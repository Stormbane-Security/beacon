package nuclei

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseTemplate_SimpleGET(t *testing.T) {
	yaml := `
id: git-config
info:
  name: Git Configuration - Detect
  author: pdteam
  severity: medium
  tags: config,git,exposure
http:
  - method: GET
    path:
      - "{{BaseURL}}/.git/config"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "[core]"
      - type: status
        status:
          - 200
`
	tmpl, err := ParseTemplate([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseTemplate failed: %v", err)
	}
	if tmpl.ID != "git-config" {
		t.Errorf("ID = %q, want git-config", tmpl.ID)
	}
	if tmpl.Info.Name != "Git Configuration - Detect" {
		t.Errorf("Name = %q", tmpl.Info.Name)
	}
	if tmpl.Info.Severity != "medium" {
		t.Errorf("Severity = %q", tmpl.Info.Severity)
	}
	if len(tmpl.HTTP) != 1 {
		t.Fatalf("HTTP blocks = %d, want 1", len(tmpl.HTTP))
	}
	block := tmpl.HTTP[0]
	if block.Method != "GET" {
		t.Errorf("Method = %q", block.Method)
	}
	if len(block.Path) != 1 || block.Path[0] != "{{BaseURL}}/.git/config" {
		t.Errorf("Path = %v", block.Path)
	}
	if len(block.Matchers) != 2 {
		t.Errorf("Matchers = %d, want 2", len(block.Matchers))
	}
	if block.MatchersCondition != "and" {
		t.Errorf("MatchersCondition = %q", block.MatchersCondition)
	}
}

func TestParseTemplate_RawRequest(t *testing.T) {
	yaml := `
id: CVE-2021-41773
info:
  name: Apache Path Traversal
  severity: high
  classification:
    cve-id: CVE-2021-41773
    cwe-id: CWE-22
    cvss-score: 7.5
  tags: cve,apache,lfi
variables:
  cmd: "echo test"
http:
  - raw:
      - |
        GET /icons/.%2e/%2e%2e/etc/passwd HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"
`
	tmpl, err := ParseTemplate([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseTemplate failed: %v", err)
	}
	if tmpl.ID != "CVE-2021-41773" {
		t.Errorf("ID = %q", tmpl.ID)
	}
	if tmpl.Info.Classification.CVEID != "CVE-2021-41773" {
		t.Errorf("CVE ID = %q", tmpl.Info.Classification.CVEID)
	}
	if tmpl.Info.Classification.CVSSScore != 7.5 {
		t.Errorf("CVSS = %f", tmpl.Info.Classification.CVSSScore)
	}
	if tmpl.Variables["cmd"] != "echo test" {
		t.Errorf("Variables[cmd] = %q", tmpl.Variables["cmd"])
	}
	if len(tmpl.HTTP[0].Raw) != 1 {
		t.Errorf("Raw = %d, want 1", len(tmpl.HTTP[0].Raw))
	}
}

func TestParseTemplate_Payloads(t *testing.T) {
	yaml := `
id: grafana-default-login
info:
  name: Grafana Default Login
  severity: high
  metadata:
    product: grafana
    vendor: grafana
  tags: grafana,default-login
http:
  - raw:
      - |
        POST /login HTTP/1.1
        Host: {{Hostname}}
        content-type: application/json

        {"user":"{{username}}","password":"{{password}}"}
    attack: pitchfork
    payloads:
      username:
        - admin
      password:
        - admin
    matchers-condition: and
    matchers:
      - type: word
        words:
          - "Logged in"
      - type: status
        status:
          - 200
`
	tmpl, err := ParseTemplate([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseTemplate failed: %v", err)
	}
	block := tmpl.HTTP[0]
	if block.Attack != "pitchfork" {
		t.Errorf("Attack = %q", block.Attack)
	}
	if len(block.Payloads) != 2 {
		t.Errorf("Payloads = %d, want 2", len(block.Payloads))
	}
	if block.Payloads["username"][0] != "admin" {
		t.Errorf("username payload = %v", block.Payloads["username"])
	}
	if tmpl.Info.Metadata.Product != "grafana" {
		t.Errorf("Product = %q", tmpl.Info.Metadata.Product)
	}
}

func TestParseTemplate_MissingID(t *testing.T) {
	yaml := `
info:
  name: No ID
  severity: low
http:
  - method: GET
    path: ["{{BaseURL}}/"]
`
	_, err := ParseTemplate([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing ID")
	}
}

func TestParseTemplate_NoHTTPBlocks(t *testing.T) {
	yaml := `
id: no-http
info:
  name: No HTTP
  severity: low
`
	_, err := ParseTemplate([]byte(yaml))
	if err == nil {
		t.Fatal("expected error for missing http blocks")
	}
}

func TestTagList(t *testing.T) {
	tmpl := &Template{
		Info: TemplateInfo{Tags: "cve,apache, lfi , rce"},
	}
	tags := tmpl.TagList()
	want := []string{"cve", "apache", "lfi", "rce"}
	if len(tags) != len(want) {
		t.Fatalf("TagList() = %v, want %v", tags, want)
	}
	for i, tag := range tags {
		if tag != want[i] {
			t.Errorf("tag[%d] = %q, want %q", i, tag, want[i])
		}
	}
}

func TestHasTag(t *testing.T) {
	tmpl := &Template{
		Info: TemplateInfo{Tags: "cve,apache,lfi"},
	}
	if !tmpl.HasTag("apache") {
		t.Error("HasTag(apache) = false")
	}
	if !tmpl.HasTag("Apache") {
		t.Error("HasTag(Apache) = false (case insensitive)")
	}
	if tmpl.HasTag("nginx") {
		t.Error("HasTag(nginx) = true")
	}
}

func TestLoadTemplatesDir_RealTemplates(t *testing.T) {
	// Test loading actual templates if available
	dir := os.Getenv("HOME") + "/nuclei-templates/http/exposures/configs"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("nuclei-templates not found at ~/nuclei-templates")
	}

	var errCount int
	templates, err := LoadTemplatesDir(dir, func(path string, err error) {
		errCount++
	})
	if err != nil {
		t.Fatalf("LoadTemplatesDir: %v", err)
	}
	if len(templates) == 0 {
		t.Fatal("expected templates to be loaded")
	}
	t.Logf("loaded %d templates, %d errors", len(templates), errCount)
}

func TestStringSlice_SingleValue(t *testing.T) {
	yaml := `
id: test
info:
  name: Test
  severity: low
  reference: https://example.com
  tags: test
http:
  - method: GET
    path: "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
`
	tmpl, err := ParseTemplate([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if len(tmpl.Info.Reference) != 1 || tmpl.Info.Reference[0] != "https://example.com" {
		t.Errorf("Reference = %v", tmpl.Info.Reference)
	}
}

func TestExtractors(t *testing.T) {
	yaml := `
id: test-extractor
info:
  name: Test Extractors
  severity: low
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
    extractors:
      - type: regex
        part: body
        group: 1
        regex:
          - "version: ([0-9.]+)"
      - type: kval
        kval:
          - server
          - x-powered-by
`
	tmpl, err := ParseTemplate([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseTemplate: %v", err)
	}
	if len(tmpl.HTTP[0].Extractors) != 2 {
		t.Fatalf("Extractors = %d, want 2", len(tmpl.HTTP[0].Extractors))
	}
	if tmpl.HTTP[0].Extractors[0].Group != 1 {
		t.Errorf("Extractor[0].Group = %d, want 1", tmpl.HTTP[0].Extractors[0].Group)
	}
	if len(tmpl.HTTP[0].Extractors[1].KVal) != 2 {
		t.Errorf("Extractor[1].KVal = %v", tmpl.HTTP[0].Extractors[1].KVal)
	}
}

func TestLoadTemplate_FromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.yaml")
	content := `
id: file-test
info:
  name: File Test
  severity: info
  tags: test
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status: [200]
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	tmpl, err := LoadTemplate(path)
	if err != nil {
		t.Fatalf("LoadTemplate: %v", err)
	}
	if tmpl.ID != "file-test" {
		t.Errorf("ID = %q", tmpl.ID)
	}
	if tmpl.Path != path {
		t.Errorf("Path = %q, want %q", tmpl.Path, path)
	}
}
