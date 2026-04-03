package nuclei

import (
	"os"
	"testing"
)

func makeTemplate(id string, tags string, product string, cveID string, path string) *Template {
	return &Template{
		ID: id,
		Info: TemplateInfo{
			Name:     id,
			Severity: "medium",
			Tags:     tags,
			Metadata: Metadata{Product: product},
			Classification: Classification{CVEID: cveID},
		},
		Path: path,
		HTTP: []HTTPBlock{{Method: "GET", Path: StringSlice{"{{BaseURL}}/"}}},
	}
}

func TestIndex_ClassifyTier_Always(t *testing.T) {
	idx := NewIndex()

	// Exposure tag → always
	tmpl := makeTemplate("git-config", "config,exposure,git", "", "", "")
	idx.Add(tmpl)

	// Misconfig tag → always
	tmpl2 := makeTemplate("admin-panel", "misconfig,exposure", "", "", "")
	idx.Add(tmpl2)

	_, always, _, _ := idx.Stats()
	if always != 2 {
		t.Errorf("always = %d, want 2", always)
	}
}

func TestIndex_ClassifyTier_AlwaysByPath(t *testing.T) {
	idx := NewIndex()

	tmpl := makeTemplate("some-panel", "panel", "", "", "/nuclei-templates/http/exposed-panels/some-panel.yaml")
	idx.Add(tmpl)

	_, always, _, _ := idx.Stats()
	if always != 1 {
		t.Errorf("always = %d, want 1 (classified by path)", always)
	}
}

func TestIndex_ClassifyTier_Targeted(t *testing.T) {
	idx := NewIndex()

	// Has specific product → targeted
	tmpl := makeTemplate("CVE-2021-41773", "cve,apache,lfi", "http_server", "CVE-2021-41773", "")
	idx.Add(tmpl)

	_, _, _, targeted := idx.Stats()
	if targeted != 1 {
		t.Errorf("targeted = %d, want 1", targeted)
	}
}

func TestIndex_ClassifyTier_Signal(t *testing.T) {
	idx := NewIndex()

	// No product, no always tags, no CVE → signal
	tmpl := makeTemplate("php-errors", "php,errors", "", "", "")
	idx.Add(tmpl)

	_, _, signal, _ := idx.Stats()
	if signal != 1 {
		t.Errorf("signal = %d, want 1", signal)
	}
}

func TestIndex_SelectTemplates_NoSignals(t *testing.T) {
	idx := NewIndex()
	idx.Add(makeTemplate("always-1", "exposure", "", "", ""))
	idx.Add(makeTemplate("signal-1", "java,errors", "", "", ""))
	idx.Add(makeTemplate("targeted-1", "apache,cve", "http_server", "CVE-2021-00001", ""))

	// No signals → should return ALL templates
	selected := idx.SelectTemplates(nil)
	if len(selected) != 3 {
		t.Errorf("no-signal selection = %d, want 3", len(selected))
	}
}

func TestIndex_SelectTemplates_WithSignals(t *testing.T) {
	idx := NewIndex()
	idx.Add(makeTemplate("always-1", "exposure", "", "", ""))
	idx.Add(makeTemplate("signal-java", "java,errors", "", "", ""))
	idx.Add(makeTemplate("signal-php", "php,errors", "", "", ""))
	idx.Add(makeTemplate("targeted-apache", "apache,cve", "http_server", "CVE-2021-00001", ""))
	idx.Add(makeTemplate("targeted-nginx", "nginx,cve", "nginx", "CVE-2022-00001", ""))

	// Signal "java" + "apache" → always + java-signal + apache-targeted
	selected := idx.SelectTemplates([]string{"java", "apache"})

	ids := make(map[string]bool)
	for _, t := range selected {
		ids[t.ID] = true
	}

	if !ids["always-1"] {
		t.Error("always-1 should be selected")
	}
	if !ids["signal-java"] {
		t.Error("signal-java should be selected")
	}
	if !ids["targeted-apache"] {
		t.Error("targeted-apache should be selected")
	}
	if ids["signal-php"] {
		t.Error("signal-php should NOT be selected")
	}
	if ids["targeted-nginx"] {
		t.Error("targeted-nginx should NOT be selected")
	}
}

func TestIndex_ExcludesDangerous(t *testing.T) {
	idx := NewIndex()
	idx.Add(makeTemplate("safe-template", "exposure", "", "", ""))
	idx.Add(makeTemplate("dos-template", "dos,crash", "", "", ""))
	idx.Add(makeTemplate("fuzz-template", "fuzz", "", "", ""))

	total, _, _, _ := idx.Stats()
	if total != 1 {
		t.Errorf("total = %d, want 1 (dangerous excluded)", total)
	}
}

func TestIndex_ByTag(t *testing.T) {
	idx := NewIndex()
	idx.Add(makeTemplate("t1", "apache,lfi", "", "", ""))
	idx.Add(makeTemplate("t2", "apache,rce", "", "", ""))
	idx.Add(makeTemplate("t3", "nginx,lfi", "", "", ""))

	apacheTemplates := idx.ByTag("apache")
	if len(apacheTemplates) != 2 {
		t.Errorf("ByTag(apache) = %d, want 2", len(apacheTemplates))
	}

	lfiTemplates := idx.ByTag("lfi")
	if len(lfiTemplates) != 2 {
		t.Errorf("ByTag(lfi) = %d, want 2", len(lfiTemplates))
	}
}

func TestIndex_ByCVE(t *testing.T) {
	idx := NewIndex()
	idx.Add(makeTemplate("CVE-2021-41773", "cve,apache", "http_server", "CVE-2021-41773", ""))

	tmpl := idx.ByCVE("CVE-2021-41773")
	if tmpl == nil {
		t.Fatal("ByCVE returned nil")
	}
	if tmpl.ID != "CVE-2021-41773" {
		t.Errorf("ByCVE ID = %q", tmpl.ID)
	}
}

func TestIndex_ByProduct(t *testing.T) {
	idx := NewIndex()
	idx.Add(makeTemplate("t1", "grafana", "grafana", "", ""))
	idx.Add(makeTemplate("t2", "grafana", "grafana", "", ""))

	templates := idx.ByProduct("grafana")
	if len(templates) != 2 {
		t.Errorf("ByProduct(grafana) = %d, want 2", len(templates))
	}
}

func TestIndex_LoadDir_RealTemplates(t *testing.T) {
	dir := os.Getenv("HOME") + "/nuclei-templates/http"
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("nuclei-templates not found")
	}

	idx := NewIndex()
	loaded, skipped, err := idx.LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}

	total, always, signal, targeted := idx.Stats()
	t.Logf("loaded=%d skipped=%d total=%d always=%d signal=%d targeted=%d",
		loaded, skipped, total, always, signal, targeted)

	if total < 1000 {
		t.Errorf("expected >1000 templates, got %d", total)
	}
	if always == 0 {
		t.Error("expected some always-tier templates")
	}
	if targeted == 0 {
		t.Error("expected some targeted-tier templates")
	}
}
