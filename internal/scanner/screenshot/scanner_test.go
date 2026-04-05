package screenshot

import (
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestName(t *testing.T) {
	s := New("")
	if s.Name() != "screenshot" {
		t.Errorf("expected 'screenshot', got %q", s.Name())
	}
}

func TestNew_DefaultBin(t *testing.T) {
	s := New("")
	if s.bin != "gowitness" {
		t.Errorf("expected default bin 'gowitness', got %q", s.bin)
	}
}

func TestNew_CustomBin(t *testing.T) {
	s := New("/usr/local/bin/gowitness")
	if s.bin != "/usr/local/bin/gowitness" {
		t.Errorf("expected custom bin, got %q", s.bin)
	}
}

func TestHasBrowser_NoPanic(t *testing.T) {
	// Just verify it doesn't panic — result depends on the host.
	_ = hasBrowser()
}

func TestDataURI_ValidFinding(t *testing.T) {
	f := finding.Finding{
		CheckID: finding.CheckAssetScreenshot,
		Evidence: map[string]any{
			"image_b64": "data:image/png;base64,iVBORw0KGgo=",
		},
	}
	uri := DataURI(f)
	if uri != "data:image/png;base64,iVBORw0KGgo=" {
		t.Errorf("expected data URI, got %q", uri)
	}
}

func TestDataURI_WrongCheckID(t *testing.T) {
	f := finding.Finding{
		CheckID: "web.xss",
		Evidence: map[string]any{
			"image_b64": "data:image/png;base64,iVBORw0KGgo=",
		},
	}
	if uri := DataURI(f); uri != "" {
		t.Errorf("expected empty string for wrong check ID, got %q", uri)
	}
}

func TestDataURI_MissingEvidence(t *testing.T) {
	f := finding.Finding{
		CheckID:  finding.CheckAssetScreenshot,
		Evidence: map[string]any{},
	}
	if uri := DataURI(f); uri != "" {
		t.Errorf("expected empty string for missing evidence, got %q", uri)
	}
}

func TestDataURI_NilEvidence(t *testing.T) {
	f := finding.Finding{
		CheckID:      finding.CheckAssetScreenshot,
		DiscoveredAt: time.Now(),
	}
	if uri := DataURI(f); uri != "" {
		t.Errorf("expected empty string for nil evidence, got %q", uri)
	}
}
