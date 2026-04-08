package screenshot

import (
	"testing"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

func TestName(t *testing.T) {
	s := &Scanner{}
	if s.Name() != "screenshot" {
		t.Errorf("expected 'screenshot', got %q", s.Name())
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
