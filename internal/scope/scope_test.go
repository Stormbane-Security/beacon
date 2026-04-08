package scope

import (
	"testing"
)

func TestInScope_ExactMatch(t *testing.T) {
	p := &Program{
		Assets: []Asset{
			{Identifier: "api.example.com", InScope: true},
			{Identifier: "admin.example.com", InScope: false},
		},
	}
	if !p.InScope("api.example.com") {
		t.Error("api.example.com should be in scope")
	}
	if p.InScope("admin.example.com") {
		t.Error("admin.example.com should be out of scope")
	}
}

func TestInScope_WildcardMatch(t *testing.T) {
	p := &Program{
		Assets: []Asset{
			{Identifier: "*.example.com", InScope: true},
		},
	}
	if !p.InScope("api.example.com") {
		t.Error("api.example.com should match *.example.com")
	}
	if !p.InScope("dev.api.example.com") {
		t.Error("dev.api.example.com should match *.example.com")
	}
	if !p.InScope("example.com") {
		t.Error("example.com should match *.example.com (bare domain)")
	}
	if p.InScope("notexample.com") {
		t.Error("notexample.com should NOT match *.example.com")
	}
}

func TestInScope_URLStripping(t *testing.T) {
	p := &Program{
		Assets: []Asset{
			{Identifier: "https://api.example.com/", InScope: true},
		},
	}
	if !p.InScope("api.example.com") {
		t.Error("should match after stripping scheme and trailing slash")
	}
}

func TestInScope_CaseInsensitive(t *testing.T) {
	p := &Program{
		Assets: []Asset{
			{Identifier: "API.Example.COM", InScope: true},
		},
	}
	if !p.InScope("api.example.com") {
		t.Error("should match case-insensitively")
	}
}

func TestInScopeAssets_FiltersCorrectly(t *testing.T) {
	p := &Program{
		Assets: []Asset{
			{Identifier: "a.com", InScope: true},
			{Identifier: "b.com", InScope: false},
			{Identifier: "c.com", InScope: true},
		},
	}
	inScope := p.InScopeAssets()
	if len(inScope) != 2 {
		t.Errorf("expected 2 in-scope assets, got %d", len(inScope))
	}
}

func TestOutOfScopeAssets_FiltersCorrectly(t *testing.T) {
	p := &Program{
		Assets: []Asset{
			{Identifier: "a.com", InScope: true},
			{Identifier: "b.com", InScope: false},
		},
	}
	outOfScope := p.OutOfScopeAssets()
	if len(outOfScope) != 1 {
		t.Errorf("expected 1 out-of-scope asset, got %d", len(outOfScope))
	}
	if outOfScope[0].Identifier != "b.com" {
		t.Errorf("expected b.com, got %s", outOfScope[0].Identifier)
	}
}

func TestInScope_EmptyProgram(t *testing.T) {
	p := &Program{}
	if p.InScope("anything.com") {
		t.Error("empty program should have nothing in scope")
	}
}
