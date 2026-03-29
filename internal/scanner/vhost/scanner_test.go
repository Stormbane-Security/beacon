package vhost

import "testing"

func TestMateriallyDifferent(t *testing.T) {
	tests := []struct {
		name     string
		baseline *hostResponse
		response *hostResponse
		want     bool
	}{
		{
			name:     "identical responses",
			baseline: &hostResponse{status: 200, bodyLen: 1000, title: "Home"},
			response: &hostResponse{status: 200, bodyLen: 1000, title: "Home"},
			want:     false,
		},
		{
			name:     "different status code",
			baseline: &hostResponse{status: 200, bodyLen: 1000, title: "Home"},
			response: &hostResponse{status: 404, bodyLen: 1000, title: "Home"},
			want:     true,
		},
		{
			name:     "different status 200 vs 301",
			baseline: &hostResponse{status: 200, bodyLen: 500, title: ""},
			response: &hostResponse{status: 301, bodyLen: 500, title: ""},
			want:     true,
		},
		{
			name:     "large body length difference exceeding 20% and 500 bytes",
			baseline: &hostResponse{status: 200, bodyLen: 1000, title: "Home"},
			response: &hostResponse{status: 200, bodyLen: 2000, title: "Home"},
			want:     true,
		},
		{
			name:     "body diff over 500 but under 20%",
			baseline: &hostResponse{status: 200, bodyLen: 10000, title: "Home"},
			response: &hostResponse{status: 200, bodyLen: 10600, title: "Home"},
			want:     false,
		},
		{
			name:     "body diff exactly 500 — not over threshold",
			baseline: &hostResponse{status: 200, bodyLen: 5000, title: "Home"},
			response: &hostResponse{status: 200, bodyLen: 5500, title: "Home"},
			want:     false,
		},
		{
			name:     "body diff 501 and over 20%",
			baseline: &hostResponse{status: 200, bodyLen: 1000, title: "Home"},
			response: &hostResponse{status: 200, bodyLen: 1501, title: "Home"},
			want:     true,
		},
		{
			name:     "small body diff under 500",
			baseline: &hostResponse{status: 200, bodyLen: 1000, title: "Home"},
			response: &hostResponse{status: 200, bodyLen: 1100, title: "Home"},
			want:     false,
		},
		{
			name:     "different titles both non-empty",
			baseline: &hostResponse{status: 200, bodyLen: 1000, title: "Home"},
			response: &hostResponse{status: 200, bodyLen: 1000, title: "Admin Panel"},
			want:     true,
		},
		{
			name:     "baseline empty title, response has title",
			baseline: &hostResponse{status: 200, bodyLen: 1000, title: ""},
			response: &hostResponse{status: 200, bodyLen: 1000, title: "Admin Panel"},
			want:     false,
		},
		{
			name:     "response empty title, baseline has title",
			baseline: &hostResponse{status: 200, bodyLen: 1000, title: "Home"},
			response: &hostResponse{status: 200, bodyLen: 1000, title: ""},
			want:     false,
		},
		{
			name:     "both empty titles same status same length",
			baseline: &hostResponse{status: 200, bodyLen: 1000, title: ""},
			response: &hostResponse{status: 200, bodyLen: 1000, title: ""},
			want:     false,
		},
		{
			name:     "zero body lengths",
			baseline: &hostResponse{status: 200, bodyLen: 0, title: ""},
			response: &hostResponse{status: 200, bodyLen: 0, title: ""},
			want:     false,
		},
		{
			name:     "response body larger than baseline — reversed diff over threshold",
			baseline: &hostResponse{status: 200, bodyLen: 2000, title: "Home"},
			response: &hostResponse{status: 200, bodyLen: 1000, title: "Home"},
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := materiallyDifferent(tt.baseline, tt.response)
			if got != tt.want {
				t.Errorf("materiallyDifferent(baseline=%+v, response=%+v) = %v, want %v",
					tt.baseline, tt.response, got, tt.want)
			}
		})
	}
}

func TestExtractVHostTitle(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "standard title",
			body: "<html><head><title>Welcome</title></head><body></body></html>",
			want: "Welcome",
		},
		{
			name: "title with whitespace",
			body: "<html><head><title>  Spaced Title  </title></head></html>",
			want: "Spaced Title",
		},
		{
			name: "no title tag",
			body: "<html><head></head><body>Hello</body></html>",
			want: "",
		},
		{
			name: "empty title",
			body: "<html><head><title></title></head></html>",
			want: "",
		},
		{
			name: "mixed case title tags",
			body: "<html><head><TITLE>Upper Case</TITLE></head></html>",
			want: "Upper Case",
		},
		{
			name: "title with no closing tag",
			body: "<html><head><title>Unclosed</head></html>",
			want: "",
		},
		{
			name: "empty body",
			body: "",
			want: "",
		},
		{
			name: "title with entities",
			body: "<title>Foo &amp; Bar</title>",
			want: "Foo &amp; Bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractVHostTitle(tt.body)
			if got != tt.want {
				t.Errorf("extractVHostTitle() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildCandidates(t *testing.T) {
	tests := []struct {
		name      string
		asset     string
		wantNil   bool
		wantIncl  []string
		wantExcl  []string
		wantMinN  int
	}{
		{
			name:    "bare domain without subdomain returns nil",
			asset:   "example",
			wantNil: true,
		},
		{
			name:     "standard subdomain generates swap candidates",
			asset:    "www.example.com",
			wantIncl: []string{"dev.example.com", "staging.example.com", "admin.example.com", "api.example.com"},
			wantExcl: []string{"www.example.com"}, // should not include the original asset
		},
		{
			name:     "includes bare domain and www variant",
			asset:    "app.example.com",
			wantIncl: []string{"example.com", "www.example.com"},
		},
		{
			name:     "generates hyphenated dev variants",
			asset:    "app.example.com",
			wantIncl: []string{"dev-app.example.com", "dev.app.example.com"},
		},
		{
			name:     "does not duplicate current prefix in swaps",
			asset:    "dev.example.com",
			wantExcl: []string{"dev.example.com"},
			wantIncl: []string{"staging.example.com", "admin.example.com"},
		},
		{
			name:    "produces at least 20 candidates for typical input",
			asset:   "www.example.com",
			wantMinN: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCandidates(tt.asset)
			if tt.wantNil {
				if got != nil {
					t.Errorf("expected nil, got %d candidates", len(got))
				}
				return
			}

			set := make(map[string]bool, len(got))
			for _, c := range got {
				set[c] = true
			}

			for _, want := range tt.wantIncl {
				if !set[want] {
					t.Errorf("expected candidate %q to be present", want)
				}
			}
			for _, excl := range tt.wantExcl {
				if set[excl] {
					t.Errorf("expected candidate %q to be absent", excl)
				}
			}
			if tt.wantMinN > 0 && len(got) < tt.wantMinN {
				t.Errorf("expected at least %d candidates, got %d", tt.wantMinN, len(got))
			}

			// Check no duplicates
			if len(set) != len(got) {
				t.Errorf("buildCandidates produced duplicates: %d unique out of %d total", len(set), len(got))
			}
		})
	}
}
