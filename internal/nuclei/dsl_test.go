package nuclei

import "testing"

func testCtx() *dslContext {
	return &dslContext{
		StatusCode: 200,
		Body:       `{"status":"ok","version":"2.4.49"}`,
		Header:     "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\nContent-Type: application/json\r\n",
		ContentLen: 34,
		All:        "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\n{\"status\":\"ok\"}",
		Extractions: map[string]string{
			"version": "2.4.49",
		},
	}
}

func TestEvalDSL_StatusCode(t *testing.T) {
	ctx := testCtx()

	tests := []struct {
		expr string
		want bool
	}{
		{"status_code == 200", true},
		{"status_code == 404", false},
		{"status_code != 404", true},
		{"status_code != 200", false},
		{"status_code >= 200", true},
		{"status_code <= 200", true},
		{"status_code > 199", true},
		{"status_code < 201", true},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			got, err := evalDSL(tt.expr, ctx)
			if err != nil {
				t.Fatalf("evalDSL(%q): %v", tt.expr, err)
			}
			if got != tt.want {
				t.Errorf("evalDSL(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestEvalDSL_Contains(t *testing.T) {
	ctx := testCtx()

	tests := []struct {
		expr string
		want bool
	}{
		{`contains(body, "status")`, true},
		{`contains(body, "nothere")`, false},
		{`contains(header, "Apache")`, true},
		{`!contains(body, "<html")`, true},
		{`!contains(body, "status")`, false},
		{`contains(tolower(body), "status")`, true},
		{`!contains(tolower(body), '<html')`, true},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			got, err := evalDSL(tt.expr, ctx)
			if err != nil {
				t.Fatalf("evalDSL(%q): %v", tt.expr, err)
			}
			if got != tt.want {
				t.Errorf("evalDSL(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestEvalDSL_ContainsAny(t *testing.T) {
	ctx := testCtx()

	tests := []struct {
		expr string
		want bool
	}{
		{`contains_any(body, "status", "error")`, true},
		{`contains_any(body, "missing", "nope")`, false},
		{`contains_any(body, "missing", "version")`, true},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			got, err := evalDSL(tt.expr, ctx)
			if err != nil {
				t.Fatalf("evalDSL(%q): %v", tt.expr, err)
			}
			if got != tt.want {
				t.Errorf("evalDSL(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestEvalDSL_Regex(t *testing.T) {
	ctx := testCtx()

	got, err := evalDSL(`regex(body, "version.*[0-9]+")`, ctx)
	if err != nil {
		t.Fatalf("evalDSL: %v", err)
	}
	if !got {
		t.Error("expected regex match")
	}

	got, err = evalDSL(`regex(body, "^NOMATCH$")`, ctx)
	if err != nil {
		t.Fatalf("evalDSL: %v", err)
	}
	if got {
		t.Error("expected no regex match")
	}
}

func TestEvalDSL_Len(t *testing.T) {
	ctx := testCtx()

	tests := []struct {
		expr string
		want bool
	}{
		{"len(body) > 0", true},
		{"len(body) == 34", true},
		{"len(body) < 100", true},
		{"len(body) == 0", false},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			got, err := evalDSL(tt.expr, ctx)
			if err != nil {
				t.Fatalf("evalDSL(%q): %v", tt.expr, err)
			}
			if got != tt.want {
				t.Errorf("evalDSL(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestEvalDSL_LogicalOperators(t *testing.T) {
	ctx := testCtx()

	tests := []struct {
		expr string
		want bool
	}{
		{`status_code == 200 && contains(body, "status")`, true},
		{`status_code == 200 && contains(body, "missing")`, false},
		{`status_code == 404 || contains(body, "status")`, true},
		{`status_code == 404 || contains(body, "missing")`, false},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			got, err := evalDSL(tt.expr, ctx)
			if err != nil {
				t.Fatalf("evalDSL(%q): %v", tt.expr, err)
			}
			if got != tt.want {
				t.Errorf("evalDSL(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestEvalDSL_EmptyAndBooleans(t *testing.T) {
	ctx := testCtx()

	tests := []struct {
		expr string
		want bool
	}{
		{"", true},
		{"true", true},
		{"false", false},
	}

	for _, tt := range tests {
		t.Run(tt.expr, func(t *testing.T) {
			got, err := evalDSL(tt.expr, ctx)
			if err != nil {
				t.Fatalf("evalDSL(%q): %v", tt.expr, err)
			}
			if got != tt.want {
				t.Errorf("evalDSL(%q) = %v, want %v", tt.expr, got, tt.want)
			}
		})
	}
}

func TestSplitLogical(t *testing.T) {
	parts := splitLogical(`a == "b && c" && d == e`, "&&")
	if len(parts) != 2 {
		t.Fatalf("splitLogical = %v, want 2 parts", parts)
	}
	if parts[0] != `a == "b && c"` {
		t.Errorf("part[0] = %q", parts[0])
	}
	if parts[1] != "d == e" {
		t.Errorf("part[1] = %q", parts[1])
	}
}

func TestParseFuncArgs(t *testing.T) {
	args, err := parseFuncArgs(`contains(body, "hello, world")`, "contains")
	if err != nil {
		t.Fatal(err)
	}
	if len(args) != 2 {
		t.Fatalf("args = %v", args)
	}
	if args[0] != "body" {
		t.Errorf("arg[0] = %q", args[0])
	}
	if args[1] != `"hello, world"` {
		t.Errorf("arg[1] = %q", args[1])
	}
}

func TestUnquote(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{`"hello"`, "hello"},
		{`'hello'`, "hello"},
		{`hello`, "hello"},
		{`""`, ""},
		{`"`, `"`},
	}
	for _, tt := range tests {
		got := unquote(tt.input)
		if got != tt.want {
			t.Errorf("unquote(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
