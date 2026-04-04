package nuclei

import "testing"

func testResp() *Response {
	return &Response{
		StatusCode: 200,
		Headers:    "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\nX-Powered-By: PHP/7.4\r\nContent-Type: text/html\r\n",
		Body:       `<html><body>[core] url = https://github.com/example/repo.git</body></html>`,
		Raw:        "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\n<html><body>[core]</body></html>",
		ContentLen: 73,
	}
}

func TestEvalWordMatcher_OR(t *testing.T) {
	resp := testResp()
	m := &Matcher{
		Type:  "word",
		Part:  "body",
		Words: []string{"[core]", "[remote]"},
	}
	if !evalMatcher(m, resp, nil) {
		t.Error("word OR matcher should match [core]")
	}

	m.Words = []string{"notfound", "alsonotfound"}
	if evalMatcher(m, resp, nil) {
		t.Error("word OR matcher should not match")
	}
}

func TestEvalWordMatcher_AND(t *testing.T) {
	resp := testResp()
	m := &Matcher{
		Type:      "word",
		Part:      "body",
		Words:     []string{"[core]", "github.com"},
		Condition: "and",
	}
	if !evalMatcher(m, resp, nil) {
		t.Error("word AND matcher should match both")
	}

	m.Words = []string{"[core]", "notfound"}
	if evalMatcher(m, resp, nil) {
		t.Error("word AND matcher should not match")
	}
}

func TestEvalWordMatcher_Header(t *testing.T) {
	resp := testResp()
	m := &Matcher{
		Type:  "word",
		Part:  "header",
		Words: []string{"Apache/2.4.49"},
	}
	if !evalMatcher(m, resp, nil) {
		t.Error("should match header")
	}
}

func TestEvalWordMatcher_CaseInsensitive(t *testing.T) {
	resp := testResp()
	m := &Matcher{
		Type:            "word",
		Part:            "body",
		Words:           []string{"CORE"},
		CaseInsensitive: true,
	}
	if !evalMatcher(m, resp, nil) {
		t.Error("case-insensitive word match failed")
	}
}

func TestEvalWordMatcher_Negative(t *testing.T) {
	resp := testResp()
	m := &Matcher{
		Type:     "word",
		Part:     "body",
		Words:    []string{"notfound"},
		Negative: true,
	}
	if !evalMatcher(m, resp, nil) {
		t.Error("negative word match should succeed")
	}
}

func TestEvalRegexMatcher(t *testing.T) {
	resp := testResp()
	m := &Matcher{
		Type:  "regex",
		Part:  "body",
		Regex: []string{`url\s*=\s*https?://.*\.git`},
	}
	if !evalMatcher(m, resp, nil) {
		t.Error("regex should match git URL")
	}

	m.Regex = []string{`^NOMATCH$`}
	if evalMatcher(m, resp, nil) {
		t.Error("regex should not match")
	}
}

func TestEvalStatusMatcher(t *testing.T) {
	resp := testResp()
	m := &Matcher{
		Type:   "status",
		Status: []int{200, 301},
	}
	if !evalMatcher(m, resp, nil) {
		t.Error("status 200 should match")
	}

	m.Status = []int{404, 500}
	if evalMatcher(m, resp, nil) {
		t.Error("status 404/500 should not match")
	}
}

func TestEvalSizeMatcher(t *testing.T) {
	resp := testResp()
	m := &Matcher{
		Type: "size",
		Size: []int{73},
	}
	if !evalMatcher(m, resp, nil) {
		t.Errorf("size 73 should match (actual ContentLen=%d)", resp.ContentLen)
	}
}

func TestEvalDSLMatcher(t *testing.T) {
	resp := testResp()
	ctx := &dslContext{
		StatusCode: resp.StatusCode,
		Body:       resp.Body,
		Header:     resp.Headers,
		ContentLen: resp.ContentLen,
		All:        resp.Raw,
	}
	m := &Matcher{
		Type: "dsl",
		DSL:  []string{`status_code == 200`, `contains(body, "[core]")`},
	}
	if !evalMatcher(m, resp, ctx) {
		t.Error("DSL matcher should match")
	}

	m.DSL = []string{`status_code == 200`, `contains(body, "notfound")`}
	if evalMatcher(m, resp, ctx) {
		t.Error("DSL matcher AND should fail when one fails")
	}
}

func TestEvalMatchers_AND(t *testing.T) {
	resp := testResp()
	block := &HTTPBlock{
		MatchersCondition: "and",
		Matchers: []Matcher{
			{Type: "word", Part: "body", Words: []string{"[core]"}},
			{Type: "status", Status: []int{200}},
		},
	}
	result := evalMatchers(block, resp, make(map[string]string))
	if !result.Matched {
		t.Error("AND condition should match")
	}
}

func TestEvalMatchers_OR(t *testing.T) {
	resp := testResp()
	block := &HTTPBlock{
		MatchersCondition: "or",
		Matchers: []Matcher{
			{Type: "word", Part: "body", Words: []string{"notfound"}, Name: "first"},
			{Type: "status", Status: []int{200}, Name: "status-ok"},
		},
	}
	result := evalMatchers(block, resp, make(map[string]string))
	if !result.Matched {
		t.Error("OR condition should match via status")
	}
	if result.MatcherName != "status-ok" {
		t.Errorf("MatcherName = %q, want status-ok", result.MatcherName)
	}
}

func TestRunExtractors_Regex(t *testing.T) {
	resp := &Response{
		Body:       `Server version: Apache/2.4.49 (Unix)`,
		Headers:    "Server: Apache/2.4.49\r\n",
		Raw:        "Server: Apache/2.4.49\r\n\r\nServer version: Apache/2.4.49 (Unix)",
		StatusCode: 200,
		ContentLen: 36,
	}
	extractors := []Extractor{
		{
			Type:  "regex",
			Part:  "body",
			Name:  "version",
			Group: 1,
			Regex: []string{`Apache/([0-9.]+)`},
		},
	}
	results := runExtractors(extractors, resp)
	if results["version"] != "2.4.49" {
		t.Errorf("extracted version = %q, want 2.4.49", results["version"])
	}
}

func TestRunExtractors_KVal(t *testing.T) {
	resp := &Response{
		Headers:    "Server: Apache/2.4.49\nX-Powered-By: PHP/7.4\n",
		Body:       "",
		Raw:        "Server: Apache/2.4.49\nX-Powered-By: PHP/7.4\n",
		StatusCode: 200,
	}
	extractors := []Extractor{
		{
			Type: "kval",
			Name: "server",
			KVal: []string{"Server"},
		},
	}
	results := runExtractors(extractors, resp)
	if results["server"] != "Apache/2.4.49" {
		t.Errorf("extracted server = %q", results["server"])
	}
}
