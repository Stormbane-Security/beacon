package nuclei

import (
	"regexp"
	"strings"
)

// Response holds an HTTP response for matcher/extractor evaluation.
type Response struct {
	StatusCode int
	Headers    string // raw header text
	Body       string
	Raw        string // headers + body
	ContentLen int
}

// MatchResult holds the outcome of evaluating all matchers on a response.
type MatchResult struct {
	Matched      bool
	MatcherName  string            // name of the matcher that triggered (for "or" condition)
	Extractions  map[string]string // extracted values
}

// evalMatchers evaluates all matchers in an HTTP block against a response.
func evalMatchers(block *HTTPBlock, resp *Response, extractions map[string]string) MatchResult {
	if len(block.Matchers) == 0 {
		return MatchResult{Matched: true, Extractions: extractions}
	}

	condition := strings.ToLower(block.MatchersCondition)
	if condition == "" {
		condition = "and"
	}

	ctx := &dslContext{
		StatusCode:  resp.StatusCode,
		Body:        resp.Body,
		Header:      resp.Headers,
		ContentLen:  resp.ContentLen,
		All:         resp.Raw,
		Extractions: extractions,
	}

	if condition == "or" {
		for _, m := range block.Matchers {
			if matched := evalMatcher(&m, resp, ctx); matched {
				return MatchResult{
					Matched:     true,
					MatcherName: m.Name,
					Extractions: extractions,
				}
			}
		}
		return MatchResult{Matched: false, Extractions: extractions}
	}

	// "and" condition (default)
	for _, m := range block.Matchers {
		if matched := evalMatcher(&m, resp, ctx); !matched {
			return MatchResult{Matched: false, Extractions: extractions}
		}
	}
	return MatchResult{Matched: true, Extractions: extractions}
}

// evalMatcher evaluates a single matcher against the response.
func evalMatcher(m *Matcher, resp *Response, ctx *dslContext) bool {
	var result bool
	switch strings.ToLower(m.Type) {
	case "word":
		result = evalWordMatcher(m, resp)
	case "regex":
		result = evalRegexMatcher(m, resp)
	case "status":
		result = evalStatusMatcher(m, resp)
	case "dsl":
		result = evalDSLMatcher(m, ctx)
	case "size":
		result = evalSizeMatcher(m, resp)
	default:
		return false
	}

	if m.Negative {
		return !result
	}
	return result
}

func matcherPart(m *Matcher, resp *Response) string {
	switch strings.ToLower(m.Part) {
	case "header", "headers":
		return resp.Headers
	case "all", "raw", "response":
		return resp.Raw
	case "status_code":
		return ""
	case "", "body":
		return resp.Body
	default:
		return resp.Body
	}
}

func evalWordMatcher(m *Matcher, resp *Response) bool {
	data := matcherPart(m, resp)
	if m.CaseInsensitive {
		data = strings.ToLower(data)
	}

	condition := strings.ToLower(m.Condition)
	if condition == "" {
		condition = "or" // word matchers default to OR
	}

	if condition == "and" {
		for _, w := range m.Words {
			needle := w
			if m.CaseInsensitive {
				needle = strings.ToLower(needle)
			}
			if !strings.Contains(data, needle) {
				return false
			}
		}
		return len(m.Words) > 0
	}

	// "or" condition
	for _, w := range m.Words {
		needle := w
		if m.CaseInsensitive {
			needle = strings.ToLower(needle)
		}
		if strings.Contains(data, needle) {
			return true
		}
	}
	return false
}

func evalRegexMatcher(m *Matcher, resp *Response) bool {
	data := matcherPart(m, resp)

	condition := strings.ToLower(m.Condition)
	if condition == "" {
		condition = "or"
	}

	if condition == "and" {
		for _, pattern := range m.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			if !re.MatchString(data) {
				return false
			}
		}
		return len(m.Regex) > 0
	}

	for _, pattern := range m.Regex {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		if re.MatchString(data) {
			return true
		}
	}
	return false
}

func evalStatusMatcher(m *Matcher, resp *Response) bool {
	for _, s := range m.Status {
		if resp.StatusCode == s {
			return true
		}
	}
	return false
}

func evalDSLMatcher(m *Matcher, ctx *dslContext) bool {
	condition := strings.ToLower(m.Condition)
	if condition == "" {
		condition = "and"
	}

	if condition == "and" {
		for _, expr := range m.DSL {
			result, err := evalDSL(expr, ctx)
			if err != nil || !result {
				return false
			}
		}
		return len(m.DSL) > 0
	}

	for _, expr := range m.DSL {
		result, err := evalDSL(expr, ctx)
		if err == nil && result {
			return true
		}
	}
	return false
}

func evalSizeMatcher(m *Matcher, resp *Response) bool {
	for _, s := range m.Size {
		if resp.ContentLen == s {
			return true
		}
	}
	return false
}

// runExtractors runs all extractors on the response and returns a map of
// extracted name→value pairs.
func runExtractors(extractors []Extractor, resp *Response) map[string]string {
	results := make(map[string]string)
	for _, e := range extractors {
		vals := runExtractor(&e, resp)
		for k, v := range vals {
			results[k] = v
		}
	}
	return results
}

func runExtractor(e *Extractor, resp *Response) map[string]string {
	results := make(map[string]string)

	switch strings.ToLower(e.Type) {
	case "regex":
		data := extractorPart(e, resp)
		for _, pattern := range e.Regex {
			re, err := regexp.Compile(pattern)
			if err != nil {
				continue
			}
			matches := re.FindStringSubmatch(data)
			if matches == nil {
				continue
			}
			group := e.Group
			if group >= 0 && group < len(matches) {
				name := e.Name
				if name == "" {
					name = pattern
				}
				results[name] = matches[group]
			} else if len(matches) > 0 {
				name := e.Name
				if name == "" {
					name = pattern
				}
				results[name] = matches[0]
			}
		}

	case "kval":
		// Extract header values by key
		headerLines := strings.Split(resp.Headers, "\n")
		for _, key := range e.KVal {
			for _, line := range headerLines {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), key) {
					name := e.Name
					if name == "" {
						name = key
					}
					results[name] = strings.TrimSpace(parts[1])
				}
			}
		}

	case "json":
		// Basic JSON extraction — only supports simple dot-path for now
		// Full JMESPath is out of scope for the initial implementation.
		for _, path := range e.JSON {
			name := e.Name
			if name == "" {
				name = path
			}
			// Simple: just store the path as a placeholder; full JSON
			// extraction requires a JMESPath library.
			results[name] = ""
		}

	case "dsl":
		ctx := &dslContext{
			StatusCode:  resp.StatusCode,
			Body:        resp.Body,
			Header:      resp.Headers,
			ContentLen:  resp.ContentLen,
			All:         resp.Raw,
			Extractions: results,
		}
		for _, expr := range e.DSL {
			name := e.Name
			if name == "" {
				name = expr
			}
			val := resolveVar(expr, ctx)
			results[name] = val
		}
	}

	return results
}

func extractorPart(e *Extractor, resp *Response) string {
	switch strings.ToLower(e.Part) {
	case "header", "headers":
		return resp.Headers
	case "all", "raw", "response":
		return resp.Raw
	case "", "body":
		return resp.Body
	default:
		return resp.Body
	}
}
