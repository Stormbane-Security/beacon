package nuclei

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// dslContext holds the variables available to DSL expressions.
type dslContext struct {
	StatusCode  int
	Body        string
	Header      string
	ContentLen  int
	All         string // header + body
	Extractions map[string]string
}

// evalDSL evaluates a single DSL expression string against the context.
// Supports a subset of Nuclei's DSL language:
//   - status_code == N, status_code != N
//   - contains(part, "str"), !contains(part, "str")
//   - contains_any(part, "a", "b", ...)
//   - regex(part, "pattern")
//   - len(part) OP N
//   - tolower(part), toupper(part)
//   - boolean: true, false
//   - comparisons with &&, ||
func evalDSL(expr string, ctx *dslContext) (bool, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == "true" {
		return true, nil
	}
	if expr == "false" {
		return false, nil
	}

	// Handle && (AND) — split on && but not inside quotes or parens
	if parts := splitLogical(expr, "&&"); len(parts) > 1 {
		for _, p := range parts {
			r, err := evalDSL(p, ctx)
			if err != nil {
				return false, err
			}
			if !r {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle || (OR)
	if parts := splitLogical(expr, "||"); len(parts) > 1 {
		for _, p := range parts {
			r, err := evalDSL(p, ctx)
			if err != nil {
				return false, err
			}
			if r {
				return true, nil
			}
		}
		return false, nil
	}

	// Handle negation: !expr
	if strings.HasPrefix(expr, "!") {
		inner := strings.TrimSpace(expr[1:])
		r, err := evalDSL(inner, ctx)
		if err != nil {
			return false, err
		}
		return !r, nil
	}

	// Handle parenthesized expression
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		inner := expr[1 : len(expr)-1]
		return evalDSL(inner, ctx)
	}

	// status_code comparisons
	if strings.HasPrefix(expr, "status_code") {
		return evalStatusCode(expr, ctx.StatusCode)
	}

	// contains(part, "string")
	if strings.HasPrefix(expr, "contains(") {
		return evalContains(expr, ctx)
	}

	// contains_any(part, "a", "b", ...)
	if strings.HasPrefix(expr, "contains_any(") {
		return evalContainsAny(expr, ctx)
	}

	// regex(part, "pattern")
	if strings.HasPrefix(expr, "regex(") {
		return evalRegex(expr, ctx)
	}

	// len(part) comparisons
	if strings.HasPrefix(expr, "len(") {
		return evalLen(expr, ctx)
	}

	// Simple string comparisons: 'X' == 'Y', 'X' != 'Y'
	if strings.Contains(expr, "==") || strings.Contains(expr, "!=") {
		return evalComparison(expr, ctx)
	}

	return false, fmt.Errorf("unsupported DSL expression: %s", expr)
}

func resolveVar(name string, ctx *dslContext) string {
	name = strings.TrimSpace(name)
	// Handle function wrapping: tolower(...), toupper(...)
	if strings.HasPrefix(name, "tolower(") && strings.HasSuffix(name, ")") {
		inner := name[8 : len(name)-1]
		return strings.ToLower(resolveVar(inner, ctx))
	}
	if strings.HasPrefix(name, "toupper(") && strings.HasSuffix(name, ")") {
		inner := name[8 : len(name)-1]
		return strings.ToUpper(resolveVar(inner, ctx))
	}

	switch strings.ToLower(name) {
	case "body":
		return ctx.Body
	case "header", "headers":
		return ctx.Header
	case "all", "raw", "response":
		return ctx.All
	case "status_code":
		return strconv.Itoa(ctx.StatusCode)
	case "content_length":
		return strconv.Itoa(ctx.ContentLen)
	default:
		// Check extractions
		if v, ok := ctx.Extractions[name]; ok {
			return v
		}
		return name
	}
}

func evalStatusCode(expr string, code int) (bool, error) {
	expr = strings.TrimSpace(expr)
	if strings.Contains(expr, "!=") {
		parts := strings.SplitN(expr, "!=", 2)
		n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return false, err
		}
		return code != n, nil
	}
	if strings.Contains(expr, "==") {
		parts := strings.SplitN(expr, "==", 2)
		n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return false, err
		}
		return code == n, nil
	}
	if strings.Contains(expr, ">=") {
		parts := strings.SplitN(expr, ">=", 2)
		n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return false, err
		}
		return code >= n, nil
	}
	if strings.Contains(expr, "<=") {
		parts := strings.SplitN(expr, "<=", 2)
		n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return false, err
		}
		return code <= n, nil
	}
	if strings.Contains(expr, ">") {
		parts := strings.SplitN(expr, ">", 2)
		n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return false, err
		}
		return code > n, nil
	}
	if strings.Contains(expr, "<") {
		parts := strings.SplitN(expr, "<", 2)
		n, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			return false, err
		}
		return code < n, nil
	}
	return false, fmt.Errorf("unsupported status_code expression: %s", expr)
}

func evalContains(expr string, ctx *dslContext) (bool, error) {
	// contains(part, "string")
	args, err := parseFuncArgs(expr, "contains")
	if err != nil {
		return false, err
	}
	if len(args) != 2 {
		return false, fmt.Errorf("contains requires 2 args, got %d", len(args))
	}
	haystack := resolveVar(args[0], ctx)
	needle := unquote(args[1])
	return strings.Contains(haystack, needle), nil
}

func evalContainsAny(expr string, ctx *dslContext) (bool, error) {
	args, err := parseFuncArgs(expr, "contains_any")
	if err != nil {
		return false, err
	}
	if len(args) < 2 {
		return false, fmt.Errorf("contains_any requires at least 2 args")
	}
	haystack := resolveVar(args[0], ctx)
	for _, arg := range args[1:] {
		needle := unquote(arg)
		if strings.Contains(haystack, needle) {
			return true, nil
		}
	}
	return false, nil
}

func evalRegex(expr string, ctx *dslContext) (bool, error) {
	args, err := parseFuncArgs(expr, "regex")
	if err != nil {
		return false, err
	}
	if len(args) != 2 {
		return false, fmt.Errorf("regex requires 2 args, got %d", len(args))
	}
	haystack := resolveVar(args[0], ctx)
	pattern := unquote(args[1])
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("regex compile: %w", err)
	}
	return re.MatchString(haystack), nil
}

func evalLen(expr string, ctx *dslContext) (bool, error) {
	// len(part) > N, len(part) == N, etc.
	// Find the closing paren of len()
	idx := strings.Index(expr, ")")
	if idx == -1 {
		return false, fmt.Errorf("malformed len expression: %s", expr)
	}
	varName := expr[4:idx] // between "len(" and ")"
	rest := strings.TrimSpace(expr[idx+1:])
	val := len(resolveVar(varName, ctx))

	return evalIntComparison(val, rest)
}

func evalIntComparison(val int, rest string) (bool, error) {
	if strings.HasPrefix(rest, ">=") {
		n, err := strconv.Atoi(strings.TrimSpace(rest[2:]))
		if err != nil {
			return false, err
		}
		return val >= n, nil
	}
	if strings.HasPrefix(rest, "<=") {
		n, err := strconv.Atoi(strings.TrimSpace(rest[2:]))
		if err != nil {
			return false, err
		}
		return val <= n, nil
	}
	if strings.HasPrefix(rest, "!=") {
		n, err := strconv.Atoi(strings.TrimSpace(rest[2:]))
		if err != nil {
			return false, err
		}
		return val != n, nil
	}
	if strings.HasPrefix(rest, "==") {
		n, err := strconv.Atoi(strings.TrimSpace(rest[2:]))
		if err != nil {
			return false, err
		}
		return val == n, nil
	}
	if strings.HasPrefix(rest, ">") {
		n, err := strconv.Atoi(strings.TrimSpace(rest[1:]))
		if err != nil {
			return false, err
		}
		return val > n, nil
	}
	if strings.HasPrefix(rest, "<") {
		n, err := strconv.Atoi(strings.TrimSpace(rest[1:]))
		if err != nil {
			return false, err
		}
		return val < n, nil
	}
	return false, fmt.Errorf("unsupported comparison: %s", rest)
}

func evalComparison(expr string, ctx *dslContext) (bool, error) {
	isNe := strings.Contains(expr, "!=")
	var parts []string
	if isNe {
		parts = strings.SplitN(expr, "!=", 2)
	} else {
		parts = strings.SplitN(expr, "==", 2)
	}
	if len(parts) != 2 {
		return false, fmt.Errorf("malformed comparison: %s", expr)
	}
	left := resolveVar(unquote(strings.TrimSpace(parts[0])), ctx)
	right := resolveVar(unquote(strings.TrimSpace(parts[1])), ctx)
	if isNe {
		return left != right, nil
	}
	return left == right, nil
}

// parseFuncArgs extracts arguments from a function call like "func(a, b, c)".
func parseFuncArgs(expr, funcName string) ([]string, error) {
	prefix := funcName + "("
	if !strings.HasPrefix(expr, prefix) {
		return nil, fmt.Errorf("expected %s(...), got: %s", funcName, expr)
	}
	// Find matching closing paren
	depth := 0
	start := len(prefix)
	end := -1
	for i := start; i < len(expr); i++ {
		switch expr[i] {
		case '(':
			depth++
		case ')':
			if depth == 0 {
				end = i
			} else {
				depth--
			}
		}
		if end != -1 {
			break
		}
	}
	if end == -1 {
		return nil, fmt.Errorf("unmatched paren in %s", expr)
	}
	inner := expr[start:end]

	// Split by comma, respecting quotes
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := byte(0)
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if !inQuote && (c == '"' || c == '\'') {
			inQuote = true
			quoteChar = c
			current.WriteByte(c)
		} else if inQuote && c == quoteChar {
			inQuote = false
			current.WriteByte(c)
		} else if !inQuote && c == ',' {
			args = append(args, strings.TrimSpace(current.String()))
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, strings.TrimSpace(current.String()))
	}
	return args, nil
}

// splitLogical splits an expression on a logical operator (&& or ||),
// respecting parentheses and quotes.
func splitLogical(expr, op string) []string {
	var parts []string
	depth := 0
	inQuote := false
	quoteChar := byte(0)
	last := 0

	for i := 0; i < len(expr); i++ {
		c := expr[i]
		if !inQuote && (c == '"' || c == '\'') {
			inQuote = true
			quoteChar = c
		} else if inQuote && c == quoteChar {
			inQuote = false
		} else if !inQuote {
			switch c {
			case '(':
				depth++
			case ')':
				depth--
			}
		}
		if depth == 0 && !inQuote && i+len(op) <= len(expr) && expr[i:i+len(op)] == op {
			parts = append(parts, strings.TrimSpace(expr[last:i]))
			last = i + len(op)
			i += len(op) - 1
		}
	}
	parts = append(parts, strings.TrimSpace(expr[last:]))
	return parts
}

// unquote removes surrounding quotes from a string.
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
