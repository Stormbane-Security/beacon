package typosquat

import (
	"sort"
	"testing"
)

func TestPermutations(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		checks func(t *testing.T, perms []string)
	}{
		{
			name:   "invalid domain no dot",
			domain: "example",
			checks: func(t *testing.T, perms []string) {
				if perms != nil {
					t.Errorf("expected nil for domain without dot, got %d permutations", len(perms))
				}
			},
		},
		{
			name:   "excludes original domain",
			domain: "example.com",
			checks: func(t *testing.T, perms []string) {
				for _, p := range perms {
					if p == "example.com" {
						t.Error("permutations should not include the original domain")
					}
				}
			},
		},
		{
			name:   "no duplicates",
			domain: "example.com",
			checks: func(t *testing.T, perms []string) {
				seen := map[string]bool{}
				for _, p := range perms {
					if seen[p] {
						t.Errorf("duplicate permutation: %s", p)
					}
					seen[p] = true
				}
			},
		},
		{
			name:   "generates TLD swaps",
			domain: "example.com",
			checks: func(t *testing.T, perms []string) {
				set := toSet(perms)
				for _, want := range []string{"example.net", "example.org", "example.io"} {
					if !set[want] {
						t.Errorf("expected TLD swap %q in permutations", want)
					}
				}
			},
		},
		{
			name:   "TLD swap excludes own TLD",
			domain: "example.net",
			checks: func(t *testing.T, perms []string) {
				set := toSet(perms)
				if set["example.net"] {
					t.Error("TLD swap should not produce the original domain")
				}
				if !set["example.com"] {
					t.Error("expected example.com in TLD swaps for example.net")
				}
			},
		},
		{
			name:   "generates character omissions",
			domain: "test.com",
			checks: func(t *testing.T, perms []string) {
				set := toSet(perms)
				// Dropping 't' (index 0) -> "est.com"
				// Dropping 'e' (index 1) -> "tst.com"
				// Dropping 's' (index 2) -> "tet.com"
				// Dropping 't' (index 3) -> "tes.com"
				for _, want := range []string{"est.com", "tst.com", "tet.com", "tes.com"} {
					if !set[want] {
						t.Errorf("expected omission %q in permutations", want)
					}
				}
			},
		},
		{
			name:   "generates transpositions",
			domain: "test.com",
			checks: func(t *testing.T, perms []string) {
				set := toSet(perms)
				// Swap t<->e -> "etst.com"
				// Swap e<->s -> "tset.com"
				// Swap s<->t -> "tets.com"
				for _, want := range []string{"etst.com", "tset.com", "tets.com"} {
					if !set[want] {
						t.Errorf("expected transposition %q in permutations", want)
					}
				}
			},
		},
		{
			name:   "generates character doublings",
			domain: "ab.com",
			checks: func(t *testing.T, perms []string) {
				set := toSet(perms)
				for _, want := range []string{"aab.com", "abb.com"} {
					if !set[want] {
						t.Errorf("expected doubling %q in permutations", want)
					}
				}
			},
		},
		{
			name:   "generates homoglyphs",
			domain: "test.com",
			checks: func(t *testing.T, perms []string) {
				set := toSet(perms)
				// 't' -> '7', 'e' -> '3', 's' -> '5'
				for _, want := range []string{"7est.com", "t3st.com", "te5t.com"} {
					if !set[want] {
						t.Errorf("expected homoglyph %q in permutations", want)
					}
				}
			},
		},
		{
			name:   "generates prefix additions",
			domain: "shop.com",
			checks: func(t *testing.T, perms []string) {
				set := toSet(perms)
				for _, want := range []string{"myshop.com", "getshop.com", "appshop.com"} {
					if !set[want] {
						t.Errorf("expected prefix %q in permutations", want)
					}
				}
			},
		},
		{
			name:   "generates suffix additions",
			domain: "shop.com",
			checks: func(t *testing.T, perms []string) {
				set := toSet(perms)
				for _, want := range []string{"shopapp.com", "shophq.com"} {
					if !set[want] {
						t.Errorf("expected suffix %q in permutations", want)
					}
				}
			},
		},
		{
			name:   "generates hyphen insertions",
			domain: "test.com",
			checks: func(t *testing.T, perms []string) {
				set := toSet(perms)
				for _, want := range []string{"t-est.com", "te-st.com", "tes-t.com"} {
					if !set[want] {
						t.Errorf("expected hyphen insertion %q in permutations", want)
					}
				}
			},
		},
		{
			name:   "produces many candidates for typical domain",
			domain: "example.com",
			checks: func(t *testing.T, perms []string) {
				// A 7-letter name should produce a substantial number of candidates
				// across all mutation strategies.
				if len(perms) < 50 {
					t.Errorf("expected at least 50 permutations for example.com, got %d", len(perms))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			perms := permutations(tt.domain)
			tt.checks(t, perms)
		})
	}
}

func TestAdjacentKeys(t *testing.T) {
	tests := []struct {
		char rune
		want []rune
	}{
		{'q', []rune{'w', 'a'}},
		{'a', []rune{'q', 'w', 's', 'z'}},
		{'m', []rune{'n', 'j', 'k'}},
		{'z', []rune{'a', 's', 'x'}},
		{'0', []rune{'9'}},
		// Uppercase should work the same (lowered internally)
		{'Q', []rune{'w', 'a'}},
		// Character not in map should return nil
		{'.', nil},
		{'!', nil},
	}

	for _, tt := range tests {
		t.Run(string(tt.char), func(t *testing.T) {
			got := adjacentKeys(tt.char)
			if !runesEqual(got, tt.want) {
				t.Errorf("adjacentKeys(%c) = %v, want %v", tt.char, got, tt.want)
			}
		})
	}
}

func TestHomoglyphs(t *testing.T) {
	tests := []struct {
		char rune
		want []rune
	}{
		{'a', []rune{'4', '@'}},
		{'e', []rune{'3'}},
		{'i', []rune{'1', 'l'}},
		{'l', []rune{'1', 'i'}},
		{'o', []rune{'0'}},
		{'s', []rune{'5'}},
		{'t', []rune{'7'}},
		{'z', []rune{'2'}},
		// Uppercase (lowered internally)
		{'A', []rune{'4', '@'}},
		// No homoglyphs defined
		{'x', nil},
		{'w', nil},
	}

	for _, tt := range tests {
		t.Run(string(tt.char), func(t *testing.T) {
			got := homoglyphs(tt.char)
			if !runesEqual(got, tt.want) {
				t.Errorf("homoglyphs(%c) = %v, want %v", tt.char, got, tt.want)
			}
		})
	}
}

func TestAltTLDs(t *testing.T) {
	tests := []struct {
		tld      string
		wantIncl []string
		wantExcl string
	}{
		{
			tld:      "com",
			wantIncl: []string{"net", "org", "io", "dev"},
			wantExcl: "com",
		},
		{
			tld:      "io",
			wantIncl: []string{"com", "net", "org"},
			wantExcl: "io",
		},
		{
			tld:      "xyz",
			wantIncl: []string{"com", "net", "org", "io"},
			wantExcl: "xyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.tld, func(t *testing.T) {
			got := altTLDs(tt.tld)
			set := toSet(got)
			for _, want := range tt.wantIncl {
				if !set[want] {
					t.Errorf("altTLDs(%q) missing %q", tt.tld, want)
				}
			}
			if set[tt.wantExcl] {
				t.Errorf("altTLDs(%q) should exclude %q", tt.tld, tt.wantExcl)
			}
		})
	}
}

func TestIsValidDomainName(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		{"test-site.com", true},
		{"a.com", true},
		{"123.com", true},
		{"abc123.io", true},
		{".com", false},        // empty label
		{"ex@mple.com", false}, // invalid char @
		{"ex ample.com", false}, // space
		{"test!.com", false},    // exclamation mark
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := isValidDomainName(tt.domain)
			if got != tt.want {
				t.Errorf("isValidDomainName(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func toSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	// Sort copies so we compare contents regardless of order.
	ac := make([]int, len(a))
	bc := make([]int, len(b))
	for i := range a {
		ac[i] = int(a[i])
		bc[i] = int(b[i])
	}
	sort.Ints(ac)
	sort.Ints(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}
