// migrate-checks reads all scanner source files, finds which finding.Check*
// constants each scanner uses, looks up their metadata in the existing Registry
// map in checkids.go, and rewrites each scanner's init() to use
// scan.RegisterWithCheckDecls instead of scan.Register.
//
// Usage: go run ./internal/finding/cmd/migrate-checks
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// registryEntry holds the metadata for a check ID from the hand-written Registry.
type registryEntry struct {
	constName string // e.g. "CheckCORSMisconfiguration"
	severity  string // e.g. "SeverityHigh"
	mode      string // e.g. "ModeSurface" or "ModeDeep"
}

func main() {
	root := "internal/scanner"

	// Step 1: Parse the Registry map from checkids.go
	registry := parseRegistry("internal/finding/checkids.go")
	fmt.Printf("Parsed %d Registry entries\n", len(registry))

	// Step 2: Find all scanner directories
	scannerDirs, err := filepath.Glob(filepath.Join(root, "*"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "glob: %v\n", err)
		os.Exit(1)
	}

	migrated := 0
	skipped := 0
	for _, dir := range scannerDirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}

		scannerFile := filepath.Join(dir, "scanner.go")
		if _, err := os.Stat(scannerFile); err != nil {
			continue
		}

		ok := migrateScanner(dir, scannerFile, registry)
		if ok {
			migrated++
		} else {
			skipped++
		}
	}

	// Also handle nested scanner dirs (cloud/aws, cloud/gcp, etc.)
	nestedDirs, _ := filepath.Glob(filepath.Join(root, "*", "*"))
	for _, dir := range nestedDirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		scannerFile := filepath.Join(dir, "scanner.go")
		if _, err := os.Stat(scannerFile); err != nil {
			continue
		}
		ok := migrateScanner(dir, scannerFile, registry)
		if ok {
			migrated++
		} else {
			skipped++
		}
	}

	fmt.Printf("\nMigrated: %d, Skipped: %d\n", migrated, skipped)
}

func migrateScanner(dir, scannerFile string, registry map[string]registryEntry) bool {
	// Read scanner.go
	src, err := os.ReadFile(scannerFile)
	if err != nil {
		return false
	}
	content := string(src)

	// Check if already migrated
	if strings.Contains(content, "RegisterWithCheckDecls") {
		return false
	}

	// Check if it uses scan.Register
	if !strings.Contains(content, "scan.Register(") {
		fmt.Printf("SKIP %s: no scan.Register\n", dir)
		return false
	}

	// Find all Check* constants used in this scanner directory
	checkIDs := findCheckIDsInDir(dir)
	if len(checkIDs) == 0 {
		fmt.Printf("SKIP %s: no check IDs found\n", dir)
		return false
	}

	// Look up metadata for each check ID
	var checks []string
	for _, cid := range checkIDs {
		entry, ok := registry[cid]
		if !ok {
			fmt.Printf("  WARN %s: %s not in Registry\n", dir, cid)
			// Use defaults
			entry = registryEntry{constName: cid, severity: "SeverityInfo", mode: "ModeDeep"}
		}
		checks = append(checks, fmt.Sprintf(
			"\t\tscan.Check(finding.%s, finding.%s, finding.%s),",
			entry.constName, entry.severity, entry.mode))
	}

	// Replace scan.Register( with scan.RegisterWithCheckDecls(
	// Pattern: scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {\n\t\treturn New()\n\t})
	// Also handles variants with different func param names

	// Find the Register call and its closing paren
	registerPattern := regexp.MustCompile(`scan\.Register\(scannerName, func\([^)]*\) scan\.Scanner \{\s*\n\s*return New\(\)\s*\n\s*\}\)`)
	loc := registerPattern.FindStringIndex(content)
	if loc == nil {
		// Try alternate pattern without scannerName
		registerPattern = regexp.MustCompile(`scan\.Register\("[^"]+", func\([^)]*\) scan\.Scanner \{\s*\n\s*return New\(\)\s*\n\s*\}\)`)
		loc = registerPattern.FindStringIndex(content)
	}
	if loc == nil {
		fmt.Printf("SKIP %s: can't find Register pattern\n", dir)
		return false
	}

	matched := content[loc[0]:loc[1]]

	// Build replacement
	replacement := strings.Replace(matched, "scan.Register(", "scan.RegisterWithCheckDecls(", 1)
	// Remove the closing ) and add check declarations
	replacement = replacement[:len(replacement)-1] + ",\n" + strings.Join(checks, "\n") + "\n\t)"

	newContent := content[:loc[0]] + replacement + content[loc[1]:]

	// Write back
	if err := os.WriteFile(scannerFile, []byte(newContent), 0644); err != nil {
		fmt.Printf("ERROR %s: write: %v\n", dir, err)
		return false
	}

	fmt.Printf("OK %s: %d checks\n", dir, len(checkIDs))
	return true
}

func findCheckIDsInDir(dir string) []string {
	// Parse all .go files in the directory
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			continue
		}

		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != "finding" {
				return true
			}
			name := sel.Sel.Name
			if strings.HasPrefix(name, "Check") && name != "CheckID" && name != "CheckMeta" {
				seen[name] = true
			}
			return true
		})
	}

	// Sort for deterministic output
	var result []string
	for name := range seen {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

// parseRegistry reads checkids.go and extracts the Registry map entries.
// Returns a map from const name (e.g. "CheckCORSMisconfiguration") to its metadata.
func parseRegistry(path string) map[string]registryEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(1)
	}

	result := make(map[string]registryEntry)

	// Parse lines like:
	//   CheckEmailSpoofable:          {CheckEmailSpoofable, SeverityCritical, ModeSurface},
	re := regexp.MustCompile(`(Check\w+):\s*\{(Check\w+),\s*(Severity\w+),\s*(Mode\w+)\}`)
	for _, match := range re.FindAllStringSubmatch(string(data), -1) {
		key := match[1]
		result[key] = registryEntry{
			constName: match[2],
			severity:  match[3],
			mode:      match[4],
		}
	}

	return result
}
