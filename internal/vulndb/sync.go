package vulndb

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// osvQueryRequest is the request body for the OSV API.
type osvQueryRequest struct {
	Package *osvPackage `json:"package,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// osvVuln is a simplified representation of an OSV vulnerability entry.
type osvVuln struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Details  string `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced"`
				Fixed      string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	Aliases    []string `json:"aliases"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

// SyncOSV fetches vulnerabilities from the OSV API for the given ecosystems.
// It queries the bulk listing endpoint for each ecosystem.
func SyncOSV(db *DB, ecosystems []string) (int, error) {
	if len(ecosystems) == 0 {
		ecosystems = []string{"npm", "PyPI", "Go", "Maven", "crates.io"}
	}
	total := 0
	for _, eco := range ecosystems {
		n, err := syncOSVEcosystem(db, eco)
		if err != nil {
			return total, fmt.Errorf("sync %s: %w", eco, err)
		}
		total += n
	}
	return total, nil
}

func syncOSVEcosystem(db *DB, ecosystem string) (int, error) {
	// Use the OSV API to query all vulns in an ecosystem. In production this
	// would paginate through the bulk download. For now we fetch the first page
	// of results via the query endpoint for a well-known package per ecosystem.
	seeds := map[string]string{
		"npm":      "lodash",
		"PyPI":     "django",
		"Go":       "golang.org/x/net",
		"Maven":    "org.apache.logging.log4j:log4j-core",
		"crates.io": "hyper",
	}
	pkg, ok := seeds[ecosystem]
	if !ok {
		return 0, nil
	}
	vulns, err := queryOSV(ecosystem, pkg)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, v := range vulns {
		cve := osvToCVE(v, ecosystem)
		if cve.ID == "" {
			continue
		}
		if err := db.UpsertCVE(cve); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func queryOSV(ecosystem, pkg string) ([]osvVuln, error) {
	body, err := json.Marshal(osvQueryRequest{
		Package: &osvPackage{Name: pkg, Ecosystem: ecosystem},
	})
	if err != nil {
		return nil, err
	}
	resp, err := http.Post("https://api.osv.dev/v1/query", "application/json",
		strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("osv query: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("osv: %d: %s", resp.StatusCode, string(b))
	}
	var result osvQueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("osv decode: %w", err)
	}
	return result.Vulns, nil
}

func osvToCVE(v osvVuln, ecosystem string) CVEEntry {
	// Prefer CVE alias if available.
	id := v.ID
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			id = alias
			break
		}
	}
	summary := v.Summary
	if summary == "" {
		summary = v.Details
		if len(summary) > 500 {
			summary = summary[:500]
		}
	}

	var product, versionRange, fixedVersion string
	if len(v.Affected) > 0 {
		aff := v.Affected[0]
		product = aff.Package.Name
		if len(aff.Ranges) > 0 {
			var parts []string
			for _, ev := range aff.Ranges[0].Events {
				if ev.Introduced != "" {
					parts = append(parts, ">= "+ev.Introduced)
				}
				if ev.Fixed != "" {
					fixedVersion = ev.Fixed
					parts = append(parts, "< "+ev.Fixed)
				}
			}
			versionRange = strings.Join(parts, ", ")
		}
	}

	severity := classifySeverity(0) // default; we parse CVSS below
	var cvss float64
	if len(v.Severity) > 0 {
		_, _ = fmt.Sscanf(v.Severity[0].Score, "%f", &cvss)
		severity = classifySeverity(cvss)
	}

	return CVEEntry{
		ID:                id,
		Summary:           summary,
		Severity:          severity,
		CVSSScore:         cvss,
		AffectedProduct:   product,
		AffectedEcosystem: ecosystem,
		VersionRange:      versionRange,
		FixedVersion:      fixedVersion,
		Source:            "osv",
		UpdatedAt:         time.Now(),
	}
}

func classifySeverity(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "critical"
	case cvss >= 7.0:
		return "high"
	case cvss >= 4.0:
		return "medium"
	case cvss > 0:
		return "low"
	default:
		return "unknown"
	}
}
