// Package toolinstall provides automatic installation of external tool binaries
// required by Beacon scanners. Go-based tools are installed via `go install`.
// testssl.sh is downloaded from GitHub. Called lazily at first scanner use.
package toolinstall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// goTools maps binary names to their `go install` package paths.
var goTools = map[string]string{
	"nuclei":     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
	"subfinder":  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
	"amass":      "github.com/owasp-amass/amass/v4/...@master",
	"gau":        "github.com/lc/gau/v2/cmd/gau@latest",
	"katana":     "github.com/projectdiscovery/katana/cmd/katana@latest",
	"gowitness":  "github.com/sensepost/gowitness@latest",
}

// pythonTools maps binary names to their pip package names.
// Note: the PyPI "theHarvester" package (v0.0.1) is a stub — theHarvester must
// be installed via brew (macOS) or apt (Debian/Ubuntu). We keep the entry so
// EnsurePython can provide a clear error message with the correct instructions.
var pythonTools = map[string]string{
	"theHarvester": "theHarvester",
}

// Ensure checks whether bin is on PATH and installs it if not.
// For Go-based tools the binary name must be a key in goTools.
// Returns the resolved binary path, or an error if installation failed.
func Ensure(bin string) (string, error) {
	// Already on PATH?
	if path, err := exec.LookPath(bin); err == nil {
		return path, nil
	}

	// Check GOPATH/bin directly (go install puts binaries there)
	gobin := gobinPath(bin)
	if _, err := os.Stat(gobin); err == nil {
		return gobin, nil
	}

	pkg, ok := goTools[bin]
	if !ok {
		return "", fmt.Errorf("unknown tool %q — add it to toolinstall.goTools or install manually", bin)
	}

	fmt.Fprintf(os.Stderr, "beacon: installing %s via go install...\n", bin)
	cmd := exec.Command("go", "install", "-v", pkg)
	cmd.Stdout = os.Stderr // show progress
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go install %s: %w", pkg, err)
	}

	// Re-check after install
	if path, err := exec.LookPath(bin); err == nil {
		return path, nil
	}
	if _, err := os.Stat(gobin); err == nil {
		return gobin, nil
	}

	return "", fmt.Errorf("%s installed but not found on PATH — add %s to your PATH", bin, filepath.Dir(gobin))
}

// EnsureTestssl checks for testssl.sh and downloads it from GitHub if missing.
// testssl.sh is a bash script so no compilation is needed.
func EnsureTestssl(bin string) (string, error) {
	if bin == "" {
		bin = "testssl.sh"
	}

	if path, err := exec.LookPath(bin); err == nil {
		return path, nil
	}

	// testssl.sh is not a Go tool — download the script directly
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("testssl.sh is not supported on Windows — deep TLS scan skipped")
	}

	dest := filepath.Join(os.TempDir(), "testssl.sh")
	if _, err := os.Stat(dest); err == nil {
		// Already downloaded to temp
		return dest, nil
	}

	fmt.Fprintf(os.Stderr, "beacon: downloading testssl.sh...\n")
	cmd := exec.Command("curl", "-fsSL",
		"https://raw.githubusercontent.com/drwetter/testssl.sh/3.2/testssl.sh",
		"-o", dest,
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("download testssl.sh: %w", err)
	}
	if err := os.Chmod(dest, 0o755); err != nil {
		return "", err
	}
	return dest, nil
}

// EnsurePython checks whether a Python-based tool binary is available and
// attempts to install it via the appropriate package manager. Returns the
// resolved path or an error that callers should treat as a non-fatal warning.
func EnsurePython(bin string) (string, error) {
	// Already on PATH?
	if path, err := exec.LookPath(bin); err == nil {
		return path, nil
	}

	// Check common user-local binary directories that are often missing from PATH.
	if path := findInUserBinDirs(bin); path != "" {
		return path, nil
	}

	if _, ok := pythonTools[bin]; !ok {
		return "", fmt.Errorf("unknown Python tool %q — install manually", bin)
	}

	// theHarvester: the PyPI package is a stub (v0.0.1) — use brew on macOS,
	// apt on Debian/Ubuntu, or clone from GitHub.
	if bin == "theHarvester" {
		return ensureTheHarvester()
	}

	return "", fmt.Errorf(
		"%s not found. Install manually:\n"+
			"  macOS:          brew install %s\n"+
			"  Debian/Ubuntu:  sudo apt install %s",
		bin, strings.ToLower(bin), strings.ToLower(bin),
	)
}

// ensureTheHarvester tries to install theHarvester via brew (macOS) or provides
// clear instructions for other platforms. The PyPI package is a stub and is not used.
func ensureTheHarvester() (string, error) {
	const bin = "theHarvester"

	// macOS: try brew
	if runtime.GOOS == "darwin" {
		if brewPath, err := exec.LookPath("brew"); err == nil {
			fmt.Fprintf(os.Stderr, "beacon: installing theHarvester via brew...\n")
			cmd := exec.Command(brewPath, "install", "theharvester")
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err == nil {
				if path, err := exec.LookPath(bin); err == nil {
					return path, nil
				}
				if path := findInUserBinDirs(bin); path != "" {
					return path, nil
				}
			}
		}
		return "", fmt.Errorf(
			"theHarvester not found. Install with:\n" +
				"  brew install theharvester",
		)
	}

	// Linux: try apt-get
	if runtime.GOOS == "linux" {
		if aptPath, err := exec.LookPath("apt-get"); err == nil {
			fmt.Fprintf(os.Stderr, "beacon: installing theharvester via apt-get...\n")
			cmd := exec.Command(aptPath, "install", "-y", "theharvester")
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
			if err := cmd.Run(); err == nil {
				if path, err := exec.LookPath(bin); err == nil {
					return path, nil
				}
			}
		}
	}

	return "", fmt.Errorf(
		"theHarvester not found. Install instructions:\n" +
			"  macOS:          brew install theharvester\n" +
			"  Debian/Ubuntu:  sudo apt install theharvester\n" +
			"  Other:          https://github.com/laramies/theHarvester",
	)
}

// findInUserBinDirs checks common user-local binary directories that are
// frequently absent from PATH (e.g. macOS pip --user installs, Linux ~/.local/bin).
func findInUserBinDirs(bin string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	var candidates []string

	// Linux pip --user
	candidates = append(candidates, filepath.Join(home, ".local", "bin", bin))

	// macOS pip --user: ~/Library/Python/<version>/bin/
	if runtime.GOOS == "darwin" {
		pattern := filepath.Join(home, "Library", "Python", "*", "bin", bin)
		if matches, err := filepath.Glob(pattern); err == nil {
			candidates = append(candidates, matches...)
		}
	}

	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// ToolStatus reports the result of ensuring a single tool.
type ToolStatus struct {
	Name    string
	Path    string
	Err     error
	Skipped bool // true when the tool is not available on this platform
}

// EnsureAll checks and installs every tool beacon depends on.
// Results are returned in a stable order: Go tools, Python tools, then testssl.
// Errors are non-fatal — callers should report them as warnings.
func EnsureAll() []ToolStatus {
	var results []ToolStatus

	// Go-based tools (deterministic order)
	goOrder := []string{"nuclei", "subfinder", "amass", "gau", "katana", "gowitness"}
	for _, bin := range goOrder {
		path, err := Ensure(bin)
		results = append(results, ToolStatus{Name: bin, Path: path, Err: err})
	}

	// Python-based tools
	for bin := range pythonTools {
		path, err := EnsurePython(bin)
		results = append(results, ToolStatus{Name: bin, Path: path, Err: err})
	}

	// testssl.sh
	if runtime.GOOS != "windows" {
		path, err := EnsureTestssl("")
		results = append(results, ToolStatus{Name: "testssl.sh", Path: path, Err: err})
	} else {
		results = append(results, ToolStatus{Name: "testssl.sh", Skipped: true})
	}

	return results
}

// gobinPath returns the expected location of a binary installed by `go install`.
func gobinPath(bin string) string {
	// Respect GOBIN if set
	if gobin := os.Getenv("GOBIN"); gobin != "" {
		return filepath.Join(gobin, bin)
	}
	// Fall back to GOPATH/bin
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, _ := os.UserHomeDir()
		gopath = filepath.Join(home, "go")
	}
	return filepath.Join(gopath, "bin", bin)
}
