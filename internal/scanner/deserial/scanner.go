// Package deserial fingerprints HTTP responses for insecure deserialization
// indicators. It looks for magic bytes and patterns associated with Java, PHP,
// and Python deserialization in HTTP responses, and tests whether endpoints
// accept and process serialized objects.
//
// Deep mode only (active POST probes with deserialization payloads).
package deserial

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/scan"
	"github.com/stormbane-security/beacon/internal/finding"
	"github.com/stormbane-security/beacon/internal/module"
	"github.com/stormbane-security/beacon/internal/scanner/schemedetect"
)


func init() {
	scan.Register(scannerName, func(_ scan.ScannerConfig) scan.Scanner {
		return New()
	})
}
const (
	scannerName = "deserial"
	maxBodySize = 64 * 1024
)

// Java serialized object magic bytes: 0xACED0005
var javaMagic = []byte{0xAC, 0xED, 0x00, 0x05}

// javaMagicB64 is a base64-encoded Java serialized object header (commonly
// sent in HTTP parameters when apps serialize to base64).
const javaMagicB64 = "rO0AB" // base64 of 0xACED0005...

// pickleMagicBytes are the opcode prefixes for Python pickle protocols 2-5.
// Protocol 2: \x80\x02, Protocol 3: \x80\x03, Protocol 4: \x80\x04, Protocol 5: \x80\x05
var pickleMagicBytes = [][]byte{
	{0x80, 0x02},
	{0x80, 0x03},
	{0x80, 0x04},
	{0x80, 0x05},
}

// pickleMagicB64 are base64-encoded prefixes for pickle protocols 2-5.
var pickleMagicB64 = []string{
	"gAI", // \x80\x02
	"gAM", // \x80\x03
	"gAQ", // \x80\x04
	"gAU", // \x80\x05
}

// phpSerializedRE matches the full PHP serialize() object notation:
//
//	O:<len>:"<classname>":<count>:{
//
// Requiring the class-name and property-count fields eliminates false positives
// from JSON responses, base64 strings, or any content that merely contains "O:\d+:".
var phpSerializedRE = regexp.MustCompile(`O:\d+:"[\w\\]+":\d+:\{`)

// probePaths are paths likely to accept or return serialized objects.
var probePaths = []string{
	"/api",
	"/api/v1",
	"/api/v2",
	"/rpc",
	"/invoke",
	"/execute",
	"/deserialize",
	"/object",
	"/session",
	"/viewstate",
}

// Scanner fingerprints for insecure deserialization vulnerabilities.
type Scanner struct{}

// New returns a new Scanner.
func New() *Scanner { return &Scanner{} }

// Name returns the stable scanner identifier.
func (s *Scanner) Name() string { return scannerName }

// Run executes the deserialization scan. Deep mode only.
func (s *Scanner) Run(ctx context.Context, asset string, scanType module.ScanType) ([]finding.Finding, error) {
	if scanType != module.ScanDeep && scanType != module.ScanAuthorized {
		return nil, nil
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	base := schemedetect.Base(ctx, client, asset)

	var findings []finding.Finding

	// Check 1: do any responses contain Java/PHP serialized object magic bytes?
	if f := scanResponsesForMagicBytes(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// Check 2: does any endpoint accept and process a Java serialized object?
	if f := probeJavaDeserialization(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// Check 3: .NET deserialization markers — __VIEWSTATE, __EVENTVALIDATION.
	if f := probeDotNetDeserialize(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// Check 4: version-aware Java gadget selection — check Server/X-Powered-By
	// for Java version and emit enriched findings when a known-vulnerable
	// version is detected alongside deserialization endpoints.
	if f := probeJavaVersionGadget(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	// Check 5: Python pickle deserialization — send a minimal pickle payload
	// and check for Python-specific error responses.
	if f := probePythonPickle(ctx, client, asset, base); f != nil {
		findings = append(findings, *f)
	}

	return findings, nil
}

// scanResponsesForMagicBytes checks GET responses for deserialization magic bytes.
func scanResponsesForMagicBytes(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	for _, path := range probePaths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()

		bodyStr := string(body)
		detected := ""
		lang := ""

		if bytes.Contains(body, javaMagic) || strings.Contains(bodyStr, javaMagicB64) {
			detected = "Java serialized object magic bytes (0xACED0005)"
			lang = "Java"
		} else if phpSerializedRE.MatchString(bodyStr) {
			detected = "PHP serialized object pattern (O:...{s:...})"
			lang = "PHP"
		} else if containsPickleMagic(body, bodyStr) {
			detected = "Python pickle magic bytes (\\x80\\x0[2-5])"
			lang = "Python"
		}

		if detected == "" {
			continue
		}

		return &finding.Finding{
			CheckID:  finding.CheckWebInsecureDeserialize,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("Serialized Object Detected in Response (%s)", lang),
			Description: fmt.Sprintf(
				"The endpoint %s%s returned data containing %s. "+
					"Applications that serialize/deserialize user-controlled objects are vulnerable to "+
					"remote code execution if an attacker can supply a crafted serialized payload.",
				base, path, detected),
			Asset:    asset,
			DeepOnly: true,
			ProofCommand: fmt.Sprintf(
				`curl -s '%s%s' | xxd | head -5`, base, path),
			Evidence: map[string]any{
				"url":      base + path,
				"detected": detected,
				"language": lang,
			},
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// probeJavaDeserialization sends a base64-encoded Java serialized header to
// common endpoints and checks whether the server returns a 500 with a Java
// exception (indicating the payload was deserialized and failed).
func probeJavaDeserialization(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	// Minimal valid Java serialized object header (no gadget chain — just header bytes).
	// A vulnerable server will try to deserialize it and throw an exception.
	javaPayload := base64.StdEncoding.EncodeToString(append(javaMagic, 0x73, 0x72, 0x00, 0x04, 0x54, 0x65, 0x73, 0x74))

	for _, path := range probePaths {
		url := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
			strings.NewReader(javaPayload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-java-serialized-object")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()

		bodyStr := string(body)
		// Java deserialization exceptions expose the stack trace or class name.
		if resp.StatusCode == http.StatusInternalServerError &&
			(strings.Contains(bodyStr, "ClassNotFoundException") ||
				strings.Contains(bodyStr, "InvalidClassException") ||
				strings.Contains(bodyStr, "java.io.") ||
				strings.Contains(bodyStr, "StreamCorruptedException")) {
			return &finding.Finding{
				CheckID:  finding.CheckWebInsecureDeserialize,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    "Java Deserialization Endpoint Detected",
				Description: fmt.Sprintf(
					"The endpoint %s returned a Java deserialization exception when sent a crafted "+
						"serialized object. This indicates the endpoint deserializes user input, making "+
						"it a candidate for remote code execution via a known gadget chain (e.g. ysoserial).",
					url),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					`# Use ysoserial to generate a payload, then:\ncurl -s -X POST '%s' -H 'Content-Type: application/x-java-serialized-object' --data-binary @payload.ser`,
					url),
				Evidence: map[string]any{
					"url":    url,
					"status": resp.StatusCode,
					"error":  firstLine(bodyStr),
				},
				DiscoveredAt: time.Now(),
			}
		}
	}
	return nil
}


// dotNetPaths are paths likely to serve ASP.NET WebForms pages containing
// ViewState fields.
var dotNetPaths = []string{
	"/",
	"/login",
	"/login.aspx",
	"/default.aspx",
	"/admin",
	"/admin/login.aspx",
	"/Account/Login",
	"/webforms/",
}

// viewStateRE matches __VIEWSTATE hidden form fields.
var viewStateRE = regexp.MustCompile(`name="__VIEWSTATE"[^>]*value="([^"]+)"`)

// eventValidationRE matches __EVENTVALIDATION hidden form fields.
var eventValidationRE = regexp.MustCompile(`name="__EVENTVALIDATION"[^>]*value="([^"]+)"`)

// probeDotNetDeserialize checks for .NET deserialization surfaces by looking
// for __VIEWSTATE and __EVENTVALIDATION hidden fields in page responses.
// Unencrypted/unsigned ViewState is a classic .NET deserialization attack vector
// (CVE-2020-0688, ysoserial.net).
func probeDotNetDeserialize(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	for _, path := range dotNetPaths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			continue
		}

		bodyStr := string(body)
		hasViewState := viewStateRE.MatchString(bodyStr)
		hasEventValidation := eventValidationRE.MatchString(bodyStr)

		if !hasViewState {
			continue
		}

		markers := "__VIEWSTATE"
		if hasEventValidation {
			markers += " + __EVENTVALIDATION"
		}

		// Check if ViewState appears to be unencrypted (base64-decodable
		// and starts with known ASP.NET ViewState magic /wE).
		vsMatch := viewStateRE.FindStringSubmatch(bodyStr)
		unencrypted := false
		if len(vsMatch) > 1 && (strings.HasPrefix(vsMatch[1], "/wE") || strings.HasPrefix(vsMatch[1], "/w")) {
			unencrypted = true
		}

		sev := finding.SeverityHigh
		desc := fmt.Sprintf(
			"The endpoint %s%s contains .NET deserialization markers (%s). "+
				"ASP.NET WebForms ViewState is a serialized object graph that, if not properly "+
				"signed and encrypted with a machine key, can be tampered with to achieve remote "+
				"code execution via known gadget chains (e.g. ysoserial.net).",
			base, path, markers)

		if unencrypted {
			sev = finding.SeverityCritical
			desc += " The ViewState value appears unencrypted (base64-decodable), increasing the risk " +
				"of successful exploitation."
		}

		return &finding.Finding{
			CheckID:  finding.CheckWebDotNetDeserialize,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: sev,
			Title:    fmt.Sprintf(".NET Deserialization Surface Detected (%s)", markers),
			Description: desc,
			Asset:    asset,
			DeepOnly: true,
			ProofCommand: fmt.Sprintf(
				`curl -s '%s%s' | grep -oE '__VIEWSTATE|__EVENTVALIDATION'`, base, path),
			Evidence: map[string]any{
				"url":              base + path,
				"markers":          markers,
				"unencrypted":      unencrypted,
				"has_viewstate":    hasViewState,
				"has_eventvalidation": hasEventValidation,
			},
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// javaVersionGadgets maps Java version patterns found in Server or X-Powered-By
// headers to known-vulnerable gadget chain families.
var javaVersionGadgets = []struct {
	pattern string // substring to match in headers
	gadget  string // recommended gadget chain
	note    string // version context
}{
	{"Java/1.7", "CommonsCollections1-5", "Java 7 — all major commons-collections gadgets available"},
	{"Java/1.8", "CommonsCollections1-7, CommonsBeansutils", "Java 8 — wide gadget surface including BeanUtils"},
	{"Java/11", "CommonsCollections5-7, JRMPClient", "Java 11 — reduced but still exploitable gadgets"},
	{"Java/17", "JRMPClient, URLDNS", "Java 17 — module system limits gadgets but JRMP/DNS still work"},
	{"Tomcat/7", "CommonsCollections3, Groovy1", "Tomcat 7 bundles vulnerable commons-collections"},
	{"Tomcat/8", "CommonsCollections3-4, Spring1", "Tomcat 8 bundles commons-collections 3.x"},
	{"Tomcat/9", "CommonsCollections6-7, Spring1-2", "Tomcat 9 — commons-collections 3.x or 4.x depending on version"},
	{"JBoss", "CommonsCollections1, MozillaRhino1, JBossInterceptors1", "JBoss/WildFly ships with extensive gadget surface"},
	{"WebLogic", "CommonsCollections1, T3/IIOP", "WebLogic — T3 protocol deserialization is a separate vector"},
	{"WebSphere", "CommonsCollections1, Jython1", "WebSphere — Jython-based gadgets available"},
}

// probeJavaVersionGadget checks Server and X-Powered-By headers for Java
// version information, and if deserialization endpoints exist, emits an
// enriched finding with version-specific gadget chain recommendations.
func probeJavaVersionGadget(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	// First, check if any deserialization endpoint exists.
	hasDeserialEndpoint := false
	for _, path := range probePaths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()

		bodyStr := string(body)
		if bytes.Contains(body, javaMagic) || strings.Contains(bodyStr, javaMagicB64) {
			hasDeserialEndpoint = true
			break
		}
	}

	// Check root page headers for Java version.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1024)) //nolint:errcheck
	resp.Body.Close()

	server := resp.Header.Get("Server")
	poweredBy := resp.Header.Get("X-Powered-By")
	combined := server + " " + poweredBy

	for _, jvg := range javaVersionGadgets {
		if !strings.Contains(combined, jvg.pattern) {
			continue
		}

		if !hasDeserialEndpoint {
			continue
		}

		return &finding.Finding{
			CheckID:  finding.CheckWebInsecureDeserialize,
			Module:   "deep",
			Scanner:  scannerName,
			Severity: finding.SeverityCritical,
			Title:    fmt.Sprintf("Java Deserialization with Version-Specific Gadgets (%s)", jvg.pattern),
			Description: fmt.Sprintf(
				"The server header reveals %s (%s). Combined with the presence of Java "+
					"serialized object endpoints, the following gadget chains are recommended "+
					"for exploitation: %s. Use ysoserial to generate payloads targeting these "+
					"gadgets.",
				jvg.pattern, jvg.note, jvg.gadget),
			Asset:    asset,
			DeepOnly: true,
			ProofCommand: fmt.Sprintf(
				"# Check server version, then use ysoserial:\n"+
					"curl -si '%s/' | grep -iE 'Server:|X-Powered-By:'\n"+
					"# java -jar ysoserial.jar %s 'id' > payload.ser",
				base, strings.SplitN(jvg.gadget, ",", 2)[0]),
			Evidence: map[string]any{
				"url":             base,
				"server_header":   server,
				"powered_by":     poweredBy,
				"java_version":   jvg.pattern,
				"gadget_chains":  jvg.gadget,
				"version_context": jvg.note,
			},
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}

// containsPickleMagic returns true if the body contains Python pickle protocol
// magic bytes (raw or base64-encoded).
func containsPickleMagic(body []byte, bodyStr string) bool {
	for _, magic := range pickleMagicBytes {
		if bytes.Contains(body, magic) {
			return true
		}
	}
	for _, prefix := range pickleMagicB64 {
		idx := 0
		for {
			pos := strings.Index(bodyStr[idx:], prefix)
			if pos < 0 {
				break
			}
			pos += idx
			end := pos + len(prefix)
			for end < len(bodyStr) && isBase64Char(bodyStr[end]) {
				end++
			}
			if end-pos >= 8 {
				if pos == 0 || bodyStr[pos-1] == '"' || bodyStr[pos-1] == ':' || bodyStr[pos-1] == ' ' || bodyStr[pos-1] == ',' || bodyStr[pos-1] == '\'' {
					return true
				}
			}
			idx = pos + 1
		}
	}
	return false
}

// pickleProbePaths are paths likely to accept Python serialized objects.
var pickleProbePaths = []string{
	"/api",
	"/api/v1",
	"/rpc",
	"/invoke",
	"/execute",
	"/session",
	"/pickle",
	"/load",
}

// probePythonPickle sends a minimal Python pickle payload to common endpoints
// and checks whether the server returns a Python-specific error indicating
// pickle deserialization was attempted.
func probePythonPickle(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	// Minimal pickle protocol 2 payload: pickle.dumps("test", protocol=2)
	// \x80\x02 = protocol 2, U\x04test = short string "test", q\x00 = put memo 0, . = STOP
	picklePayload := []byte{0x80, 0x02, 0x55, 0x04, 't', 'e', 's', 't', 0x71, 0x00, 0x2e}

	for _, path := range pickleProbePaths {
		url := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url,
			bytes.NewReader(picklePayload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-python-serialize")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()

		bodyStr := string(body)
		// Python pickle errors that indicate deserialization was attempted.
		if resp.StatusCode == http.StatusInternalServerError &&
			(strings.Contains(bodyStr, "UnpicklingError") ||
				strings.Contains(bodyStr, "pickle") ||
				strings.Contains(bodyStr, "_pickle") ||
				strings.Contains(bodyStr, "cPickle")) {
			return &finding.Finding{
				CheckID:  finding.CheckWebInsecureDeserialize,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    "Python Pickle Deserialization Endpoint Detected",
				Description: fmt.Sprintf(
					"The endpoint %s returned a Python pickle error when sent a crafted "+
						"serialized object. This indicates the endpoint deserializes user input via "+
						"pickle.loads(), making it vulnerable to arbitrary code execution. Python pickle "+
						"is inherently unsafe for untrusted data — any pickle payload can execute arbitrary "+
						"Python code during deserialization.",
					url),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					"python3 -c \"import pickle,requests; "+
						"requests.post('%s', data=pickle.dumps('test'), "+
						"headers={'Content-Type':'application/x-python-serialize'})\"",
					url),
				Evidence: map[string]any{
					"url":      url,
					"status":   resp.StatusCode,
					"error":    firstLine(bodyStr),
					"language": "Python",
				},
				DiscoveredAt: time.Now(),
			}
		}

		// Also check if the server accepts the payload successfully (200) and
		// returns something Python-shaped — this means it silently deserialized.
		if resp.StatusCode == http.StatusOK &&
			(strings.Contains(bodyStr, "test") || strings.Contains(bodyStr, "result")) {
			// Verify by checking Content-Type or Python-specific headers.
			ct := resp.Header.Get("Content-Type")
			server := resp.Header.Get("Server") + " " + resp.Header.Get("X-Powered-By")
			if strings.Contains(strings.ToLower(ct), "python") ||
				strings.Contains(server, "Python") ||
				strings.Contains(server, "gunicorn") ||
				strings.Contains(server, "uvicorn") ||
				strings.Contains(server, "Flask") ||
				strings.Contains(server, "Django") {
				return &finding.Finding{
					CheckID:  finding.CheckWebInsecureDeserialize,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityCritical,
					Title:    "Python Pickle Deserialization Accepted Silently",
					Description: fmt.Sprintf(
						"The endpoint %s accepted a Python pickle payload and returned a success "+
							"response on a Python-backed server. This strongly indicates the endpoint "+
							"deserializes user input via pickle.loads(). Python pickle is inherently unsafe — "+
							"any attacker can craft a payload that executes arbitrary code during deserialization.",
						url),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						"python3 -c \"import pickle,requests; "+
							"r=requests.post('%s', data=pickle.dumps('test'), "+
							"headers={'Content-Type':'application/x-python-serialize'}); print(r.text)\"",
						url),
					Evidence: map[string]any{
						"url":          url,
						"status":       resp.StatusCode,
						"content_type": ct,
						"server":       server,
						"language":     "Python",
					},
					DiscoveredAt: time.Now(),
				}
			}
		}
	}
	return nil
}

func isBase64Char(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
