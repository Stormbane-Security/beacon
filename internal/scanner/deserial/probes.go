package deserial

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/stormbane-security/beacon/internal/finding"
)

// phpProbePaths are paths likely to accept PHP serialized objects in parameters.
var phpProbePaths = []string{
	"/",
	"/api",
	"/api/v1",
	"/login",
	"/session",
	"/data",
	"/index.php",
	"/admin",
	"/user",
	"/profile",
}

// phpPayloads are PHP serialized objects to test for unserialize() behavior.
var phpPayloads = []string{
	`O:8:"stdClass":0:{}`,
	`a:1:{s:4:"test";s:4:"test";}`,
}

// probePHPDeserialization sends serialized PHP objects in POST parameters and
// cookies to detect whether the server deserializes them. If the response
// changes meaningfully (PHP error, different status, object-related output),
// the endpoint is vulnerable to PHP object injection.
func probePHPDeserialization(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	for _, path := range phpProbePaths {
		targetURL := base + path

		for _, payload := range phpPayloads {
			// Test 1: Send as POST form parameter.
			form := url.Values{"data": {payload}, "input": {payload}}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL,
				strings.NewReader(form.Encode()))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
			_ = resp.Body.Close()

			bodyStr := string(body)

			// Check for PHP unserialize errors or object-related output.
			if isPHPDeserResponse(resp.StatusCode, bodyStr) {
				return &finding.Finding{
					CheckID:  finding.CheckWebPHPDeserialization,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    "PHP Deserialization (unserialize) Endpoint Detected",
					Description: fmt.Sprintf(
						"The endpoint %s processed a PHP serialized object (%s) submitted as a POST "+
							"parameter and returned a PHP-specific error or changed behavior. This indicates "+
							"the server calls unserialize() on user input, enabling PHP object injection — "+
							"an attacker can craft serialized objects that trigger magic methods (__wakeup, "+
							"__destruct) to achieve remote code execution via POP chains.",
						targetURL, payload),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						`curl -s -X POST '%s' -d 'data=%s'`,
						targetURL, url.QueryEscape(payload)),
					Evidence: map[string]any{
						"url":     targetURL,
						"payload": payload,
						"method":  "POST parameter",
						"status":  resp.StatusCode,
						"error":   firstLine(bodyStr),
					},
					DiscoveredAt: time.Now(),
				}
			}

			// Test 2: Send as cookie value.
			req2, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
			if err != nil {
				continue
			}
			// URL-encode to avoid Go's net/http cookie validation log spam
			// for characters like " in PHP serialized objects.
			encoded := url.QueryEscape(payload)
			req2.AddCookie(&http.Cookie{Name: "session", Value: encoded})
			req2.AddCookie(&http.Cookie{Name: "data", Value: encoded})

			resp2, err := client.Do(req2)
			if err != nil {
				continue
			}
			body2, _ := io.ReadAll(io.LimitReader(resp2.Body, maxBodySize))
			_ = resp2.Body.Close()

			bodyStr2 := string(body2)
			if isPHPDeserResponse(resp2.StatusCode, bodyStr2) {
				return &finding.Finding{
					CheckID:  finding.CheckWebPHPDeserialization,
					Module:   "deep",
					Scanner:  scannerName,
					Severity: finding.SeverityHigh,
					Title:    "PHP Deserialization via Cookie Detected",
					Description: fmt.Sprintf(
						"The endpoint %s processed a PHP serialized object submitted in a cookie "+
							"and returned a PHP-specific error. This indicates the server deserializes "+
							"cookie values via unserialize(), enabling PHP object injection attacks.",
						targetURL),
					Asset:    asset,
					DeepOnly: true,
					ProofCommand: fmt.Sprintf(
						`curl -s '%s' -b 'session=%s'`,
						targetURL, url.QueryEscape(payload)),
					Evidence: map[string]any{
						"url":     targetURL,
						"payload": payload,
						"method":  "cookie",
						"status":  resp2.StatusCode,
						"error":   firstLine(bodyStr2),
					},
					DiscoveredAt: time.Now(),
				}
			}
		}
	}
	return nil
}

// isPHPDeserResponse returns true if the response indicates PHP processed a
// serialized object — either via error messages or recognizable PHP output.
func isPHPDeserResponse(statusCode int, body string) bool {
	lower := strings.ToLower(body)

	// PHP unserialize errors.
	if strings.Contains(lower, "unserialize()") ||
		strings.Contains(lower, "unserialize():") {
		return true
	}

	// PHP object-related errors.
	if strings.Contains(body, "__PHP_Incomplete_Class") ||
		strings.Contains(body, "__wakeup") ||
		strings.Contains(body, "__destruct") {
		return true
	}

	// PHP fatal/warning with class references triggered by deserialization.
	if statusCode == http.StatusInternalServerError &&
		(strings.Contains(lower, "fatal error") || strings.Contains(lower, "php warning")) &&
		(strings.Contains(lower, "class") || strings.Contains(lower, "object")) {
		return true
	}

	return false
}

// probeJavaDeserializationSpecific checks for Java deserialization indicators
// by looking for JSESSIONID cookies combined with endpoints that accept binary
// content types. This emits the language-specific web.java_deserialization
// check ID (separate from the generic web.insecure_deserialize).
func probeJavaDeserializationSpecific(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
	// First check if the server uses JSESSIONID (indicates Java backend).
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/", nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	_ = resp.Body.Close()

	hasJSessionID := false
	for _, c := range resp.Cookies() {
		if strings.ToUpper(c.Name) == "JSESSIONID" {
			hasJSessionID = true
			break
		}
	}

	if !hasJSessionID {
		return nil
	}

	// Probe endpoints with Java serialized object content type.
	javaPayload := append(javaMagic, 0x73, 0x72, 0x00, 0x04, 0x54, 0x65, 0x73, 0x74)

	for _, path := range probePaths {
		targetURL := base + path
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL,
			bytes.NewReader(javaPayload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-java-serialized-object")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		_ = resp.Body.Close()

		bodyStr := string(body)
		// Java deserialization exceptions indicate the payload was processed.
		if resp.StatusCode == http.StatusInternalServerError &&
			(strings.Contains(bodyStr, "ClassNotFoundException") ||
				strings.Contains(bodyStr, "InvalidClassException") ||
				strings.Contains(bodyStr, "java.io.") ||
				strings.Contains(bodyStr, "StreamCorruptedException") ||
				strings.Contains(bodyStr, "ObjectInputStream")) {
			return &finding.Finding{
				CheckID:  finding.CheckWebJavaDeserialization,
				Module:   "deep",
				Scanner:  scannerName,
				Severity: finding.SeverityCritical,
				Title:    "Java Deserialization with JSESSIONID Detected",
				Description: fmt.Sprintf(
					"The server at %s uses JSESSIONID cookies (Java backend) and the endpoint %s "+
						"returned a Java deserialization exception when sent a crafted serialized object "+
						"with Content-Type: application/x-java-serialized-object. This confirms the "+
						"endpoint deserializes untrusted input — an attacker can achieve remote code "+
						"execution using ysoserial gadget chains.",
					base, targetURL),
				Asset:    asset,
				DeepOnly: true,
				ProofCommand: fmt.Sprintf(
					"curl -si '%s' -X POST -H 'Content-Type: application/x-java-serialized-object' --data-binary @payload.ser",
					targetURL),
				Evidence: map[string]any{
					"url":          targetURL,
					"jsessionid":   true,
					"status":       resp.StatusCode,
					"error":        firstLine(bodyStr),
					"content_type": "application/x-java-serialized-object",
				},
				DiscoveredAt: time.Now(),
			}
		}
	}

	return nil
}

// probeViewstateUnprotected checks for .NET ViewState fields that lack MAC
// protection. This is a surface-safe check (GET only) that looks for
// ViewState values that are base64-decodable but not signed, which means
// an attacker can tamper with them to inject serialized .NET objects.
func probeViewstateUnprotected(ctx context.Context, client *http.Client, asset, base string) *finding.Finding {
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
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusNotFound {
			continue
		}

		bodyStr := string(body)
		vsMatch := viewStateRE.FindStringSubmatch(bodyStr)
		if len(vsMatch) < 2 {
			continue
		}

		vsValue := vsMatch[1]
		// Unencrypted ViewState starts with /wE (base64 for the ASP.NET
		// serialization header). If present without __EVENTVALIDATION or
		// without ViewStateUserKey, the ViewState is tamperable.
		if !strings.HasPrefix(vsValue, "/wE") && !strings.HasPrefix(vsValue, "/w") {
			continue
		}

		// Check if __EVENTVALIDATION is absent — without it, there's no
		// secondary integrity check on the ViewState.
		hasEventValidation := eventValidationRE.MatchString(bodyStr)

		// Check for ViewStateEncryptionMode or ViewStateUserKey in the page
		// which would indicate the ViewState has additional protection.
		hasEncryptionHint := strings.Contains(bodyStr, "ViewStateEncryptionMode") ||
			strings.Contains(bodyStr, "ViewStateUserKey")

		if hasEncryptionHint {
			continue
		}

		desc := fmt.Sprintf(
			"The endpoint %s%s contains an ASP.NET __VIEWSTATE field with an unencrypted "+
				"value (base64-decodable, starts with /wE). Without ViewState MAC validation, "+
				"an attacker can deserialize arbitrary .NET objects by tampering with the "+
				"ViewState parameter, potentially achieving remote code execution via "+
				"ysoserial.net gadget chains (e.g. CVE-2020-0688).",
			base, path)

		if !hasEventValidation {
			desc += " No __EVENTVALIDATION field was found, removing another layer of protection."
		}

		return &finding.Finding{
			CheckID:  finding.CheckWebViewstateUnprotected,
			Module:   "surface",
			Scanner:  scannerName,
			Severity: finding.SeverityHigh,
			Title:    fmt.Sprintf("Unprotected .NET ViewState at %s%s", base, path),
			Description: desc,
			Asset:    asset,
			ProofCommand: fmt.Sprintf(
				`curl -s '%s%s' | grep -oP 'name="__VIEWSTATE"[^>]*value="[^"]*"'`,
				base, path),
			Evidence: map[string]any{
				"url":                 base + path,
				"viewstate_prefix":    vsValue[:min(len(vsValue), 20)],
				"unencrypted":         true,
				"has_eventvalidation": hasEventValidation,
			},
			DiscoveredAt: time.Now(),
		}
	}
	return nil
}
