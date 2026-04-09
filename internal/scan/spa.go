// SPA rendering utilities for scanners that need to analyze JavaScript-rendered
// pages. Uses headless Chrome (chromedp) to execute JS and return the fully
// rendered DOM. Falls back to raw HTML when Chrome is not available.
package scan

import (
	"context"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// spaIndicators are strings in the raw HTML that suggest a Single Page Application.
var spaIndicators = []string{
	// Angular
	"ng-app", "ng-controller", "ng-view", "ng-model",
	"<app-root", "app-root>",
	// React
	"data-reactroot", "data-reactid", "__REACT_DEVTOOLS",
	`id="root"></div>`, `id="root"> </div>`,
	`id="app"></div>`, `id="app"> </div>`,
	// Vue
	`id="__nuxt"`, "__vue__", "v-app", "data-v-",
	// Next.js
	"__NEXT_DATA__", "_next/static",
	// Svelte / SvelteKit
	"__sveltekit",
	// Generic SPA shells: empty body with script tags
	"<body></body>", "<body> </body>",
}

// IsSPA checks if a page is likely a Single Page Application by looking for
// framework indicators in the raw HTML. SPA pages typically have a minimal
// HTML shell with JavaScript that renders the actual content client-side.
func IsSPA(rawHTML string) bool {
	lower := strings.ToLower(rawHTML)
	for _, indicator := range spaIndicators {
		if strings.Contains(lower, strings.ToLower(indicator)) {
			return true
		}
	}

	// Heuristic: if body has very little text content but many script tags,
	// it is likely an SPA shell.
	bodyStart := strings.Index(lower, "<body")
	bodyEnd := strings.Index(lower, "</body>")
	if bodyStart >= 0 && bodyEnd > bodyStart {
		body := lower[bodyStart:bodyEnd]
		scriptCount := strings.Count(body, "<script")
		// Strip all tags to get visible text length.
		text := stripTags(body)
		text = strings.TrimSpace(text)
		if scriptCount >= 2 && len(text) < 50 {
			return true
		}
	}

	return false
}

// stripTags removes HTML tags from a string (simple heuristic, not a parser).
func stripTags(s string) string {
	var b strings.Builder
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// RenderSPA navigates to a URL in headless Chrome and returns the fully
// rendered DOM HTML after JavaScript execution.
// Falls back to the raw HTTP response body if Chrome is not available.
func RenderSPA(ctx context.Context, url string) (string, error) {
	return renderSPA(ctx, url, nil)
}

// RenderSPAWithCookies renders a page with pre-set cookies (for authenticated scanning).
// Falls back to the raw HTTP response body if Chrome is not available.
func RenderSPAWithCookies(ctx context.Context, url string, cookies []*http.Cookie) (string, error) {
	return renderSPA(ctx, url, cookies)
}

// renderSPA is the shared implementation.
func renderSPA(ctx context.Context, targetURL string, cookies []*http.Cookie) (string, error) {
	if !chromeInstalled() {
		return fetchRawHTML(ctx, targetURL, cookies)
	}

	// 10-second timeout for the render.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("ignore-certificate-errors", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	browserCtx, browserCancel := chromedp.NewContext(allocCtx)
	defer browserCancel()

	// Build the action list.
	actions := make([]chromedp.Action, 0, 6)

	// Set cookies before navigation if provided.
	if len(cookies) > 0 {
		actions = append(actions, chromedp.ActionFunc(func(actx context.Context) error {
			for _, c := range cookies {
				if err := chromedp.Run(actx, setCookie(c, targetURL)); err != nil {
					return err
				}
			}
			return nil
		}))
	}

	var rendered string
	actions = append(actions,
		chromedp.Navigate(targetURL),
		// Wait for the page to settle — JS frameworks typically render within 2s.
		chromedp.Sleep(2*time.Second),
		// Extract the fully rendered DOM.
		chromedp.Evaluate(`document.documentElement.outerHTML`, &rendered),
	)

	if err := chromedp.Run(browserCtx, actions...); err != nil {
		// Fallback to raw HTTP on Chrome error.
		html, fallbackErr := fetchRawHTML(ctx, targetURL, cookies)
		if fallbackErr != nil {
			return "", err // return original Chrome error
		}
		return html, nil
	}

	return rendered, nil
}

// setCookie builds a chromedp action that sets a single cookie via the CDP
// Network.setCookie command.
func setCookie(c *http.Cookie, targetURL string) chromedp.Action {
	return chromedp.ActionFunc(func(ctx context.Context) error {
		// Use the cookie's domain or infer from URL.
		domain := c.Domain
		if domain == "" {
			if idx := strings.Index(targetURL, "://"); idx >= 0 {
				rest := targetURL[idx+3:]
				if slashIdx := strings.IndexByte(rest, '/'); slashIdx >= 0 {
					domain = rest[:slashIdx]
				} else {
					domain = rest
				}
			}
			// Strip port for cookie domain.
			if colonIdx := strings.LastIndexByte(domain, ':'); colonIdx >= 0 {
				domain = domain[:colonIdx]
			}
		}

		return network.SetCookie(c.Name, c.Value).
			WithDomain(domain).
			WithPath("/").
			Do(ctx)
	})
}

// fetchRawHTML performs a plain HTTP GET as a fallback when Chrome is unavailable.
func fetchRawHTML(ctx context.Context, url string, cookies []*http.Cookie) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	buf := make([]byte, 256*1024)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n]), nil
}

// ChromeAvailable reports whether headless Chrome can be used for SPA rendering.
// Scanners should check this before attempting browser-based extraction.
func ChromeAvailable() bool { return chromeInstalled() }

// chromeInstalled checks if Chrome or Chromium is on the PATH.
func chromeInstalled() bool {
	candidates := []string{
		"google-chrome", "google-chrome-stable", "chromium",
		"chromium-browser",
		"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
	}
	for _, c := range candidates {
		if _, err := exec.LookPath(c); err == nil {
			return true
		}
	}
	return false
}
