// beacon-crawler is a standalone JS-rendering crawler that discovers endpoints
// in single-page applications by driving headless Chrome via chromedp.
//
// Usage:
//
//	beacon-crawler --url https://example.com --output /tmp/endpoints.json --timeout 30s --max-pages 50
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
)

// ---------- output types ----------

// CrawlResult is the top-level JSON output.
type CrawlResult struct {
	StartURL   string     `json:"start_url"`
	Timestamp  string     `json:"timestamp"`
	PagesCount int        `json:"pages_count"`
	Pages      []PageInfo `json:"pages"`
}

// PageInfo holds everything extracted from a single rendered page.
type PageInfo struct {
	URL        string      `json:"url"`
	Title      string      `json:"title"`
	Links      []string    `json:"links,omitempty"`
	Forms      []FormInfo  `json:"forms,omitempty"`
	Inputs     []InputInfo `json:"inputs,omitempty"`
	APIHints   []string    `json:"api_hints,omitempty"`
	ScriptURLs []string    `json:"script_urls,omitempty"`
}

// FormInfo describes an HTML <form>.
type FormInfo struct {
	Action string      `json:"action"`
	Method string      `json:"method"`
	Fields []InputInfo `json:"fields,omitempty"`
}

// InputInfo describes an <input>, <textarea>, or <select> element.
type InputInfo struct {
	Tag   string `json:"tag"`
	Type  string `json:"type,omitempty"`
	Name  string `json:"name,omitempty"`
	ID    string `json:"id,omitempty"`
	Value string `json:"value,omitempty"`
}

// ---------- CLI flags ----------

func main() {
	startURL := flag.String("url", "", "URL to start crawling (required)")
	output := flag.String("output", "", "Output file path for JSON results (required)")
	timeout := flag.Duration("timeout", 30*time.Second, "Overall crawl timeout")
	maxPages := flag.Int("max-pages", 50, "Maximum number of pages to visit")
	flag.Parse()

	if *startURL == "" || *output == "" {
		flag.Usage()
		os.Exit(1)
	}

	parsed, err := url.Parse(*startURL)
	if err != nil {
		log.Fatalf("invalid start URL: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	result, err := crawl(ctx, parsed, *maxPages)
	if err != nil {
		log.Fatalf("crawl failed: %v", err)
	}

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("json marshal: %v", err)
	}

	if err := os.WriteFile(*output, data, 0o644); err != nil {
		log.Fatalf("write output: %v", err)
	}

	fmt.Fprintf(os.Stderr, "beacon-crawler: wrote %d pages to %s\n", result.PagesCount, *output)
}

// ---------- crawler ----------

func crawl(ctx context.Context, startURL *url.URL, maxPages int) (*CrawlResult, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("ignore-certificate-errors", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	browserCtx, browserCancel := chromedp.NewContext(allocCtx,
		chromedp.WithLogf(log.Printf),
	)
	defer browserCancel()

	// Keep track of visited URLs.
	var mu sync.Mutex
	visited := make(map[string]bool)
	var pages []PageInfo

	queue := []string{startURL.String()}
	visited[normalizeURL(startURL.String())] = true

	for len(queue) > 0 && len(pages) < maxPages {
		if ctx.Err() != nil {
			break
		}

		current := queue[0]
		queue = queue[1:]

		fmt.Fprintf(os.Stderr, "beacon-crawler: visiting %s (%d/%d)\n", current, len(pages)+1, maxPages)

		page, err := visitPage(browserCtx, current)
		if err != nil {
			fmt.Fprintf(os.Stderr, "beacon-crawler: error visiting %s: %v\n", current, err)
			continue
		}

		mu.Lock()
		pages = append(pages, *page)

		// Enqueue discovered same-origin links.
		for _, link := range page.Links {
			norm := normalizeURL(link)
			if visited[norm] {
				continue
			}
			parsed, err := url.Parse(link)
			if err != nil || !isSameOrigin(startURL, parsed) {
				continue
			}
			visited[norm] = true
			queue = append(queue, link)
		}
		mu.Unlock()
	}

	return &CrawlResult{
		StartURL:   startURL.String(),
		Timestamp:  time.Now().UTC().Format(time.RFC3339),
		PagesCount: len(pages),
		Pages:      pages,
	}, nil
}

func visitPage(ctx context.Context, pageURL string) (*PageInfo, error) {
	tabCtx, tabCancel := chromedp.NewContext(ctx)
	defer tabCancel()

	// Per-page timeout.
	tabCtx, pageCancel := context.WithTimeout(tabCtx, 15*time.Second)
	defer pageCancel()

	var title string

	// Navigate and wait for network to go idle.
	if err := chromedp.Run(tabCtx,
		chromedp.Navigate(pageURL),
		chromedp.WaitReady("body"),
		chromedp.Sleep(500*time.Millisecond), // let async JS settle
		chromedp.Title(&title),
	); err != nil {
		return nil, fmt.Errorf("navigate: %w", err)
	}

	// Extract everything from the rendered DOM via JS.
	var extractedJSON string
	if err := chromedp.Run(tabCtx,
		chromedp.Evaluate(extractionJS, &extractedJSON),
	); err != nil {
		return nil, fmt.Errorf("extract: %w", err)
	}

	var extracted extractedData
	if err := json.Unmarshal([]byte(extractedJSON), &extracted); err != nil {
		return nil, fmt.Errorf("unmarshal extracted: %w", err)
	}

	return &PageInfo{
		URL:        pageURL,
		Title:      title,
		Links:      extracted.Links,
		Forms:      extracted.Forms,
		Inputs:     extracted.Inputs,
		APIHints:   extracted.APIHints,
		ScriptURLs: extracted.ScriptURLs,
	}, nil
}

type extractedData struct {
	Links      []string    `json:"links"`
	Forms      []FormInfo  `json:"forms"`
	Inputs     []InputInfo `json:"inputs"`
	APIHints   []string    `json:"api_hints"`
	ScriptURLs []string    `json:"script_urls"`
}

// extractionJS runs in the browser context and pulls data from the rendered DOM.
const extractionJS = `
(function() {
	var result = { links: [], forms: [], inputs: [], api_hints: [], script_urls: [] };

	// --- Links ---
	var anchors = document.querySelectorAll('a[href]');
	var linkSet = {};
	anchors.forEach(function(a) {
		var href = a.href;
		if (href && href.indexOf('javascript:') !== 0 && href.indexOf('#') !== 0 && !linkSet[href]) {
			linkSet[href] = true;
			result.links.push(href);
		}
	});

	// --- Forms ---
	var forms = document.querySelectorAll('form');
	forms.forEach(function(f) {
		var fields = [];
		f.querySelectorAll('input, textarea, select').forEach(function(el) {
			fields.push({
				tag:   el.tagName.toLowerCase(),
				type:  el.type || '',
				name:  el.name || '',
				id:    el.id || '',
				value: el.value || ''
			});
		});
		result.forms.push({
			action: f.action || '',
			method: (f.method || 'GET').toUpperCase(),
			fields: fields
		});
	});

	// --- Standalone inputs (outside forms) ---
	document.querySelectorAll('input:not(form input), textarea:not(form textarea), select:not(form select)').forEach(function(el) {
		result.inputs.push({
			tag:   el.tagName.toLowerCase(),
			type:  el.type || '',
			name:  el.name || '',
			id:    el.id || '',
			value: el.value || ''
		});
	});

	// --- API endpoint hints from JS ---
	// Look for fetch/XHR patterns in inline scripts and rendered content.
	var apiPattern = /(?:fetch|axios|XMLHttpRequest|\.ajax|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*['"\x60](\/[^'"\x60\s]{2,})['"\x60]/g;
	var scripts = document.querySelectorAll('script:not([src])');
	var apiSet = {};
	scripts.forEach(function(s) {
		var m;
		var text = s.textContent || '';
		while ((m = apiPattern.exec(text)) !== null) {
			if (!apiSet[m[1]]) {
				apiSet[m[1]] = true;
				result.api_hints.push(m[1]);
			}
		}
	});

	// Also look for URL-like strings in data attributes.
	document.querySelectorAll('[data-url], [data-api], [data-endpoint], [data-href], [data-src]').forEach(function(el) {
		['data-url','data-api','data-endpoint','data-href','data-src'].forEach(function(attr) {
			var v = el.getAttribute(attr);
			if (v && v.length > 1 && !apiSet[v]) {
				apiSet[v] = true;
				result.api_hints.push(v);
			}
		});
	});

	// --- Script URLs ---
	document.querySelectorAll('script[src]').forEach(function(s) {
		result.script_urls.push(s.src);
	});

	return JSON.stringify(result);
})()
`

// ---------- helpers ----------

func normalizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Fragment = ""
	u.RawQuery = "" // normalize for dedup; query params ignored in queue
	return strings.TrimRight(u.String(), "/")
}

func isSameOrigin(base, candidate *url.URL) bool {
	return candidate.Scheme == base.Scheme && candidate.Host == base.Host
}
