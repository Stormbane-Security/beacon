package report

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"

	"github.com/stormbane-security/beacon/internal/enrichment"
	"github.com/stormbane-security/beacon/internal/store"
)

// RenderPDF generates a PDF report by rendering the enhanced Markdown report
// to HTML and printing it to PDF via headless Chrome (chromedp).
//
// If Chrome is not available, the function writes the Markdown report to a
// .md file next to outPath and returns an error explaining that PDF generation
// requires Chrome.
func RenderPDF(run store.ScanRun, enriched []enrichment.EnrichedFinding, summary string, executions []store.AssetExecution, screenshotDir string, outPath string) error {
	md := RenderEnhancedMarkdown(run, enriched, summary, executions, screenshotDir)

	// Convert markdown to a self-contained HTML document suitable for
	// Chrome's print-to-PDF. We use a simple but functional conversion
	// since we control the markdown output format.
	html := markdownToHTML(md, run.Domain)

	if !ChromeAvailable() {
		// Fall back: write the markdown file and explain.
		mdPath := strings.TrimSuffix(outPath, filepath.Ext(outPath)) + ".md"
		if err := os.WriteFile(mdPath, []byte(md), 0o600); err != nil {
			return fmt.Errorf("write markdown fallback: %w", err)
		}
		return fmt.Errorf("PDF generation requires Chrome/Chromium; markdown report written to %s", mdPath)
	}

	// Write HTML to a temp file so Chrome can load it with file:// URL,
	// which allows relative screenshot paths to resolve.
	tmpDir, err := os.MkdirTemp("", "beacon-pdf-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	htmlPath := filepath.Join(tmpDir, "report.html")
	if err := os.WriteFile(htmlPath, []byte(html), 0o644); err != nil {
		return fmt.Errorf("write temp HTML: %w", err)
	}

	// If screenshots exist, symlink the directory so relative paths work.
	if screenshotDir != "" {
		absScreenshots, _ := filepath.Abs(screenshotDir)
		if absScreenshots != "" {
			_ = os.Symlink(absScreenshots, filepath.Join(tmpDir, "screenshots"))
		}
	}

	// Print to PDF via headless Chrome.
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("allow-file-access-from-files", true),
	)
	allocCtx, allocCancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer allocCancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	pdfCtx, pdfCancel := context.WithTimeout(ctx, 60*time.Second)
	defer pdfCancel()

	fileURL := "file://" + htmlPath

	var pdfBuf []byte
	if err := chromedp.Run(pdfCtx,
		chromedp.Navigate(fileURL),
		chromedp.Sleep(2*time.Second),
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			pdfBuf, _, err = page.PrintToPDF().
				WithPrintBackground(true).
				WithPreferCSSPageSize(true).
				WithMarginTop(0.4).
				WithMarginBottom(0.4).
				WithMarginLeft(0.4).
				WithMarginRight(0.4).
				Do(ctx)
			return err
		}),
	); err != nil {
		return fmt.Errorf("print to PDF: %w", err)
	}

	if err := os.WriteFile(outPath, pdfBuf, 0o600); err != nil {
		return fmt.Errorf("write PDF: %w", err)
	}

	return nil
}

// markdownToHTML converts our structured markdown report into a styled HTML
// page suitable for PDF printing. This is a purpose-built converter (not a
// full markdown parser) that handles the specific constructs we emit.
func markdownToHTML(md string, domain string) string {
	var b strings.Builder

	b.WriteString(`<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Beacon Security Report`)
	if domain != "" {
		b.WriteString(" — ")
		b.WriteString(domain)
	}
	b.WriteString(`</title>
<style>
  @page { size: A4; margin: 1cm; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 11pt;
    line-height: 1.5;
    color: #1a1a2e;
    max-width: 210mm;
    margin: 0 auto;
    padding: 1em;
  }
  h1 { font-size: 20pt; border-bottom: 2px solid #e94560; padding-bottom: 0.3em; margin-top: 1.5em; }
  h2 { font-size: 16pt; border-bottom: 1px solid #ccc; padding-bottom: 0.2em; margin-top: 1.5em; }
  h3 { font-size: 13pt; margin-top: 1.2em; }
  table { border-collapse: collapse; width: 100%; margin: 0.5em 0; page-break-inside: avoid; }
  th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; font-size: 10pt; }
  th { background: #f0f0f5; font-weight: 600; }
  tr:nth-child(even) { background: #fafafa; }
  code { background: #f4f4f8; padding: 2px 5px; border-radius: 3px; font-size: 10pt; }
  pre { background: #1a1a2e; color: #e0e0e0; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 9pt; }
  pre code { background: transparent; padding: 0; color: inherit; }
  hr { border: none; border-top: 1px solid #ddd; margin: 1.5em 0; }
  img { max-width: 100%; border: 1px solid #ddd; border-radius: 4px; margin: 0.5em 0; }
  .badge-critical { color: #fff; background: #dc3545; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 9pt; }
  .badge-high { color: #fff; background: #fd7e14; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 9pt; }
  .badge-medium { color: #000; background: #ffc107; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 9pt; }
  .badge-low { color: #fff; background: #0d6efd; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 9pt; }
  .badge-info { color: #666; background: #e9ecef; padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 9pt; }
  .finding { page-break-inside: avoid; margin-bottom: 1.5em; }
  .toc a { color: #0d6efd; text-decoration: none; }
  .toc a:hover { text-decoration: underline; }
  .toc ul { list-style: none; padding-left: 1em; }
  .toc li { margin: 0.2em 0; }
</style>
</head>
<body>
`)

	// Simple line-by-line markdown to HTML conversion.
	lines := strings.Split(md, "\n")
	inCodeBlock := false
	inTable := false
	tableHeaderDone := false

	for i := 0; i < len(lines); i++ {
		line := lines[i]

		// Code blocks
		if strings.HasPrefix(line, "```") {
			if inCodeBlock {
				b.WriteString("</code></pre>\n")
				inCodeBlock = false
			} else {
				b.WriteString("<pre><code>")
				inCodeBlock = true
			}
			continue
		}
		if inCodeBlock {
			b.WriteString(escapeHTML(line))
			b.WriteString("\n")
			continue
		}

		// Close table if we leave table context.
		if inTable && !strings.HasPrefix(line, "|") {
			b.WriteString("</tbody></table>\n")
			inTable = false
			tableHeaderDone = false
		}

		// Tables
		if strings.HasPrefix(line, "|") {
			cells := parseTableRow(line)
			if len(cells) == 0 {
				continue
			}
			// Detect separator row (|---|---|)
			isSep := true
			for _, c := range cells {
				trimmed := strings.TrimSpace(c)
				trimmed = strings.Trim(trimmed, "-: ")
				if trimmed != "" {
					isSep = false
					break
				}
			}
			if isSep {
				tableHeaderDone = true
				continue
			}
			if !inTable {
				b.WriteString("<table>\n<thead><tr>")
				for _, c := range cells {
					b.WriteString("<th>")
					b.WriteString(inlineMarkdown(strings.TrimSpace(c)))
					b.WriteString("</th>")
				}
				b.WriteString("</tr></thead>\n<tbody>\n")
				inTable = true
				continue
			}
			if tableHeaderDone {
				b.WriteString("<tr>")
				for _, c := range cells {
					b.WriteString("<td>")
					b.WriteString(inlineMarkdown(strings.TrimSpace(c)))
					b.WriteString("</td>")
				}
				b.WriteString("</tr>\n")
			}
			continue
		}

		trimmed := strings.TrimSpace(line)

		// Horizontal rules
		if trimmed == "---" || trimmed == "***" || trimmed == "___" {
			b.WriteString("<hr>\n")
			continue
		}

		// Headings
		if strings.HasPrefix(line, "# ") {
			b.WriteString("<h1>")
			b.WriteString(inlineMarkdown(line[2:]))
			b.WriteString("</h1>\n")
			continue
		}
		if strings.HasPrefix(line, "## ") {
			id := slugify(line[3:])
			fmt.Fprintf(&b, `<h2 id="%s">`, id)
			b.WriteString(inlineMarkdown(line[3:]))
			b.WriteString("</h2>\n")
			continue
		}
		if strings.HasPrefix(line, "### ") {
			id := slugify(line[4:])
			fmt.Fprintf(&b, `<h3 id="%s">`, id)
			b.WriteString(inlineMarkdown(line[4:]))
			b.WriteString("</h3>\n")
			continue
		}

		// Empty lines
		if trimmed == "" {
			continue
		}

		// Regular paragraphs
		b.WriteString("<p>")
		b.WriteString(inlineMarkdown(line))
		b.WriteString("</p>\n")
	}

	if inTable {
		b.WriteString("</tbody></table>\n")
	}
	if inCodeBlock {
		b.WriteString("</code></pre>\n")
	}

	b.WriteString("</body>\n</html>\n")
	return b.String()
}

// inlineMarkdown handles bold, code, images, and links within a line.
func inlineMarkdown(s string) string {
	// Images: ![alt](src)
	for {
		start := strings.Index(s, "![")
		if start == -1 {
			break
		}
		altEnd := strings.Index(s[start:], "](")
		if altEnd == -1 {
			break
		}
		altEnd += start
		srcEnd := strings.Index(s[altEnd+2:], ")")
		if srcEnd == -1 {
			break
		}
		srcEnd += altEnd + 2
		alt := s[start+2 : altEnd]
		src := s[altEnd+2 : srcEnd]
		img := fmt.Sprintf(`<img src="%s" alt="%s">`, escapeHTML(src), escapeHTML(alt))
		s = s[:start] + img + s[srcEnd+1:]
	}

	// Bold: **text**
	for {
		start := strings.Index(s, "**")
		if start == -1 {
			break
		}
		end := strings.Index(s[start+2:], "**")
		if end == -1 {
			break
		}
		end += start + 2
		inner := s[start+2 : end]
		s = s[:start] + "<strong>" + inner + "</strong>" + s[end+2:]
	}

	// Inline code: `text`
	for {
		start := strings.Index(s, "`")
		if start == -1 {
			break
		}
		end := strings.Index(s[start+1:], "`")
		if end == -1 {
			break
		}
		end += start + 1
		inner := s[start+1 : end]
		s = s[:start] + "<code>" + escapeHTML(inner) + "</code>" + s[end+1:]
	}

	// Severity badge spans (emoji-based from our markdown).
	badges := map[string]string{
		"\U0001f534": "badge-critical",
		"\U0001f7e0": "badge-high",
		"\U0001f7e1": "badge-medium",
		"\U0001f535": "badge-low",
		"\u26aa":     "badge-info",
	}
	for emoji, class := range badges {
		if strings.Contains(s, emoji) {
			label := ""
			switch class {
			case "badge-critical":
				label = "CRITICAL"
			case "badge-high":
				label = "HIGH"
			case "badge-medium":
				label = "MEDIUM"
			case "badge-low":
				label = "LOW"
			case "badge-info":
				label = "INFO"
			}
			s = strings.ReplaceAll(s, emoji, fmt.Sprintf(`<span class="%s">%s</span>`, class, label))
		}
	}

	return s
}

// parseTableRow splits a markdown table row into cells.
func parseTableRow(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.Trim(line, "|")
	if line == "" {
		return nil
	}
	return strings.Split(line, "|")
}

// slugify creates a URL-safe anchor ID from a heading.
func slugify(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteRune(c)
		case c == ' ' || c == '-':
			b.WriteByte('-')
		}
	}
	result := b.String()
	for strings.Contains(result, "--") {
		result = strings.ReplaceAll(result, "--", "-")
	}
	return strings.Trim(result, "-")
}
