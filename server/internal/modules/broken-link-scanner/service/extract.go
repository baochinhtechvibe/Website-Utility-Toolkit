package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
	"regexp"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"
	"tools.bctechvibe.com/server/internal/platform/validator"
)

var CheckSafeHostname = validator.IsSafeHostname

var (
	cssURLRegex       = regexp.MustCompile(`(?i)url\(\s*['"]?([^'")]+)['"]?\s*\)`)
	cssImportRegex    = regexp.MustCompile(`(?i)@import\s+(?:url\(\s*['"]?([^'")]+)['"]?\s*\)|['"]([^'"]+)['"])`)
	metaRefreshRegex  = regexp.MustCompile(`(?i)\burl\s*=\s*['"]?([^'"]+?)['"]?\s*$`)
)

type crawlJob struct {
	URL   string
	Depth int
}

// ExtractLinks fetches the page, resolves the final URL, and gathers assets via BFS crawling.
func ExtractLinks(ctx context.Context, req models.ScanRequest, rc *RobotsChecker) (models.ScanData, []models.ScanResultRow, error) {
	// Point #1: SSRF Defense for base URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil || !CheckSafeHostname(parsedURL.Hostname()) {
		return models.ScanData{}, nil, fmt.Errorf("địa chỉ website không hợp lệ hoặc thuộc mạng nội bộ")
	}

	client := SafeBasePageClient(req.IgnoreTlsErrors)

	if req.MaxDepth <= 0 {
		req.MaxDepth = 2
	}
	if req.MaxPages <= 0 {
		req.MaxPages = 50
	}
	if req.MaxLinks <= 0 {
		req.MaxLinks = 1000
	}

	data := models.ScanData{
		RequestedURL: req.URL,
		FinalPageURL: req.URL,
		Summary: models.ScanSummary{
			Total: 0,
		},
	}

	queue := []crawlJob{{URL: req.URL, Depth: 1}}
	visitedPages := make(map[string]bool)

	var allValidLinks []models.ScanResultRow

	pagesCrawled := 0
	pagesSkipped := 0
	originHost := parsedURL.Hostname()

	for len(queue) > 0 {
		select {
		case <-ctx.Done():
			return data, allValidLinks, ctx.Err()
		default:
		}

		current := queue[0]
		queue = queue[1:]

		cURL, err := url.Parse(current.URL)
		if err != nil || cURL.Scheme == "" {
			pagesSkipped++
			continue
		}
		cURL.Fragment = ""
		normalizedPageUrl := cURL.String()

		if visitedPages[normalizedPageUrl] {
			continue
		}

		if req.IsRespectRobots() && !rc.IsAllowed(normalizedPageUrl) {
			pagesSkipped++
			continue
		}

		if pagesCrawled >= req.MaxPages {
			if len(queue) > 0 {
				data.Summary.LimitReached = true
			}
			break
		}
		if len(allValidLinks) >= req.MaxLinks {
			if len(queue) > 0 {
				data.Summary.LimitReached = true
			}
			break
		}

		visitedPages[normalizedPageUrl] = true

		if err := rc.WaitCrawlDelay(ctx, normalizedPageUrl, req.CrawlDelay, req.IsRespectRobots()); err != nil {
			return data, allValidLinks, ctx.Err()
		}

		httpReq, err := http.NewRequestWithContext(ctx, "GET", current.URL, nil)
		if err != nil {
			pagesSkipped++
			continue
		}
		httpReq.Header.Set("User-Agent", rc.agent)

		resp, err := client.Do(httpReq)
		if err != nil {
			pagesSkipped++
			continue
		}

		if resp.StatusCode >= 400 {
			resp.Body.Close()
			pagesSkipped++
			continue
		}

		pagesCrawled++

		if rc.progressFn != nil {
			rc.progressFn(pagesCrawled, len(allValidLinks), "extracting")
		}

		finalPageURL := resp.Request.URL
		baseURLStr := finalPageURL.String()

		if pagesCrawled == 1 {
			data.FinalPageURL = baseURLStr
			if u, err := url.Parse(baseURLStr); err == nil {
				originHost = u.Host
			}
		}

		ct := resp.Header.Get("Content-Type")
		if ct != "" && !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") {
			if strings.Contains(ct, "text/css") {
				const maxCSSSize = 2 * 1024 * 1024 // 2MB limit
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxCSSSize))
				resp.Body.Close()
				cssText := string(bodyBytes)
				extractedLinks := parseCSSText(cssText, "CSS File")

				seenInPage := make(map[string]bool)
				rows, _, outCount := dedupeAndNormalize(extractedLinks, finalPageURL, req.Scope, current.URL, originHost, seenInPage)
				data.Summary.SkippedOutOfScope += outCount

				for _, row := range rows {
					if len(allValidLinks) < req.MaxLinks {
						allValidLinks = append(allValidLinks, row)
						if row.Kind == "CSS_IMPORT" && current.Depth < req.MaxDepth {
							vu, err := url.Parse(row.FinalURL)
							if err == nil && originHost != "" && strings.EqualFold(vu.Host, originHost) {
								queue = append(queue, crawlJob{URL: row.FinalURL, Depth: current.Depth + 1})
							}
						}
					} else {
						data.Summary.SkippedOverLimit++
					}
				}

				if len(allValidLinks) >= req.MaxLinks {
					if len(queue) > 0 {
						data.Summary.LimitReached = true
					}
					queue = nil
				}
				
				if rc.progressFn != nil {
					rc.progressFn(pagesCrawled, len(allValidLinks), "extracting")
				}
				continue
			}
			resp.Body.Close()
			pagesCrawled--
			pagesSkipped++
			continue
		}

		const maxBodySize = 10 * 1024 * 1024 // 10MB
		rawLinks := parseHTML(io.LimitReader(resp.Body, maxBodySize))
		resp.Body.Close()

		seenInPage := make(map[string]bool)
		validLinks, skippedInvalid, skippedOutOfScope := dedupeAndNormalize(rawLinks, finalPageURL, req.Scope, baseURLStr, originHost, seenInPage)
		data.Summary.SkippedInvalid += skippedInvalid
		data.Summary.SkippedOutOfScope += skippedOutOfScope

		for _, vl := range validLinks {
			if len(allValidLinks) < req.MaxLinks {
				allValidLinks = append(allValidLinks, vl)

				// Enqueue internal links for crawling if depth allows
				if current.Depth < req.MaxDepth && (vl.Kind == "<a>" || vl.Kind == "<link rel=\"stylesheet\">" || vl.Kind == "CSS_IMPORT") {
					vu, err := url.Parse(vl.FinalURL)
					if err == nil && originHost != "" && strings.EqualFold(vu.Host, originHost) {
						queue = append(queue, crawlJob{URL: vl.FinalURL, Depth: current.Depth + 1})
					}
				}
			} else {
				data.Summary.SkippedOverLimit++
			}
		}
		
		if rc.progressFn != nil {
			rc.progressFn(pagesCrawled, len(allValidLinks), "extracting")
		}

		if len(allValidLinks) >= req.MaxLinks {
			if len(queue) > 0 {
				data.Summary.LimitReached = true
			}
			queue = nil // Stop crawling further pages if limit reached
		}
	}

	data.Summary.Total = len(allValidLinks)
	data.Summary.PagesCrawled = pagesCrawled
	data.Summary.PagesSkipped = pagesSkipped

	if pagesCrawled == 0 {
		return data, nil, fmt.Errorf("không thể quét được trang nội dung nào")
	}

	return data, allValidLinks, nil
}

type unverifiedLink struct {
	Kind      string
	SourceTag string
	RawURL    string
}

func parseHTML(r io.Reader) []unverifiedLink {
	tokenizer := html.NewTokenizer(r)
	var links []unverifiedLink
	inStyle := false

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return links
		case html.TextToken:
			if inStyle {
				token := tokenizer.Token()
				links = append(links, parseCSSText(token.Data, "<style>")...)
			}
		case html.EndTagToken:
			token := tokenizer.Token()
			tName := strings.ToLower(token.Data)
			if tName == "style" {
				inStyle = false
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			tName := strings.ToLower(token.Data)
			if tName == "style" {
				inStyle = true
			}

			// Parse inline style attribute
			for _, attr := range token.Attr {
				if strings.ToLower(attr.Key) == "style" {
					links = append(links, parseCSSText(attr.Val, "<"+tName+" style>")...)
				}
			}

			// Parse meta refresh
			if tName == "meta" {
				var isRefresh bool
				var contentVal string
				for _, attr := range token.Attr {
					k := strings.ToLower(attr.Key)
					if k == "http-equiv" && strings.ToLower(attr.Val) == "refresh" {
						isRefresh = true
					}
					if k == "content" {
						contentVal = attr.Val
					}
				}
				if isRefresh && contentVal != "" {
					if l := parseMetaRefresh(contentVal, token.String()); l != nil {
						links = append(links, *l)
					}
				}
			}

			isStylesheet := false
			if tName == "link" {
				for _, attr := range token.Attr {
					if strings.ToLower(attr.Key) == "rel" && strings.Contains(strings.ToLower(attr.Val), "stylesheet") {
						isStylesheet = true
					}
				}
			}

			attrFields := make([]string, 0)

			switch tName {
			case "a", "link":
				attrFields = append(attrFields, "href")
			case "img", "source", "video", "audio", "embed", "track":
				attrFields = append(attrFields, "src")
				if tName == "img" || tName == "source" {
					attrFields = append(attrFields, "srcset")
				}
				if tName == "video" {
					attrFields = append(attrFields, "poster")
				}
			case "script", "iframe":
				attrFields = append(attrFields, "src")
			case "object":
				attrFields = append(attrFields, "data")
			case "form":
				attrFields = append(attrFields, "action")
			}

			for _, attr := range token.Attr {
				k := strings.ToLower(attr.Key)
				for _, expected := range attrFields {
					if k == expected {
						if k == "srcset" {
							parts := strings.Split(attr.Val, ",")
							for _, p := range parts {
								p = strings.TrimSpace(p)
								split := strings.Split(p, " ")
								if len(split) > 0 && split[0] != "" {
									links = append(links, unverifiedLink{Kind: "<" + tName + ">", SourceTag: token.String(), RawURL: split[0]})
								}
							}
						} else {
							kind := "<" + tName + ">"
							if tName == "link" && isStylesheet {
								kind = "<link rel=\"stylesheet\">"
							}
							links = append(links, unverifiedLink{Kind: kind, SourceTag: token.String(), RawURL: attr.Val})
						}
					}
				}
			}
		}
	}
}

func parseCSSText(text string, sourceTag string) []unverifiedLink {
	var links []unverifiedLink
	seenRaw := make(map[string]bool)

	// Find @import first to prioritize it
	importMatches := cssImportRegex.FindAllStringSubmatch(text, -1)
	for _, m := range importMatches {
		if len(m) > 2 {
			val := m[1]
			if val == "" {
				val = m[2]
			}
			if val != "" {
				seenRaw[val] = true
				links = append(links, unverifiedLink{Kind: "CSS_IMPORT", SourceTag: sourceTag, RawURL: val})
			}
		}
	}

	// Find url(...)
	urlMatches := cssURLRegex.FindAllStringSubmatch(text, -1)
	for _, m := range urlMatches {
		if len(m) > 1 {
			val := m[1]
			if !seenRaw[val] {
				seenRaw[val] = true
				links = append(links, unverifiedLink{Kind: "CSS", SourceTag: sourceTag, RawURL: val})
			}
		}
	}

	return links
}

func parseMetaRefresh(contentVal string, sourceTag string) *unverifiedLink {
	m := metaRefreshRegex.FindStringSubmatch(contentVal)
	if len(m) > 1 {
		raw := strings.TrimSpace(m[1])
		return &unverifiedLink{Kind: "<meta>", SourceTag: sourceTag, RawURL: raw}
	}
	return nil
}

func dedupeAndNormalize(links []unverifiedLink, base *url.URL, scope string, sourcePage string, originHost string, seen map[string]bool) ([]models.ScanResultRow, int, int) {
	var result []models.ScanResultRow
	invalidCount := 0
	outOfScopeCount := 0

	for _, l := range links {
		trimmed := strings.TrimSpace(l.RawURL)
		if trimmed == "" {
			invalidCount++
			continue
		}

		rawHashMark := strings.Index(trimmed, "#")
		if rawHashMark == 0 {
			invalidCount++
			continue
		} else if rawHashMark > 0 {
			trimmed = trimmed[:rawHashMark]
		}

		u, err := url.Parse(trimmed)
		if err != nil {
			invalidCount++
			continue
		}

		scheme := strings.ToLower(u.Scheme)
		if scheme != "" && targetSchemeAllowed(scheme) == false {
			invalidCount++
			continue
		}

		absoluteContext := base.ResolveReference(u)
		absoluteURL := absoluteContext.String()

		// Security: reject URLs with embedded credentials (user:pass@host)
		if absoluteContext.User != nil {
			invalidCount++
			continue
		}

		if seen[absoluteURL] {
			continue
		}
		seen[absoluteURL] = true

		if scope == "same-host" && originHost != "" {
			if !strings.EqualFold(absoluteContext.Host, originHost) {
				outOfScopeCount++
				continue
			}
		}

		result = append(result, models.ScanResultRow{
			Kind:        l.Kind,
			SourceTag:   l.SourceTag,
			SourcePage:  sourcePage,
			OriginalURL: l.RawURL,
			FinalURL:    absoluteURL,
			StatusCode:  0,
			StatusClass: "unknown",
		})
	}
	return result, invalidCount, outOfScopeCount
}

func targetSchemeAllowed(s string) bool {
	return s == "http" || s == "https"
}
