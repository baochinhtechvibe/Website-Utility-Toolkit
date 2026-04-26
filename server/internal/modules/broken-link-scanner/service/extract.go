package service

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"
	"tools.bctechvibe.com/server/internal/platform/validator"
)

// ExtractLinks fetches the page, resolves the final URL, and gathers assets.
func ExtractLinks(ctx context.Context, req models.ScanRequest) (models.ScanData, []models.ScanResultRow, error) {
	// Point #1: SSRF Defense for base URL
	parsedURL, err := url.Parse(req.URL)
	if err != nil || !validator.IsSafeHostname(parsedURL.Hostname()) {
		return models.ScanData{}, nil, fmt.Errorf("địa chỉ website không hợp lệ hoặc thuộc mạng nội bộ")
	}

	client := SafeBasePageClient(req.IgnoreTlsErrors)
	
	httpReq, err := http.NewRequestWithContext(ctx, "GET", req.URL, nil)
	if err != nil {
		return models.ScanData{}, nil, err
	}
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BCTechVibe-Scanner/1.0")

	// Follow redirects until max depth automatically
	resp, err := client.Do(httpReq)
	if err != nil {
		return models.ScanData{}, nil, err
	}
	defer resp.Body.Close()

	// Validate Content-Type: chỉ parse HTML
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") {
		return models.ScanData{}, nil, fmt.Errorf("content-type không hợp lệ: %s", ct)
	}

	if resp.StatusCode >= 400 {
		return models.ScanData{}, nil, fmt.Errorf("website trả về mã lỗi HTTP %d", resp.StatusCode)
	}

	finalPageURL := resp.Request.URL
	baseURLStr := finalPageURL.String()

	data := models.ScanData{
		RequestedURL: req.URL,
		FinalPageURL: baseURLStr,
		Summary: models.ScanSummary{
			Total: 0,
		},
	}

	// Point #1: Limit body size to 10MB to avoid OOM for misconfigured large pages
	const maxBodySize = 10 * 1024 * 1024 // 10MB
	rawLinks := parseHTML(io.LimitReader(resp.Body, maxBodySize))
	
	validLinks, skippedInvalid, skippedOutOfScope := dedupeAndNormalize(rawLinks, finalPageURL, req.Scope)
	data.Summary.SkippedInvalid = skippedInvalid
	data.Summary.SkippedOutOfScope = skippedOutOfScope

	// Hard limit to 500 (GEMINI Rule #30 - Resource Management)
	if len(validLinks) > 500 {
		data.Summary.SkippedOverLimit = len(validLinks) - 500
		validLinks = validLinks[:500]
	}

	data.Summary.Total = len(validLinks) // Only valid links count towards total rows checking

	return data, validLinks, nil
}

type unverifiedLink struct {
	Kind      string
	SourceTag string
	RawURL    string
}

func parseHTML(r io.Reader) []unverifiedLink {
	tokenizer := html.NewTokenizer(r)
	var links []unverifiedLink

	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return links
		case html.StartTagToken, html.SelfClosingTagToken:
			token := tokenizer.Token()
			tName := strings.ToLower(token.Data)
			
			// Maps valid tags to their attribute target
			attrFields := make([]string, 0)
			
			switch tName {
			case "a", "link":
				attrFields = append(attrFields, "href")
			case "img", "source", "video", "audio", "embed", "track":
				attrFields = append(attrFields, "src")
				if tName == "img" || tName == "source" {
					attrFields = append(attrFields, "srcset")
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
							// Parse basic srcset split
							parts := strings.Split(attr.Val, ",")
							for _, p := range parts {
								p = strings.TrimSpace(p)
								split := strings.Split(p, " ")
								if len(split) > 0 && split[0] != "" {
									links = append(links, unverifiedLink{Kind: "<" + tName + ">", SourceTag: token.String(), RawURL: split[0]})
								}
							}
						} else {
							links = append(links, unverifiedLink{Kind: "<" + tName + ">", SourceTag: token.String(), RawURL: attr.Val})
						}
					}
				}
			}
		}
	}
}

func dedupeAndNormalize(links []unverifiedLink, base *url.URL, scope string) ([]models.ScanResultRow, int, int) {
	seen := make(map[string]bool)
	var result []models.ScanResultRow
	invalidCount := 0
	outOfScopeCount := 0

	for _, l := range links {
		trimmed := strings.TrimSpace(l.RawURL)
		if trimmed == "" {
			invalidCount++
			continue
		}

		// Remove anchor fragment natively
		rawHashMark := strings.Index(trimmed, "#")
		if rawHashMark == 0 { // Just an anchor 
			invalidCount++
			continue
		} else if rawHashMark > 0 {
			trimmed = trimmed[:rawHashMark]
		}

		// Parse the individual raw URL and resolve into Absolute Context 
		u, err := url.Parse(trimmed)
		if err != nil {
			invalidCount++
			continue
		}

		// Reject mailto, javascript, data...
		scheme := strings.ToLower(u.Scheme)
		if scheme != "" && targetSchemeAllowed(scheme) == false {
			invalidCount++
			continue
		}

		absoluteContext := base.ResolveReference(u)
		absoluteURL := absoluteContext.String()
		
		// Dedupe
		if seen[absoluteURL] {
			continue // Deduplicated links DO NOT count as SkippedInvalid according to specs
		}
		seen[absoluteURL] = true

		// Check scope: same-host means strictly equal Host
		if scope == "same-host" {
			if !strings.EqualFold(absoluteContext.Host, base.Host) {
				outOfScopeCount++
				continue
			}
		}

		result = append(result, models.ScanResultRow{
			Kind:          l.Kind,
			SourceTag:     l.SourceTag,
			OriginalURL:   l.RawURL,
			FinalURL:      absoluteURL,
			StatusCode:    0,
			StatusClass:   "unknown",
		})
	}
	return result, invalidCount, outOfScopeCount
}

func targetSchemeAllowed(s string) bool {
	return s == "http" || s == "https"
}
