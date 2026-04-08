package service

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"
)

// ExtractLinks fetches the page, resolves the final URL, and gathers assets.
func ExtractLinks(req models.ScanRequest) (models.ScanData, []models.ScanResultRow, error) {
	client := SafeBasePageClient(req.IgnoreTlsErrors)
	
	httpReq, err := http.NewRequest("GET", req.URL, nil)
	if err != nil {
		return models.ScanData{}, nil, err
	}
	httpReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) BCTechVibe-Scanner/1.0")

	// Follow redirects until max depth automatically
	resp, err := client.Do(httpReq)
	if err != nil {
		return models.ScanData{}, nil, fmt.Errorf("failed fetching base URL: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return models.ScanData{}, nil, fmt.Errorf("base URL returned status code %d", resp.StatusCode)
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

	rawLinks := parseHTML(resp.Body)
	
	validLinks, skippedInvalid := dedupeAndNormalize(rawLinks, finalPageURL, req.Scope)
	data.Summary.SkippedInvalid = skippedInvalid

	// Hard limit to 250
	if len(validLinks) > 250 {
		validLinks = validLinks[:250]
	}

	data.Summary.Total += len(validLinks) // Only valid links count towards total rows checking

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
			case "img", "source":
				attrFields = append(attrFields, "src")
				attrFields = append(attrFields, "srcset")
			case "script", "iframe":
				attrFields = append(attrFields, "src")
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

func dedupeAndNormalize(links []unverifiedLink, base *url.URL, scope string) ([]models.ScanResultRow, int) {
	seen := make(map[string]bool)
	var result []models.ScanResultRow
	invalidCount := 0

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
				// Valid URL, but omitted voluntarily. We skip recording it. 
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
	return result, invalidCount
}

func targetSchemeAllowed(s string) bool {
	return s == "http" || s == "https"
}
