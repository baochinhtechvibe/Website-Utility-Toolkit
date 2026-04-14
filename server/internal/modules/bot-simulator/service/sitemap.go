package service

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Giới hạn bảo vệ chống fan-out sitemap index
const (
	MaxSitemapFiles    = 20
	MaxSitemapDepth    = 2
	MaxSitemapXMLBytes = 5 * 1024 * 1024 // 5MB mỗi file
	MaxSitemapURLs     = 50000
)

// SitemapCheckResult chứa kết quả kiểm tra sitemap.
type SitemapCheckResult struct {
	DiscoveryPath string   // "robots.txt" | "/sitemap.xml"
	Found         bool
	SitemapURL    string
	URLInSitemap  bool
	FilesScanned  int
	URLsChecked   int
	ParseErrors   []string
}

// xmlURL là struct để parse <url> trong sitemap urlset.
type xmlURL struct {
	Loc string `xml:"loc"`
}

// xmlURLSet là struct để parse <urlset>.
type xmlURLSet struct {
	URLs []xmlURL `xml:"url"`
}

// xmlSitemapEntry là struct để parse <sitemap> trong sitemapindex.
type xmlSitemapEntry struct {
	Loc string `xml:"loc"`
}

// xmlSitemapIndex là struct để parse <sitemapindex>.
type xmlSitemapIndex struct {
	Sitemaps []xmlSitemapEntry `xml:"sitemap"`
}

// CheckSitemap kiểm tra sự xuất hiện của targetURL trong sitemap.
// Discovery theo thứ tự: robots.txt Sitemap directive → fallback /sitemap.xml.
func CheckSitemap(ctx context.Context, targetURL string, robotsResult *RobotsParseResult, ua string, ignoreTLS bool) *SitemapCheckResult {
	result := &SitemapCheckResult{
		ParseErrors: []string{},
	}

	visited := make(map[string]bool)

	// Bước 1: Lấy sitemap URLs từ robots.txt
	sitemapURLs := []string{}
	if robotsResult != nil && len(robotsResult.SitemapURLs) > 0 {
		sitemapURLs = robotsResult.SitemapURLs
		result.DiscoveryPath = "robots.txt"
	}

	// Bước 2: Nếu không có trong robots.txt, fallback /sitemap.xml
	if len(sitemapURLs) == 0 {
		u, err := url.Parse(targetURL)
		if err == nil {
			fallback := fmt.Sprintf("%s://%s/sitemap.xml", u.Scheme, u.Host)
			sitemapURLs = append(sitemapURLs, fallback)
			result.DiscoveryPath = "/sitemap.xml"
		}
	}

	if len(sitemapURLs) == 0 {
		result.Found = false
		return result
	}

	// Bước 3: Scan sitemap với giới hạn depth và file count
	targetNorm := normalizeURLForCompare(strings.TrimRight(targetURL, "/"))
	
	accessible, inSitemap, foundURL := scanSitemapURLs(ctx, sitemapURLs, targetNorm, ua, ignoreTLS, visited, result, 0)

	result.Found = accessible
	result.URLInSitemap = inSitemap
	if inSitemap && foundURL != "" {
		result.SitemapURL = foundURL
	} else if accessible && result.SitemapURL == "" {
		result.SitemapURL = sitemapURLs[0]
	}

	return result
}

// scanSitemapURLs đệ quy đọc các file sitemap với guardrails.
func scanSitemapURLs(
	ctx context.Context,
	sitemapURLs []string,
	targetNorm string,
	ua string,
	ignoreTLS bool,
	visited map[string]bool,
	result *SitemapCheckResult,
	depth int,
) (accessible bool, inSitemap bool, sitemapURL string) {
	if depth > MaxSitemapDepth {
		return false, false, ""
	}

	for _, sUrl := range sitemapURLs {
		if result.FilesScanned >= MaxSitemapFiles {
			break
		}
		if visited[sUrl] {
			continue
		}
		visited[sUrl] = true

		body, fetchErr := fetchSitemapFile(ctx, sUrl, ua, ignoreTLS)
		if fetchErr != nil {
			result.ParseErrors = append(result.ParseErrors, fmt.Sprintf("%s: %s", sUrl, fetchErr.Error()))
			continue
		}

		result.FilesScanned++
		accessible = true

		// Thử parse urlset trước
		var urlSet xmlURLSet
		if xmlErr := xml.Unmarshal(body, &urlSet); xmlErr == nil && len(urlSet.URLs) > 0 {
			for _, u := range urlSet.URLs {
				if result.URLsChecked >= MaxSitemapURLs {
					break
				}
				result.URLsChecked++
				norm := normalizeURLForCompare(strings.TrimRight(u.Loc, "/"))
				if norm == targetNorm {
					inSitemap = true
					return true, true, sUrl
				}
			}
			continue
		}

		// Thử parse sitemapindex (nested sitemaps)
		var sitemapIndex xmlSitemapIndex
		if xmlErr := xml.Unmarshal(body, &sitemapIndex); xmlErr == nil && len(sitemapIndex.Sitemaps) > 0 {
			nestedURLs := []string{}
			for _, s := range sitemapIndex.Sitemaps {
				if s.Loc != "" {
					nestedURLs = append(nestedURLs, s.Loc)
				}
			}
			nestedAcc, nestedIn, nestedURL := scanSitemapURLs(ctx, nestedURLs, targetNorm, ua, ignoreTLS, visited, result, depth+1)
			if nestedAcc {
				accessible = true
			}
			if nestedIn {
				return true, true, nestedURL
			}
			continue
		}

		result.ParseErrors = append(result.ParseErrors, fmt.Sprintf("%s: không thể parse XML", sUrl))
	}

	return accessible, inSitemap, ""
}

// fetchSitemapFile tải file sitemap với SSRF protection.
func fetchSitemapFile(ctx context.Context, sitemapURL string, ua string, ignoreTLS bool) ([]byte, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("sitemap redirect vượt giới hạn")
			}
			return nil
		},
		Transport: &http.Transport{
			DisableKeepAlives: true,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: ignoreTLS}, //nolint:gosec
			DialContext:       SafeDialContext,
		},
	}

	req, err := http.NewRequest("GET", sitemapURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", sanitizeHeaderValue(ua))
	req.Header.Set("Accept", "application/xml, text/xml, */*;q=0.8")

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// Kiểm tra content-type
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if ct != "" && !strings.Contains(ct, "xml") && !strings.Contains(ct, "text") {
		return nil, fmt.Errorf("content-type không phải XML: %s", ct)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxSitemapXMLBytes))
	if err != nil {
		return nil, err
	}
	return body, nil
}
