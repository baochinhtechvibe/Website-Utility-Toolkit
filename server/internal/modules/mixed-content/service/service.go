package service

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/net/html"
	"tools.bctechvibe.com/server/internal/modules/mixed-content/models"
	"tools.bctechvibe.com/server/internal/platform/validator"
)

const (
	maxItems        = 200
	maxBodySize     = 5 * 1024 * 1024 // 5MB
	maxRedirects    = 3
	cacheTTL        = 5 * time.Minute
	scanUserAgent   = "MixedContentScanner/1.0 (+https://tools.bctechvibe.com)"
)

// ─── Cache ────────────────────────────────────────────────────────────────────

type cacheEntry struct {
	data      *models.ScanData
	expiresAt time.Time
}

var (
	cacheMap sync.Map
)

func cacheGet(key string) (*models.ScanData, bool) {
	v, ok := cacheMap.Load(key)
	if !ok {
		return nil, false
	}
	entry := v.(cacheEntry)
	if time.Now().After(entry.expiresAt) {
		cacheMap.Delete(key)
		return nil, false
	}
	return entry.data, true
}

func cacheSet(key string, data *models.ScanData) {
	cacheMap.Store(key, cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(cacheTTL),
	})
}

// ─── SSRF Protection (Delegated to platform/validator) ────────────

func newSecureClient(ignoreTLS bool) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return http.ErrUseLastResponse
			}
			// Block redirect đến private IP
			if err := validateHostSSRF(req.URL.Hostname()); err != nil {
				return err
			}
			return nil
		},
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: ignoreTLS},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.LookupIP(host)
				if err != nil {
					return nil, err
				}
				var safeIP net.IP
				for _, ip := range ips {
					if validator.IsSafeIP(ip) {
						safeIP = ip
						break
					}
				}
				if safeIP == nil {
					return nil, fmt.Errorf("SSRF Protection: no safe IP for %s", host)
				}
				return (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
			},
		},
	}
}

func validateHostSSRF(hostname string) error {
	if !validator.IsSafeHostname(hostname) {
		return fmt.Errorf("SSRF Protection: địa chỉ IP nội bộ bị chặn")
	}
	return nil
}

// ─── Classification ──────────────────────────────────────────────────────────

var activeSubtypes = map[string]bool{
	"script":  true,
	"iframe":  true,
	"object":  true,
	"embed":   true,
	"css":     true,
}

var infoSubtypes = map[string]bool{
	"link": true,
	"form": true,
}

func classifyType(subtype string) string {
	if activeSubtypes[subtype] {
		return "Active"
	}
	if infoSubtypes[subtype] {
		return "Info"
	}
	return "Passive"
}

func classifyOrigin(itemURL, baseHost string) string {
	parsed, err := url.Parse(itemURL)
	if err != nil {
		return "third-party"
	}
	if strings.EqualFold(parsed.Hostname(), baseHost) {
		return "same-domain"
	}
	return "third-party"
}

func makeFix(rawURL string) string {
	return strings.Replace(rawURL, "http://", "https://", 1)
}

// ─── HTML Parser ─────────────────────────────────────────────────────────────

var reInlineStyleURL = regexp.MustCompile(`(?i)url\s*\(\s*['"]?\s*(http://[^'"\)\s]+)\s*['"]?\s*\)`)

func extractMixedItems(body io.Reader, baseHost string) ([]models.MixedItem, bool) {
	var items []models.MixedItem
	truncated := false

	addItem := func(rawURL, subtype, foundIn string) {
		if len(items) >= maxItems {
			truncated = true
			return
		}
		// Chỉ lấy HTTP (không phải HTTPS)
		lower := strings.ToLower(rawURL)
		if !strings.HasPrefix(lower, "http://") {
			return
		}
		items = append(items, models.MixedItem{
			URL:           rawURL,
			Type:          classifyType(subtype),
			Subtype:       subtype,
			Origin:        classifyOrigin(rawURL, baseHost),
			FoundIn:       foundIn,
			FixSuggestion: makeFix(rawURL),
		})
	}

	doc, err := html.Parse(body)
	if err != nil {
		log.Warn().Err(err).Msg("html.Parse error")
		return items, truncated
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if truncated {
			return
		}
		if n.Type == html.ElementNode {
			tag := strings.ToLower(n.Data)
			switch tag {
			case "script":
				if src := attrVal(n, "src"); src != "" {
					addItem(src, "script", "<script src>")
				}
			case "link":
				rel := strings.ToLower(attrVal(n, "rel"))
				href := attrVal(n, "href")
				if href != "" {
					switch rel {
					case "stylesheet":
						addItem(href, "css", "<link rel=stylesheet href>")
					case "preload", "prefetch":
						addItem(href, "other", fmt.Sprintf("<link rel=%s href>", rel))
					}
				}
			case "img":
				if src := attrVal(n, "src"); src != "" {
					addItem(src, "img", "<img src>")
				}
				if srcset := attrVal(n, "srcset"); srcset != "" {
					for _, u := range parseSrcset(srcset) {
						addItem(u, "img", "<img srcset>")
					}
				}
			case "iframe":
				if src := attrVal(n, "src"); src != "" {
					addItem(src, "iframe", "<iframe src>")
				}
			case "video", "audio":
				if src := attrVal(n, "src"); src != "" {
					addItem(src, tag, fmt.Sprintf("<%s src>", tag))
				}
			case "source":
				if src := attrVal(n, "src"); src != "" {
					addItem(src, "media", "<source src>")
				}
			case "object":
				if data := attrVal(n, "data"); data != "" {
					addItem(data, "object", "<object data>")
				}
			case "embed":
				if src := attrVal(n, "src"); src != "" {
					addItem(src, "embed", "<embed src>")
				}
			case "style":
				// Inline <style> — parse url()
				if n.FirstChild != nil {
					matches := reInlineStyleURL.FindAllStringSubmatch(n.FirstChild.Data, -1)
					for _, m := range matches {
						if len(m) > 1 {
							addItem(m[1], "css", "<style> url()")
						}
					}
				}
			case "a":
				if href := attrVal(n, "href"); href != "" {
					addItem(href, "link", "<a href>")
				}
			case "form":
				if action := attrVal(n, "action"); action != "" {
					addItem(action, "form", "<form action>")
				}
			}
			// style attribute inline
			if styleAttr := attrVal(n, "style"); styleAttr != "" {
				matches := reInlineStyleURL.FindAllStringSubmatch(styleAttr, -1)
				for _, m := range matches {
					if len(m) > 1 {
						addItem(m[1], "css", fmt.Sprintf("<%s style=>", tag))
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return items, truncated
}

func attrVal(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return strings.TrimSpace(a.Val)
		}
	}
	return ""
}

func parseSrcset(srcset string) []string {
	var urls []string
	parts := strings.Split(srcset, ",")
	for _, p := range parts {
		fields := strings.Fields(strings.TrimSpace(p))
		if len(fields) > 0 {
			urls = append(urls, fields[0])
		}
	}
	return urls
}

// ─── Public API ──────────────────────────────────────────────────────────────

// ScanMixedContent fetch URL, parse HTML, trả danh sách HTTP resources
func ScanMixedContent(ctx context.Context, req models.ScanRequest) (*models.ScanData, error) {
	rawURL := strings.TrimSpace(req.URL)

	// Validate scheme
	lower := strings.ToLower(rawURL)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return nil, fmt.Errorf("URL phải bắt đầu bằng http:// hoặc https://")
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("URL không hợp lệ")
	}

	// SSRF check trước khi fetch
	if err := validateHostSSRF(parsed.Hostname()); err != nil {
		return nil, err
	}

	// Cache lookup
	if cached, ok := cacheGet(rawURL); ok {
		log.Debug().Str("url", rawURL).Msg("mixedcontent cache hit")
		return cached, nil
	}

	client := newSecureClient(req.IgnoreTLSErrors)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("không thể tạo request")
	}
	httpReq.Header.Set("User-Agent", scanUserAgent)
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(httpReq)
	if err != nil {
		log.Warn().Err(err).Str("url", rawURL).Msg("mixedcontent fetch failed")
		return nil, fmt.Errorf("không thể kết nối tới URL (%v). Vui lòng kiểm tra lại URL và thử lại.", err)
	}
	defer resp.Body.Close()

	limitedBody := io.LimitReader(resp.Body, maxBodySize)
	baseHost := parsed.Hostname()

	items, truncated := extractMixedItems(limitedBody, baseHost)

	activeCount, passiveCount := 0, 0
	for _, it := range items {
		if it.Type == "Active" {
			activeCount++
		} else {
			passiveCount++
		}
	}

	data := &models.ScanData{
		ScannedURL:   rawURL,
		TotalFound:   len(items),
		ActiveCount:  activeCount,
		PassiveCount: passiveCount,
		Items:        items,
		Truncated:    truncated,
	}

	cacheSet(rawURL, data)
	return data, nil
}
