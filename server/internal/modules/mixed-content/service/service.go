package service

import (
	"context"
	"crypto/tls"
	"errors"
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
	cache "github.com/go-pkgz/expirable-cache/v3"
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

// ─── Cache & Rate Limiting ──────────────────────────────────────────────────

type cacheEntry struct {
	Data      *models.ScanData
	FetchedAt time.Time
}

var (
	// Bộ nhớ tạm cho kết quả scan (TTL 5 phút)
	scanCache cache.Cache[string, cacheEntry]

	// Bộ nhớ tạm để giới hạn lượt bấm "Làm mới" theo IP (5 lần/phút)
	ipLimiter cache.Cache[string, []time.Time]

	// Khóa để tránh race condition khi cập nhật danh sách IP
	ipMutex sync.Mutex

	// ErrRateLimited là lỗi sentinel cho rate limit (Quy tắc #45)
	ErrRateLimited = errors.New("rate_limited")
)

func init() {
	// Khởi tạo cache với LRU và TTL chuẩn của github.com/go-pkgz/expirable-cache/v3
	scanCache = cache.NewCache[string, cacheEntry]().WithLRU().WithTTL(cacheTTL)
	ipLimiter = cache.NewCache[string, []time.Time]().WithLRU().WithTTL(1 * time.Minute)
}

// checkRateLimit kiểm tra xem IP có vượt quá 5 lần bấm "Làm mới" trong 1 phút không
func checkRateLimit(ip string) error {
	if ip == "" || ip == "127.0.0.1" || ip == "::1" {
		return nil // Không limit localhost
	}

	ipMutex.Lock()
	defer ipMutex.Unlock()

	now := time.Now()
	oneMinuteAgo := now.Add(-1 * time.Minute)

	history, _ := ipLimiter.Get(ip)

	// Lọc bỏ các request cũ hơn 1 phút
	var validRequests []time.Time
	for _, t := range history {
		if t.After(oneMinuteAgo) {
			validRequests = append(validRequests, t)
		}
	}

	if len(validRequests) >= 5 {
		return ErrRateLimited
	}

	// Thêm request hiện tại vào lịch sử
	validRequests = append(validRequests, now)
	ipLimiter.Set(ip, validRequests, 2*time.Minute)

	return nil
}

// ─── SSRF Protection (Delegated to platform/validator) ────────────

// Singleton HTTP clients: reuse TCP connection pool + TLS session cache
var (
	defaultClient      *http.Client
	insecureClient     *http.Client
	defaultClientOnce  sync.Once
	insecureClientOnce sync.Once
)

func buildSecureClient(ignoreTLS bool) *http.Client {
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
			Proxy:             http.ProxyFromEnvironment,
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: ignoreTLS},
			MaxIdleConns:      50,
			IdleConnTimeout:   90 * time.Second,
			DisableKeepAlives: false,
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

func getSecureClient(ignoreTLS bool) *http.Client {
	if ignoreTLS {
		insecureClientOnce.Do(func() {
			insecureClient = buildSecureClient(true)
		})
		return insecureClient
	}
	defaultClientOnce.Do(func() {
		defaultClient = buildSecureClient(false)
	})
	return defaultClient
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

func extractMixedItems(ctx context.Context, body io.Reader, baseHost string) ([]models.MixedItem, bool) {
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

	nodeCount := 0
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if truncated {
			return
		}
		// Kiểm tra context định kỳ để dừng nếu timeout (Quy tắc #41)
		nodeCount++
		if nodeCount%100 == 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
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
func ScanMixedContent(ctx context.Context, req models.ScanRequest, clientIP string) (scanRes *models.ScanData, errRes error, isCached bool, fetchedAt time.Time) {
	rawURL := strings.TrimSpace(req.URL)

	// Validate scheme
	lower := strings.ToLower(rawURL)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return nil, fmt.Errorf("URL phải bắt đầu bằng http:// hoặc https://"), false, time.Time{}
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("URL không hợp lệ"), false, time.Time{}
	}

	// SSRF check trước khi fetch
	if err := validateHostSSRF(parsed.Hostname()); err != nil {
		return nil, err, false, time.Time{}
	}

	// Cache key bao gồm TLS mode (Quy tắc #42)
	cacheKey := fmt.Sprintf("%s|tls=%v", rawURL, req.IgnoreTLSErrors)

	// Cache lookup (chỉ khi không bypass)
	if !req.BypassCache {
		if cached, ok := scanCache.Get(cacheKey); ok {
			log.Debug().Str("url", rawURL).Msg("mixedcontent cache hit")
			return cached.Data, nil, true, cached.FetchedAt
		}
	} else {
		// Kiểm tra Rate Limit khi Bypass Cache
		if err := checkRateLimit(clientIP); err != nil {
			return nil, err, false, time.Time{}
		}
	}

	fetchedAt = time.Now()
	client := getSecureClient(req.IgnoreTLSErrors)
	httpReq, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("không thể tạo request"), false, time.Time{}
	}
	httpReq.Header.Set("User-Agent", scanUserAgent)
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	httpReq.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(httpReq)
	if err != nil {
		// Trả về lỗi gốc để handler.go có thể dùng errutil.TranslateError dịch chính xác
		return nil, err, false, time.Time{}
	}
	defer resp.Body.Close()

	// Validate Content-Type: chỉ parse HTML, bỏ qua binary (PDF, ZIP...)
	ct := resp.Header.Get("Content-Type")
	if ct != "" && !strings.Contains(ct, "text/html") && !strings.Contains(ct, "application/xhtml") {
		return nil, fmt.Errorf("content-type không hợp lệ: %s", ct), false, time.Time{}
	}

	limitedBody := io.LimitReader(resp.Body, maxBodySize)
	baseHost := parsed.Hostname()

	items, truncated := extractMixedItems(ctx, limitedBody, baseHost)

	activeCount, passiveCount := 0, 0
	for _, it := range items {
		switch it.Type {
		case "Active":
			activeCount++
		case "Passive":
			passiveCount++
		// "Info" type: không tính vào active hay passive
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

	cacheSetEntry := cacheEntry{
		Data:      data,
		FetchedAt: fetchedAt,
	}
	scanCache.Set(cacheKey, cacheSetEntry, cacheTTL)
	return data, nil, false, fetchedAt
}
