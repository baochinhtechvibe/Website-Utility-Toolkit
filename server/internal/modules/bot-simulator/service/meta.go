package service

import (
	"regexp"
	"strings"
)

// MetaParseResult chứa thông tin meta được parse từ HTML.
type MetaParseResult struct {
	Title           string
	MetaRobots      string // nội dung của <meta name="robots" content="...">
	XRobotsTag      string // nội dung của header X-Robots-Tag
	Canonical       string
	CanonicalSelf   bool // canonical trỏ về chính URL đang check
	CanonicalMissing bool
	Snippet         string // đoạn mô tả ngắn (meta description hoặc 200 ký tự đầu body)
}

var (
	reTitle       = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reMetaRobots  = regexp.MustCompile(`(?i)<meta[^>]+name=["']?robots["']?[^>]+content=["']([^"'>]+)["']`)
	reMetaRobots2 = regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"'>]+)["'][^>]+name=["']?robots["']?`)
	reCanonical   = regexp.MustCompile(`(?i)<link[^>]+rel=["']canonical["'][^>]+href=["']([^"'>]+)["']`)
	reCanonical2  = regexp.MustCompile(`(?i)<link[^>]+href=["']([^"'>]+)["'][^>]+rel=["']canonical["']`)
	reMetaDesc    = regexp.MustCompile(`(?i)<meta[^>]+name=["']?description["']?[^>]+content=["']([^"'>]+)["']`)
	reMetaDesc2   = regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"'>]+)["'][^>]+name=["']?description["']?`)
	reBodyText    = regexp.MustCompile(`(?is)<body[^>]*>(.*?)</body>`)
	reHTMLTags    = regexp.MustCompile(`<[^>]+>`)
)

// ParseMeta phân tích HTML body và X-Robots-Tag header để trích xuất tín hiệu indexability.
func ParseMeta(body string, xRobotsTag string, targetURL string) MetaParseResult {
	result := MetaParseResult{
		XRobotsTag: strings.TrimSpace(xRobotsTag),
	}

	if body == "" {
		return result
	}

	// Parse title
	if m := reTitle.FindStringSubmatch(body); len(m) > 1 {
		result.Title = cleanText(m[1])
	}

	// Parse meta robots
	if m := reMetaRobots.FindStringSubmatch(body); len(m) > 1 {
		result.MetaRobots = strings.TrimSpace(m[1])
	} else if m := reMetaRobots2.FindStringSubmatch(body); len(m) > 1 {
		result.MetaRobots = strings.TrimSpace(m[1])
	}

	// Parse canonical
	cf := ""
	if m := reCanonical.FindStringSubmatch(body); len(m) > 1 {
		cf = strings.TrimSpace(m[1])
	} else if m := reCanonical2.FindStringSubmatch(body); len(m) > 1 {
		cf = strings.TrimSpace(m[1])
	}

	if cf == "" {
		result.CanonicalMissing = true
	} else {
		result.Canonical = cf
		// Kiểm tra canonical self
		if targetURL != "" {
			result.CanonicalSelf = normalizeURLForCompare(cf) == normalizeURLForCompare(targetURL)
		}
	}

	// Parse snippet (meta description hoặc text đầu body)
	snippet := ""
	if m := reMetaDesc.FindStringSubmatch(body); len(m) > 1 {
		snippet = strings.TrimSpace(m[1])
	} else if m := reMetaDesc2.FindStringSubmatch(body); len(m) > 1 {
		snippet = strings.TrimSpace(m[1])
	}

	if snippet == "" {
		// Fallback: lấy text từ body
		if bm := reBodyText.FindStringSubmatch(body); len(bm) > 1 {
			raw := reHTMLTags.ReplaceAllString(bm[1], " ")
			raw = collapseWhitespace(raw)
			if len(raw) > 200 {
				raw = raw[:200] + "..."
			}
			snippet = raw
		}
	}
	result.Snippet = snippet

	return result
}

// HasNoindex kiểm tra một directive string có chứa noindex không.
func HasNoindex(directives string) bool {
	if directives == "" {
		return false
	}
	for _, part := range strings.Split(strings.ToLower(directives), ",") {
		t := strings.TrimSpace(part)
		if t == "noindex" || t == "none" {
			return true
		}
		// X-Robots-Tag có thể có dạng "bot: noindex"
		if idx := strings.Index(part, ":"); idx >= 0 {
			val := strings.TrimSpace(part[idx+1:])
			if val == "noindex" {
				return true
			}
		}
	}
	return false
}

// HasNofollow kiểm tra có chứa nofollow không.
func HasNofollow(directives string) bool {
	if directives == "" {
		return false
	}
	d := strings.ToLower(directives)
	for _, part := range strings.Split(d, ",") {
		if strings.TrimSpace(part) == "nofollow" {
			return true
		}
	}
	return false
}

// ParseXRobotsTag lấy giá trị X-Robots-Tag từ header map.
func ParseXRobotsTag(headers map[string]string) string {
	for k, v := range headers {
		if strings.EqualFold(k, "x-robots-tag") {
			return v
		}
	}
	return ""
}

// normalizeURLForCompare chuẩn hóa URL để so sánh (bỏ trailing slash, lowercase scheme+host).
func normalizeURLForCompare(rawURL string) string {
	rawURL = strings.TrimRight(rawURL, "/")
	rawURL = strings.ToLower(rawURL)
	return rawURL
}

// cleanText xóa tag HTML lồng trong title, trim whitespace.
func cleanText(s string) string {
	s = reHTMLTags.ReplaceAllString(s, "")
	return strings.TrimSpace(collapseWhitespace(s))
}

// collapseWhitespace gộp nhiều khoảng trắng thành một.
func collapseWhitespace(s string) string {
	fields := strings.Fields(s)
	return strings.Join(fields, " ")
}
