package service

import (
	"net/url"
	"regexp"
	"strings"
)

// MetaParseResult chứa thông tin meta được parse từ HTML.
type MetaParseResult struct {
	Title            string
	MetaRobots       string // nội dung của <meta name="robots" content="...">
	XRobotsTag       string // nội dung của header X-Robots-Tag
	Canonical        string
	CanonicalSelf    bool // canonical trỏ về chính URL đang check
	CanonicalMissing bool
	Snippet          string // đoạn mô tả ngắn (meta description hoặc 200 ký tự đầu body)
}

/*
LƯU Ý VỀ REGEX (Rule #Review Fix):
Sử dụng Regex để parse HTML là phương pháp heuristic, có thể bị "break" bởi:
- HTML Comments: <!-- <meta name="robots" content="noindex"> -->
- Multiline attributes hoặc CDATA sections.
Tuy nhiên, với mục đích SEO Simulation và yêu cầu về hiệu suất (không dùng full DOM parser),
cách tiếp cận này là chấp nhận được.
*/
var (
	reTitle       = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reCanonical   = regexp.MustCompile(`(?i)<link[^>]+rel\s*=\s*["']?canonical["']?[^>]+href\s*=\s*["']?([^"'>]+)["']?`)
	reCanonical2  = regexp.MustCompile(`(?i)<link[^>]+href\s*=\s*["']?([^"'>]+)["']?[^>]+rel\s*=\s*["']?canonical["']?`)
	reMetaDesc    = regexp.MustCompile(`(?i)<meta[^>]+name\s*=\s*["']?description["']?[^>]+content\s*=\s*["']?([^"'>]+)["']?`)
	reMetaDesc2   = regexp.MustCompile(`(?i)<meta[^>]+content\s*=\s*["']?([^"'>]+)["']?[^>]+name\s*=\s*["']?description["']?`)
	reBodyText    = regexp.MustCompile(`(?is)<body[^>]*>(.*?)</body>`)
	reHTMLTags    = regexp.MustCompile(`<[^>]+>`)
)

// ParseMeta phân tích HTML body và X-Robots-Tag header để trích xuất tín hiệu indexability.
func ParseMeta(body string, xRobotsTag string, targetURL string, botToken string) MetaParseResult {
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

	// Parse meta robots (chính xác tuyệt đối theo name attribute, tránh lỗi P1)
	var metaRobotsParts []string
	var botMetaRobotsParts []string
	botTokenLower := strings.ToLower(botToken)

	reMetaTags := regexp.MustCompile(`(?i)<meta[^>]+>`)
	reName := regexp.MustCompile(`(?i)name\s*=\s*(?:"|')?([^"'\s>]+)(?:"|')?`)
	reContent := regexp.MustCompile(`(?i)content\s*=\s*(?:"|')?([^"'>]+)(?:"|')?`)

	for _, tagMatch := range reMetaTags.FindAllString(body, -1) {
		nameMatch := reName.FindStringSubmatch(tagMatch)
		contentMatch := reContent.FindStringSubmatch(tagMatch)

		if len(nameMatch) > 1 && len(contentMatch) > 1 {
			name := strings.ToLower(strings.TrimSpace(nameMatch[1]))
			content := strings.TrimSpace(contentMatch[1])

			if name == "robots" {
				metaRobotsParts = append(metaRobotsParts, content)
			} else if botTokenLower != "" && name == botTokenLower {
				botMetaRobotsParts = append(botMetaRobotsParts, content)
			}
		}
	}

	allMetaParts := append(metaRobotsParts, botMetaRobotsParts...)
	result.MetaRobots = strings.Join(allMetaParts, ", ")

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
			// Cắt an toàn theo rune để không cắt ngang ký tự đa byte (Rule #50)
			runes := []rune(raw)
			if len(runes) > 200 {
				raw = string(runes[:200]) + "..."
			}
			snippet = raw
		}
	}
	result.Snippet = snippet

	return result
}

// hasDirective kiểm tra một directive cụ thể có tồn tại cho bot chỉ định không.
// Parser này duyệt qua danh sách comma-separated và lưu state của currentBot
// để xử lý đúng case như "googlebot: noindex, nofollow" (cả 2 rule thuộc googlebot).
func hasDirective(directives string, botToken string, target string, targetAlias string) bool {
	if directives == "" {
		return false
	}
	botToken = strings.ToLower(botToken)
	currentBot := ""

	for _, part := range strings.Split(strings.ToLower(directives), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		directive := part
		if idx := strings.Index(part, ":"); idx >= 0 {
			currentBot = strings.TrimSpace(part[:idx])
			directive = strings.TrimSpace(part[idx+1:])
		}

		// Nếu rule thuộc global ("") hoặc đúng bot đang check
		if currentBot == "" || currentBot == botToken {
			if directive == target || directive == targetAlias {
				return true
			}
		}
	}
	return false
}

// HasNoindex kiểm tra một directive string có chứa noindex cho bot chỉ định không.
func HasNoindex(directives string, botToken string) bool {
	return hasDirective(directives, botToken, "noindex", "none")
}

// HasNofollow kiểm tra có chứa nofollow không.
func HasNofollow(directives string, botToken string) bool {
	return hasDirective(directives, botToken, "nofollow", "none")
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

// normalizeURLForCompare chuẩn hóa URL để so sánh (bỏ fragment, bỏ trailing slash, lowercase scheme+host).
func normalizeURLForCompare(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if idx := strings.Index(rawURL, "#"); idx >= 0 {
		rawURL = rawURL[:idx]
	}
	if u, err := url.Parse(rawURL); err == nil {
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		rawURL = u.String()
	}
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
