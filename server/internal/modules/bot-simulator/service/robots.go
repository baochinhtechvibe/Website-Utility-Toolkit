package service

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RobotsAccessStatus biểu diễn kết quả fetch /robots.txt.
// Lưu ý: Kết hợp giữa tiêu chuẩn RFC 9309 và Simulator Policy bảo thủ (như Googlebot).
type RobotsAccessStatus string

const (
	RobotsStatus2xx         RobotsAccessStatus = "2xx"         // Tìm thấy, đọc được (RFC)
	RobotsStatus3xx         RobotsAccessStatus = "3xx"         // Redirect nhưng không thành công cuối cùng
	RobotsStatus4xx         RobotsAccessStatus = "4xx_allow"   // 4xx (trừ 429) → Cho phép crawl (RFC & Google)
	RobotsStatus5xx         RobotsAccessStatus = "5xx_block"   // 5xx hoặc 429 → Hoãn crawl (RFC & Google)
	RobotsStatusTimeout     RobotsAccessStatus = "timeout"     // Timeout → Hoãn crawl (RFC)
	RobotsStatusUnreachable RobotsAccessStatus = "unreachable" // Không kết nối được
	RobotsStatusNone        RobotsAccessStatus = "none"        // Không check
)

// RobotsRule là một cặp rule allow/disallow cho một path.
type RobotsRule struct {
	Path   string
	Allow  bool
	Length int // độ dài path để tính longest-match
}

// RobotsGroup là group user-agent trong robots.txt.
type RobotsGroup struct {
	Agents []string
	Rules  []RobotsRule
}

// RobotsParseResult chứa toàn bộ kết quả parse và fetch robots.txt.
type RobotsParseResult struct {
	FetchStatus RobotsAccessStatus
	RobotsURL   string
	SitemapURLs []string
	Groups      []RobotsGroup
	RawContent  string // giới hạn 10KB để debug
	FetchedAt   time.Time
}

// RobotsDecision là kết quả quyết định access cho một bot/path cụ thể.
type RobotsDecision struct {
	Allowed      bool
	MatchedGroup string // agents trong group đã match
	MatchedRule  string // rule cụ thể đã match (path)
	Decision     string // "allow" | "disallow" | "default_allow" | "default_disallow"
}

// FetchAndParseRobots fetch /robots.txt và parse theo RFC 9309.
// Xử lý đúng các HTTP status code: 2xx/3xx/4xx/5xx/timeout/unreachable.
func FetchAndParseRobots(ctx context.Context, targetURL string, botUA string, ignoreTLS bool) (*RobotsParseResult, error) {
	robotsURL, err := RobotsURL(targetURL)
	if err != nil {
		return nil, fmt.Errorf("không thể tạo URL robots.txt: %w", err)
	}

	result := &RobotsParseResult{
		RobotsURL:   robotsURL,
		SitemapURLs: []string{},
		Groups:      []RobotsGroup{},
		FetchedAt:   time.Now(),
	}

	client := getClient(ignoreTLS)

	req, err := http.NewRequest("GET", robotsURL, nil)
	if err != nil {
		result.FetchStatus = RobotsStatusUnreachable
		return result, nil
	}
	req.Header.Set("User-Agent", sanitizeHeaderValue(botUA))
	req.Header.Set("Accept", "text/plain, text/*, */*;q=0.8")

	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		if TimeoutError(err) {
			// Sửa lỗi P2: Timeout thì gán đúng status timeout để UI map ra label chính xác,
			// indexability engine vẫn treat timeout như deferred/unknown crawl block.
			result.FetchStatus = RobotsStatusTimeout
		} else {
			result.FetchStatus = RobotsStatusUnreachable
		}
		return result, nil
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// 2xx: đọc và parse
		result.FetchStatus = RobotsStatus2xx
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 500*1024)) // max 500KB robots.txt theo chuẩn RFC và Google
		// Lưu raw content giới hạn để debug
		if len(bodyBytes) > 10*1024 {
			result.RawContent = string(bodyBytes[:10*1024]) + "\n... (truncated)"
		} else {
			result.RawContent = string(bodyBytes)
		}

		parsed := ParseRobotsContent(string(bodyBytes))
		result.Groups = parsed.Groups
		result.SitemapURLs = parsed.SitemapURLs

	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		// 3xx: Theo RFC 9309 §2.3.1.2: Follow redirect tối đa 5 lần
		loc := resp.Header.Get("Location")
		if loc != "" {
			result.FetchStatus = RobotsStatus3xx
			parsedBase, _ := url.Parse(robotsURL)
			parsedLoc, err := url.Parse(loc)
			if err == nil && parsedBase != nil {
				nextURL := parsedBase.ResolveReference(parsedLoc).String()
				result2, err2 := fetchRobotsWithRedirects(ctx, nextURL, botUA, ignoreTLS, 1)
				if result2 != nil {
					result.Groups = result2.Groups
					result.SitemapURLs = result2.SitemapURLs
					result.RawContent = result2.RawContent
					result.FetchStatus = result2.FetchStatus
				}
				_ = err2
			}
		} else {
			result.FetchStatus = RobotsStatus3xx
		}

	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// Sửa theo review (P1): Theo RFC 9309 và Google Search Central:
		// Mọi lỗi 4xx (bao gồm 401/403) trừ 429 đều được hiểu là "Unavailable" -> Full Allow.
		// Mã 429 (Too Many Requests) được xử lý tương đương 5xx -> Crawler hoãn lại.
		if resp.StatusCode == 429 {
			result.FetchStatus = RobotsStatus5xx
		} else {
			result.FetchStatus = RobotsStatus4xx
		}

	case resp.StatusCode >= 500:
		// 5xx: theo RFC 9309 §2.3.1.5 → bot nên hoãn crawl, treat như full block tạm thời
		result.FetchStatus = RobotsStatus5xx

	default:
		result.FetchStatus = RobotsStatusUnreachable
	}

	return result, nil
}

// fetchRobotsWithRedirects thực hiện loop đệ quy follow redirect cho robots.txt (tối đa 5 lần).
func fetchRobotsWithRedirects(ctx context.Context, targetURL string, ua string, ignoreTLS bool, depth int) (*RobotsParseResult, error) {
	result := &RobotsParseResult{
		SitemapURLs: []string{},
		Groups:      []RobotsGroup{},
	}

	if depth > 5 {
		// Sửa lỗi P1 từ review: Quá 5 hop redirect thì treat như không có robots.txt (Full Allow)
		result.FetchStatus = RobotsStatus4xx
		return result, fmt.Errorf("robots.txt redirect vượt giới hạn (5)")
	}

	opts := FetchOptions{
		UserAgent:       ua,
		IgnoreTLSErrors: ignoreTLS,
		FollowRedirects: false,
	}

	res, err := FetchPage(ctx, targetURL, opts)
	if err != nil {
		return result, err
	}

	if res.StatusCode >= 200 && res.StatusCode < 300 {
		content := res.Body
		if len(content) > 10*1024 {
			result.RawContent = content[:10*1024] + "\n... (truncated)"
		} else {
			result.RawContent = content
		}
		parsed := ParseRobotsContent(content)
		result.Groups = parsed.Groups
		result.SitemapURLs = parsed.SitemapURLs
		result.FetchStatus = RobotsStatus2xx
	} else if res.StatusCode >= 300 && res.StatusCode < 400 {
		loc := res.Headers["Location"]
		if loc != "" {
			parsedBase, _ := url.Parse(targetURL)
			parsedLoc, err := url.Parse(loc)
			if err == nil && parsedBase != nil {
				nextURL := parsedBase.ResolveReference(parsedLoc).String()
				return fetchRobotsWithRedirects(ctx, nextURL, ua, ignoreTLS, depth+1)
			}
		}
		result.FetchStatus = RobotsStatus3xx
	} else if res.StatusCode >= 400 && res.StatusCode < 500 {
		if res.StatusCode == 429 {
			result.FetchStatus = RobotsStatus5xx
		} else {
			result.FetchStatus = RobotsStatus4xx
		}
	} else if res.StatusCode >= 500 {
		result.FetchStatus = RobotsStatus5xx
	} else {
		result.FetchStatus = RobotsStatusUnreachable
	}

	return result, nil
}

// ParseRobotsContent parse nội dung file robots.txt theo RFC 9309.
// Hỗ trợ: nhiều group, wildcard *, $, Sitemap directive.
func ParseRobotsContent(content string) *RobotsParseResult {
	result := &RobotsParseResult{
		Groups:      []RobotsGroup{},
		SitemapURLs: []string{},
	}
	scanner := bufio.NewScanner(strings.NewReader(content))
	// Giới hạn buffer để tránh panic với line quá dài (Rule #Review Fix)
	// Max line 64KB, tổng body đã bị limit 512KB ở tầng fetch.
	scanner.Buffer(make([]byte, 64*1024), 512*1024)

	var currentAgents []string
	var currentRules []RobotsRule
	var inGroup bool

	flushGroup := func() {
		if len(currentAgents) > 0 {
			result.Groups = append(result.Groups, RobotsGroup{
				Agents: currentAgents,
				Rules:  currentRules,
			})
		}
		currentAgents = nil
		currentRules = nil
		inGroup = false
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Bỏ comment
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			// Dòng trống = kết thúc group
			if inGroup {
				flushGroup()
			}
			continue
		}

		colonIdx := strings.Index(line, ":")
		if colonIdx < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:colonIdx]))
		value := strings.TrimSpace(line[colonIdx+1:])

		switch key {
		case "user-agent":
			if len(currentRules) > 0 {
				// Group mới bắt đầu, flush group cũ trước
				flushGroup()
			}
			if value != "" {
				currentAgents = append(currentAgents, strings.ToLower(value))
				inGroup = true
			}
		case "allow":
			if inGroup && value != "" {
				currentRules = append(currentRules, RobotsRule{
					Path:   value,
					Allow:  true,
					Length: len(value),
				})
			}
		case "disallow":
			if inGroup {
				if value == "" {
					// Disallow rỗng = cho phép tất cả (RFC 9309)
					currentRules = append(currentRules, RobotsRule{
						Path:   "",
						Allow:  true,
						Length: 0,
					})
				} else {
					currentRules = append(currentRules, RobotsRule{
						Path:   value,
						Allow:  false,
						Length: len(value),
					})
				}
			}
		case "sitemap":
			if value != "" {
				result.SitemapURLs = appendUniq(result.SitemapURLs, value)
			}
		case "crawl-delay":
			// Ghi nhận nhưng không enforce
		}
	}

	// Flush group cuối (không có dòng trống kết thúc)
	if inGroup {
		flushGroup()
	}

	return result
}

// CheckRobotsAccess quyết định một bot có được phép crawl một path không.
// Áp dụng lookup theo RFC 9309: specific UA match trước, fallback *, longest-match wins.
func CheckRobotsAccess(result *RobotsParseResult, botToken string, targetURL string) RobotsDecision {
	// Nếu 4xx (401, 403, 404,...) → RFC 9309 & Google: tất cả đều được phép
	if result.FetchStatus == RobotsStatus4xx {
		return RobotsDecision{
			Allowed:  true,
			Decision: "default_allow",
		}
	}

	// Nếu 5xx hoặc timeout → treat như blocked tạm (conservative)
	if result.FetchStatus == RobotsStatus5xx || result.FetchStatus == RobotsStatusTimeout {
		return RobotsDecision{
			Allowed:  false,
			Decision: "default_disallow",
		}
	}

	parsedTarget, err := url.Parse(targetURL)
	if err != nil || parsedTarget == nil {
		return RobotsDecision{Allowed: true, Decision: "default_allow"}
	}
	targetPath := parsedTarget.Path
	if parsedTarget.RawQuery != "" {
		targetPath += "?" + parsedTarget.RawQuery
	}

	token := strings.ToLower(botToken)

	// Tìm nhóm specific match (botToken) và nhóm wildcard (*)
	var specificGroup *RobotsGroup
	var wildcardGroup *RobotsGroup

	for i := range result.Groups {
		g := &result.Groups[i]
		for _, agent := range g.Agents {
			if agent == token {
				specificGroup = g
			}
			if agent == "*" {
				wildcardGroup = g
			}
		}
	}

	// Ưu tiên specific group, nếu không có thì dùng wildcard
	var group *RobotsGroup
	groupLabel := ""
	if specificGroup != nil {
		group = specificGroup
		groupLabel = token
	} else if wildcardGroup != nil {
		group = wildcardGroup
		groupLabel = "*"
	}

	// Không có group nào → default allow
	if group == nil {
		return RobotsDecision{Allowed: true, Decision: "default_allow"}
	}

	// Áp dụng longest-match theo RFC 9309 §2.2.2
	var bestRule *RobotsRule
	bestLen := -1

	for i := range group.Rules {
		rule := &group.Rules[i]
		if rule.Path == "" {
			// Disallow: (empty) → allow all, length 0 — chỉ áp dụng nếu không có rule nào khác
			if bestLen < 0 {
				bestRule = rule
				bestLen = 0
			}
			continue
		}
		if pathMatches(rule.Path, targetPath) {
			if rule.Length > bestLen {
				bestLen = rule.Length
				bestRule = rule
			} else if rule.Length == bestLen && bestRule != nil && rule.Allow && !bestRule.Allow {
				// Cùng độ dài: Allow thắng Disallow
				bestRule = rule
			}
		}
	}

	if bestRule == nil {
		return RobotsDecision{
			Allowed:      true,
			MatchedGroup: groupLabel,
			Decision:     "default_allow",
		}
	}

	decision := "allow"
	if !bestRule.Allow {
		decision = "disallow"
	}

	return RobotsDecision{
		Allowed:      bestRule.Allow,
		MatchedGroup: groupLabel,
		MatchedRule:  bestRule.Path,
		Decision:     decision,
	}
}

// pathMatches kiểm tra một rule path có match với target path không.
// Hỗ trợ wildcard * và ký tự kết thúc $ theo RFC 9309.
func pathMatches(pattern, target string) bool {
	// Loại bỏ fragment
	if idx := strings.Index(target, "#"); idx >= 0 {
		target = target[:idx]
	}

	// Hỗ trợ ký tự $ ở cuối pattern
	endsWith := strings.HasSuffix(pattern, "$")
	if endsWith {
		pattern = pattern[:len(pattern)-1]
	}

	return matchWildcard(pattern, target, endsWith)
}

// matchWildcard so khớp pattern có wildcard * với target.
func matchWildcard(pattern, target string, exact bool) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		// Không có wildcard
		if exact {
			return target == pattern
		}
		return strings.HasPrefix(target, pattern)
	}

	// Kiểm tra prefix đầu tiên
	if !strings.HasPrefix(target, parts[0]) {
		return false
	}
	remaining := target[len(parts[0]):]

	for i := 1; i < len(parts); i++ {
		part := parts[i]
		if i == len(parts)-1 && exact && part != "" {
			// Phần cuối cùng phải ở cuối target nếu exact
			if !strings.HasSuffix(remaining, part) {
				return false
			}
			return true
		}
		idx := strings.Index(remaining, part)
		if idx < 0 {
			return false
		}
		remaining = remaining[idx+len(part):]
	}

	if exact {
		return remaining == ""
	}
	return true
}

// appendUniq thêm phần tử vào slice nếu chưa có.
func appendUniq(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
