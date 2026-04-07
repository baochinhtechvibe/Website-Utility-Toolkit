// ============================================
// FILE: security-headers/service/cookies.go
//
// Phân tích cookie bảo mật:
//   - HttpOnly flag
//   - Secure flag (khi HTTPS)
//   - SameSite attribute
//
// Parse attribute-based (tránh false positive)
// Tổng penalty cap tối đa -20
// Severity dùng worst-case ranking
// ============================================

package service

import (
	"net/http"
	"strings"

	"tools.bctechvibe.com/server/internal/modules/security-headers/models"
)

const maxCookiePenalty = 20

// severityRank map string severity → int để so sánh worst-case
var severityRank = map[string]int{
	models.SeverityGood:   0,
	models.SeverityMedium: 1,
	models.SeverityHigh:   2,
}

// worstSeverity trả về severity nghiêm trọng hơn giữa a và b
func worstSeverity(a, b string) string {
	if severityRank[a] >= severityRank[b] {
		return a
	}
	return b
}

// CookieAnalysisResult chứa output phân tích cookie
type CookieAnalysisResult struct {
	Cookies      []models.CookieResult
	HasSetCookie bool
	Penalty      int
}

// analyzeCookies parse và phân tích cookie attributes
func analyzeCookies(resp *http.Response, finalScheme string) CookieAnalysisResult {
	var cookies []models.CookieResult
	totalPenalty := 0

	rawCookies := resp.Header.Values("Set-Cookie")
	if len(rawCookies) == 0 {
		return CookieAnalysisResult{
			Cookies:      cookies,
			HasSetCookie: false,
			Penalty:      0,
		}
	}

	for _, rawCookie := range rawCookies {
		parts := strings.Split(rawCookie, ";")

		// Lấy tên cookie từ phần đầu tiên (key=value)
		cookieTuple := strings.SplitN(parts[0], "=", 2)
		cookieName := strings.TrimSpace(cookieTuple[0])
		if cookieName == "" {
			continue
		}

		// Parse attributes riêng biệt (tránh false positive)
		httpOnly := false
		secure := false
		sameSite := ""

		for _, part := range parts[1:] {
			attr := strings.TrimSpace(strings.ToLower(part))
			switch {
			case attr == "httponly":
				httpOnly = true
			case attr == "secure":
				secure = true
			case strings.HasPrefix(attr, "samesite="):
				sameSite = strings.TrimSpace(strings.TrimPrefix(attr, "samesite="))
			}
		}

		// Normalize SameSite display value
		sameSiteDisplay := "None"
		switch strings.ToLower(sameSite) {
		case "lax":
			sameSiteDisplay = "Lax"
		case "strict":
			sameSiteDisplay = "Strict"
		case "none":
			sameSiteDisplay = "None"
		}

		// Bug #3 FIX: Tính severity dùng worst-case ranking
		// Mỗi issue tự đánh giá severity riêng, sau đó lấy worst-case
		cookiePenalty := 0
		severity := models.SeverityGood

		if !httpOnly {
			cookiePenalty += 5
			severity = worstSeverity(severity, models.SeverityHigh)
		}
		if !secure && finalScheme == "https" {
			cookiePenalty += 5
			severity = worstSeverity(severity, models.SeverityHigh)
		}
		if sameSiteDisplay == "None" {
			if !secure {
				// Không có Secure → sai spec, browser reject
				cookiePenalty += 3
				severity = worstSeverity(severity, models.SeverityMedium)
			} else {
				// Có Secure → valid spec, nhưng vẫn là cross-site cookie
				// Chỉ warn nhẹ, không penalty score
				severity = worstSeverity(severity, models.SeverityMedium)
			}
		}

		totalPenalty += cookiePenalty

		cookies = append(cookies, models.CookieResult{
			Name:     cookieName,
			HttpOnly: httpOnly,
			Secure:   secure,
			SameSite: sameSiteDisplay,
			Severity: severity,
		})
	}

	// Cap penalty tối đa -20
	if totalPenalty > maxCookiePenalty {
		totalPenalty = maxCookiePenalty
	}

	return CookieAnalysisResult{
		Cookies:      cookies,
		HasSetCookie: true,
		Penalty:      totalPenalty,
	}
}
