package handlers

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
	"tools.bctechvibe.com/server/internal/modules/whois/service"
	"tools.bctechvibe.com/server/internal/platform/validator"
	"tools.bctechvibe.com/server/internal/response"
)

// whoisIDNAProfile dùng Lookup profile: normalize và validate theo chuẩn IDNA2008
// (subset an toàn cho WHOIS/DNS lookup — chặn ký tự không hợp lệ).
var whoisIDNAProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.ValidateLabels(true),
)

// HandleWhoisLookup xử lý GET /api/whois/lookup?domain=...&bypassCache=true
func HandleWhoisLookup(c *gin.Context) {
	domain := strings.TrimSpace(c.Query("domain"))
	bypassCacheStr := c.Query("bypassCache")
	bypassCache := bypassCacheStr == "true"

	if domain == "" {
		response.Error(c, http.StatusBadRequest, "Vui lòng nhập tên miền cần tra cứu.")
		return
	}

	// Strip http/https prefix nếu user paste URL
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "http://")
	// Strip trailing paths
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Normalize IDN (Unicode/tiếng Việt) → Punycode ASCII trước khi validate và lookup.
	// VD: "việt.vn" → "xn--vit-ula.vn", "日本語.jp" → "xn--wgv71a309e.jp"
	// Nếu domain đã là ASCII, hàm này trả nguyên không thay đổi.
	if ascii, err := whoisIDNAProfile.ToASCII(domain); err == nil {
		domain = ascii
	}
	// Lỗi normalize (ký tự không hợp lệ) → validator.IsValidDomain bên dưới sẽ reject

	// ✅ Validate domain syntax
	if !validator.IsValidDomain(domain) {
		response.Error(c, http.StatusBadRequest, "Định dạng tên miền không hợp lệ. Vui lòng kiểm tra lại.")
		return
	}

	// 🚫 Chặn IPv4/IPv6 lọt vào WHOIS
	if net.ParseIP(domain) != nil {
		response.Error(c, http.StatusBadRequest, "Vui lòng nhập tên miền hợp lệ. Chức năng WHOIS cho địa chỉ IP hiện chưa được hỗ trợ.")
		return
	}

	// Extract apex domain (eTLD+1) từ subdomain
	// VD: subdomain.bctechvibe.com → bctechvibe.com
	//     subdomain.bctechvibe.io.vn → bctechvibe.io.vn
	//     www.google.com → google.com
	// WHOIS chỉ hoạt động trên registered domain, không phải subdomain
	if apexDomain, err := publicsuffix.EffectiveTLDPlusOne(domain); err == nil {
		if apexDomain != domain {
			log.Info().
				Str("input", domain).
				Str("apex", apexDomain).
				Msg("WHOIS: input is subdomain, using apex domain")
			domain = apexDomain
		}
	}

	log.Info().Str("domain", domain).Bool("bypassCache", bypassCache).Msg("WHOIS lookup request")

	resp, meta, err := service.LookupWhois(c.Request.Context(), domain, bypassCache, c.ClientIP())
	if err != nil {
		log.Error().Err(err).Str("domain", domain).Msg("WHOIS lookup error")

		// Phân định mã lỗi HTTP theo GEMINI.md rule B-03
		msg := "Không thể tra cứu thông tin tên miền này. Vui lòng thử lại sau."
		statusCode := http.StatusOK // Mặc định 200 + success:false cho lỗi nghiệp vụ

		if whoisErr, ok := err.(*service.WhoisError); ok {
			msg = whoisErr.Message
		}

		// Context timeout → 504
		if errors.Is(err, context.DeadlineExceeded) {
			statusCode = http.StatusGatewayTimeout
			msg = "Yêu cầu tra cứu quá hạn (timeout). Vui lòng thử lại sau."
		} else if errors.Is(err, context.Canceled) {
			// Client disconnect → không cần response
			return
		}

		if statusCode == http.StatusOK {
			// Lỗi nghiệp vụ (domain not found, WHOIS server unreachable) → 200 + success:false
			response.FailWithData(c, nil, msg)
		} else {
			response.Error(c, statusCode, msg)
		}
		return
	}

	// Thành công → dùng shared response.Success
	fetchedAt, _ := time.Parse(time.RFC3339, meta.FetchedAt)
	response.Success(c, resp, meta.Cached, fetchedAt)
}
