package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"golang.org/x/net/publicsuffix"
	"tools.bctechvibe.com/server/internal/modules/whois/models"
	"tools.bctechvibe.com/server/internal/modules/whois/service"
	"tools.bctechvibe.com/server/internal/platform/validator"
)

// HandleWhoisLookup xử lý GET /api/whois/lookup?domain=...&bypassCache=true
func HandleWhoisLookup(c *gin.Context) {
	domain := strings.TrimSpace(c.Query("domain"))
	bypassCacheStr := c.Query("bypassCache")
	bypassCache := bypassCacheStr == "true"

	if domain == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Vui lòng nhập tên miền cần tra cứu.",
		})
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

	// ✅ Validate domain syntax
	if !validator.IsValidDomain(domain) {
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Định dạng tên miền không hợp lệ. Vui lòng kiểm tra lại.",
		})
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
		
		// Mask internal errors, show only friendly messages
		msg := "Không thể tra cứu thông tin tên miền này. Vui lòng thử lại sau."
		if whoisErr, ok := err.(*service.WhoisError); ok {
			msg = whoisErr.Message
		}

		c.JSON(http.StatusOK, models.APIResponse{
			Success: false,
			Message: msg,
		})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Tra cứu WHOIS thành công.",
		Data:    resp,
		Meta:    meta,
	})
}
