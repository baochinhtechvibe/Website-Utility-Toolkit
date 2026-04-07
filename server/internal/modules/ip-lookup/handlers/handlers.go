package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/ip-lookup/models"
	"tools.bctechvibe.com/server/internal/response"
	"tools.bctechvibe.com/server/internal/platform/cache"
)

var ipCache = cache.NewMemoryCache(30 * time.Minute)

// HandleMyIP trả về thông tin IP của người đang truy cập
func HandleMyIP(c *gin.Context) {
	clientIP := c.ClientIP()

	// Fallback cho môi trường phát triển (Localhost)
	// Luôn tự động tìm IP Public nếu Client đang truy cập từ nội bộ để có dữ liệu test mượt mà
	if isLocalIP(clientIP) {
		publicIP := fetchPublicIPFallback()
		if publicIP != "" {
			clientIP = publicIP
		}
	}

	userAgent := c.GetHeader("User-Agent")
	refresh := c.Query("refresh") == "true"
	cacheKey := "myip:" + clientIP

	if refresh {
		ipCache.Delete(cacheKey)
	} else {
		if data, fetchedAt, found := ipCache.Get(cacheKey); found {
			response.Success(c, data, true, fetchedAt)
			return
		}
	}

	now := time.Now()
	info := getIPDetails(c.Request.Context(), clientIP, userAgent)
	ipCache.Set(cacheKey, info)
	response.Success(c, info, false, now)
}

func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsPrivate()
}

var fallbackProviders = []string{
	"https://api.ipify.org",
	"https://api4.my-ip.io/ip",
	"https://checkip.amazonaws.com",
}

func fetchPublicIPFallback() string {
	const fallbackCacheKey = "public_ip_fallback"

	// Check cache first (MemoryCache đã có sẵn mutex rlock/lock nội bộ nên cực kỳ an toàn)
	if data, _, found := ipCache.Get(fallbackCacheKey); found {
		if ip, ok := data.(string); ok {
			return ip
		}
	}

	client := &http.Client{Timeout: 3 * time.Second}
	for _, urlStr := range fallbackProviders {
		resp, err := client.Get(urlStr)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			// Cache IP fallback trong 24h để đảm bảo stale data được cập nhật lại
			ipCache.SetWithTTL(fallbackCacheKey, ip, 24*time.Hour)
			return ip
		}
	}

	log.Warn().Msg("All public IP fallback providers failed")
	return ""
}


func getIPDetails(ctx context.Context, ipStr string, ua string) *models.IPInfo {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return &models.IPInfo{IP: ipStr}
	}

	version := "IPv4"
	if ip.To4() == nil {
		version = "IPv6"
	}

	info := &models.IPInfo{
		IP:        ipStr,
		Version:   version,
		Decimal:   ipToDecimal(ip),
		UserAgent: ua,
	}

	// Hostname lookup
	names, err := net.LookupAddr(ipStr)
	if err == nil && len(names) > 0 {
		info.Hostname = strings.TrimSuffix(names[0], ".")
	} else {
		info.Hostname = "N/A"
	}

	// Browser & OS detection (Simple parsing)
	info.Browser, info.OS = parseUserAgent(ua)

	// GeoIP & ISP Lookup
	fillGeoInfo(ctx, info, ipStr)

	return info
}

func ipToDecimal(ip net.IP) string {
	i := big.NewInt(0)
	if ip.To4() != nil {
		i.SetBytes(ip.To4())
	} else {
		i.SetBytes(ip.To16())
	}
	return i.String()
}

func parseUserAgent(ua string) (browser, os string) {
	ua = strings.ToLower(ua)

	// OS detection
	if strings.Contains(ua, "windows") {
		os = "Windows"
	} else if strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os") {
		os = "macOS"
	} else if strings.Contains(ua, "linux") {
		os = "Linux"
	} else if strings.Contains(ua, "android") {
		os = "Android"
	} else if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
		os = "iOS"
	} else {
		os = "Unknown"
	}

	// Browser detection - Thứ tự quan trọng
	// Edge UA thường chứa cả "chrome" và "safari", nên phải check Edge (edg/) trước Chrome.
	switch {
	case strings.Contains(ua, "edg/"):
		browser = "Edge"
	case strings.Contains(ua, "opr/") || strings.Contains(ua, "opera"):
		browser = "Opera"
	case strings.Contains(ua, "firefox"):
		browser = "Firefox"
	case strings.Contains(ua, "chrome"):
		browser = "Chrome"
	case strings.Contains(ua, "safari"):
		// Chrome trên iOS/macOS thường chứa "Safari", nên check Chrome ở trên trước
		browser = "Safari"
	default:
		browser = "Unknown"
	}

	return
}

var geoClient = &http.Client{
	Timeout: 5 * time.Second,
}

func fillGeoInfo(ctx context.Context, info *models.IPInfo, ipStr string) {
	// ip-api.com (HTTP) là lựa chọn tốt nhất để lấy dữ liệu chi tiết (ISP, AS, Proxy,...) miễn phí từ Backend
	reqURL := fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,as,org,proxy,hosting,mobile",
		url.PathEscape(ipStr),
	)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return
	}

	// Tận dụng geoClient với timeout xác định để tránh treo request
	resp, err := geoClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var data struct {
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		RegionName  string  `json:"regionName"`
		City        string  `json:"city"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		ISP         string  `json:"isp"`
		AS          string  `json:"as"`
		Org         string  `json:"org"`
		TimeZone    string  `json:"timezone"`
		Proxy       bool    `json:"proxy"`
		Hosting     bool    `json:"hosting"`
		Mobile      bool    `json:"mobile"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return
	}

	if data.Status == "success" {
		info.Country = data.Country
		info.CountryCode = strings.ToLower(data.CountryCode)
		info.Region = data.RegionName
		info.City = data.City
		info.Latitude = data.Lat
		info.Longitude = data.Lon
		info.TimeZone = data.TimeZone
		info.ISP = data.ISP
		info.ASN = data.AS

		// Metadata xịn xò từ ip-api
		info.IsProxy = data.Proxy
		info.IsHosting = data.Hosting
		info.IsMobile = data.Mobile

		// Dịch vụ mapping thông minh
		var services []string
		if data.Proxy {
			services = append(services, "VPN/Proxy")
		}
		if data.Hosting {
			services = append(services, "Hosting/Datacenter")
		}
		if data.Mobile {
			services = append(services, "Mobile Network")
		}

		if len(services) > 0 {
			info.Services = strings.Join(services, ", ")
		} else {
			info.Services = "Residential/Global"
		}
	}
}
