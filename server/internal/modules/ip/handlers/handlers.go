package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/ip/models"
	"tools.bctechvibe.com/server/internal/response"
	"tools.bctechvibe.com/server/pkg/cache"
)

var ipCache = cache.NewMemoryCache(30 * time.Minute)

// HandleMyIP trả về thông tin IP của người đang truy cập
func HandleMyIP(c *gin.Context) {
	clientIP := c.ClientIP()

	// Fallback cho môi trường phát triển (Localhost)
	if isLocalIP(clientIP) {
		publicIP := fetchPublicIPFallback()
		if publicIP != "" {
			clientIP = publicIP
		}
	}

	userAgent := c.GetHeader("User-Agent")
	refresh := c.Query("refresh") == "true"
	cacheKey := clientIP

	if refresh {
		ipCache.Delete(cacheKey)
	} else {
		if data, fetchedAt, found := ipCache.Get(cacheKey); found {
			response.Success(c, data, true, fetchedAt)
			return
		}
	}

	info := getIPDetails(clientIP, userAgent)
	ipCache.Set(cacheKey, info)
	response.Success(c, info, false, time.Now())
}

func isLocalIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	// Check private ranges (10.x, 172.16.x, 192.168.x)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 ||
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) ||
			(ip4[0] == 192 && ip4[1] == 168)
	}
	return false
}

func fetchPublicIPFallback() string {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("https://api.ipify.org")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// HandleIPLookup trả về thông tin chi tiết cho một IP cụ thể
func HandleIPLookup(c *gin.Context) {
	targetIP := c.Param("ip")
	if targetIP == "" {
		response.Error(c, http.StatusBadRequest, "IP address is required")
		return
	}

	userAgent := c.GetHeader("User-Agent")
	refresh := c.Query("refresh") == "true"
	cacheKey := targetIP

	if refresh {
		ipCache.Delete(cacheKey)
	} else {
		if data, fetchedAt, found := ipCache.Get(cacheKey); found {
			response.Success(c, data, true, fetchedAt)
			return
		}
	}

	info := getIPDetails(targetIP, userAgent)
	ipCache.Set(cacheKey, info)
	response.Success(c, info, false, time.Now())
}

func getIPDetails(ipStr string, ua string) *models.IPInfo {
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
		FetchedAt: time.Now(),
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

	// GeoIP & ISP Lookup (Reuse from DNS module for now)
	// Note: dnsService.EnrichIPInfoByString expects a *models.DNSRecord,
	// we might need a more generic helper or manually fill it.
	// For now, let's use the same logic as in dnsService.getGeoIPInfo
	fillGeoInfo(info, ipStr)

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

	// Browser detection
	if strings.Contains(ua, "edg/") {
		browser = "Edge"
	} else if strings.Contains(ua, "opr/") || strings.Contains(ua, "opera") {
		browser = "Opera"
	} else if strings.Contains(ua, "chrome") {
		browser = "Chrome"
	} else if strings.Contains(ua, "firefox") {
		browser = "Firefox"
	} else if strings.Contains(ua, "safari") {
		browser = "Safari"
	} else {
		browser = "Unknown"
	}

	return
}

func fillGeoInfo(info *models.IPInfo, ipStr string) {
	// Call the same logic as DNS module
	// Since we don't want to duplicate logic, but can't easily refactor dns module now
	// We'll just call the public/internal methods if available.
	// Actually, I'll implement a local version of getGeoIPInfo here
	// or move getGeoIPInfo to a common package.

	// For now, let's call the ip-api as a fallback like DNS module does.
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,as,org,proxy,hosting,mobile",
		ipStr,
	))
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var data struct {
		Status      string  `json:"status"`
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

		// Detection logic for VPN/Hosting
		if data.Proxy || data.Hosting {
			info.Services = "VPN Server"
		} else {
			info.Services = "N/A"
		}
	}
}
