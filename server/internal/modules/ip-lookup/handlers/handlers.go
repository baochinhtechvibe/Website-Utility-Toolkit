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
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/ip-lookup/models"
	"tools.bctechvibe.com/server/internal/response"
	"tools.bctechvibe.com/server/internal/platform/cache"
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

var (
	cachedPublicIP string
	publicIPOnce   sync.Once
)

var fallbackProviders = []string{
	"https://api.ipify.org",
	"https://api4.my-ip.io/ip",
	"https://checkip.amazonaws.com",
}

func fetchPublicIPFallback() string {
	publicIPOnce.Do(func() {
		client := &http.Client{Timeout: 2 * time.Second}
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
				cachedPublicIP = ip
				return
			}
		}
	})
	return cachedPublicIP
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

func fillGeoInfo(ctx context.Context, info *models.IPInfo, ipStr string) {
	// ip-api.com free plan chỉ hỗ trợ HTTP. Upgrade lên pro để dùng HTTPS.
	reqURL := fmt.Sprintf(
		"http://ip-api.com/json/%s?fields=status,country,countryCode,regionName,city,lat,lon,timezone,isp,as,org,proxy,hosting,mobile",
		url.PathEscape(ipStr),
	)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
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
