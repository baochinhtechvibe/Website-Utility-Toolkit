package service

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tools.bctechvibe.com/server/internal/modules/ip-lookup/models"
)

var geoClient = &http.Client{
	Timeout: 5 * time.Second,
}

// GetIPDetails lấy thông tin chi tiết của một địa chỉ IP
func GetIPDetails(ctx context.Context, ipStr string, ua string) *models.IPInfo {
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
