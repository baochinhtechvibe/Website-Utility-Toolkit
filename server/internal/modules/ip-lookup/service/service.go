package service

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"tools.bctechvibe.com/server/internal/modules/ip-lookup/models"
	"tools.bctechvibe.com/server/internal/pkg/geoip"
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
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(lookupCtx, ipStr)
	if err == nil && len(names) > 0 {
		info.Hostname = strings.TrimSuffix(names[0], ".")
	} else {
		info.Hostname = "N/A"
	}

	// Browser & OS detection (Simple parsing)
	info.Browser, info.OS = ParseUserAgent(ua)

	// GeoIP & ISP Lookup
	fillGeoInfo(ctx, info, ipStr)

	return info
}

// ResolvePublicIP kiểm tra nếu IP là local (127.0.0.1/::1) thì sẽ lấy IP Public thật của máy server.
// Giúp ích cho việc debug/test tính năng VPN khi chạy tool ở localhost.
func ResolvePublicIP(ipStr string) string {
	if ipStr == "127.0.0.1" || ipStr == "::1" || strings.HasPrefix(ipStr, "192.168.") || strings.HasPrefix(ipStr, "10.") {
		resp, err := geoClient.Get("https://api64.ipify.org")
		if err == nil {
			defer resp.Body.Close()
			ipBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
			if len(ipBytes) > 0 {
				fetchedIP := strings.TrimSpace(string(ipBytes))
				if net.ParseIP(fetchedIP) != nil {
					return fetchedIP
				}
			}
		}
	}
	return ipStr
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

func ParseUserAgent(ua string) (browser, os string) {
	ua = strings.ToLower(ua)

	// OS detection
	if strings.Contains(ua, "windows") {
		os = "Windows"
	} else if strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad") {
		os = "iOS"
	} else if strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os") {
		os = "macOS"
	} else if strings.Contains(ua, "linux") {
		os = "Linux"
	} else if strings.Contains(ua, "android") {
		os = "Android"
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
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}

	if geoip.GeoIPDB != nil {
		if city, err := geoip.GeoIPDB.City(ip); err == nil {
			info.Country = city.Country.Names["en"]
			info.CountryCode = strings.ToLower(city.Country.IsoCode)

			if len(city.Subdivisions) > 0 {
				info.Region = city.Subdivisions[0].Names["en"]
			}
			info.City = city.City.Names["en"]

			info.Latitude = city.Location.Latitude
			info.Longitude = city.Location.Longitude
			info.TimeZone = city.Location.TimeZone
		}
	}

	if geoip.GeoASNDB != nil {
		if asn, err := geoip.GeoASNDB.ASN(ip); err == nil {
			org := strings.TrimSpace(asn.AutonomousSystemOrganization)
			if org != "" {
				info.ISP = org
				info.ASN = fmt.Sprintf("AS%d", asn.AutonomousSystemNumber)
			}
		}
	}

	// Local DB doesn't have proxy/hosting/mobile boolean flags (needs GeoIP2-ISP/Anonymous DBs)
	// We set defaults for now.
	info.IsProxy = false
	info.IsHosting = false
	info.IsMobile = false
	info.Services = "N/A"
}
