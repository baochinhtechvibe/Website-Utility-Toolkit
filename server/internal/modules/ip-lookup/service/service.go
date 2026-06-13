package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"tools.bctechvibe.com/server/internal/modules/ip-lookup/models"
	"tools.bctechvibe.com/server/internal/pkg/geoip"
)

var geoClient = &http.Client{
	Timeout: 15 * time.Second,
}

// GetIPDetails lấy thông tin chi tiết của một địa chỉ IP
func GetIPDetails(ctx context.Context, ipStr string, ua string, mode string) *models.IPInfo {
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
	fillGeoInfo(ctx, info, ipStr, mode)

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

func fillGeoInfo(ctx context.Context, info *models.IPInfo, ipStr string, mode string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}

	// Tầng 1: Local DB
	if geoip.GeoIPDB != nil {
		if city, err := geoip.GeoIPDB.City(ip); err == nil {
			info.Country = city.Country.Names["en"]
			info.CountryCode = strings.ToLower(city.Country.IsoCode)

			if len(city.Subdivisions) > 0 {
				info.Region = city.Subdivisions[0].Names["en"]
			}
			info.City = city.City.Names["en"]
			info.PostalCode = city.Postal.Code

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

	info.IsProxy = false
	info.IsHosting = false
	info.IsMobile = false
	info.Services = "N/A"

	// Nếu mode=fast, dừng tại đây để trả kết quả ngay (chỉ có MaxMind)
	if mode == "fast" {
		return
	}

	// Đặt timeout tổng cộng 15s cho toàn bộ các API external
	timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// Tầng 3: API Key (IPData)
	apiKey := os.Getenv("IPDATA_API_KEY")
	enriched := false
	if apiKey != "" {
		enriched = enrichFromIPData(timeoutCtx, info, ipStr, apiKey)
	}

	// Tầng 2: Fallback API (ipwhois.app & freeipapi & ipapi.is) chạy song song
	if !enriched || info.City == "" || info.City == "N/A" || info.Region == "" || info.Region == "N/A" || info.PostalCode == "" || info.Services == "N/A" {
		enrichFallbackParallel(timeoutCtx, info, ipStr)
	}

	// Format lại TimeZone (ví dụ: Asia/Ho_Chi_Minh - UTC +07:00)
	if info.TimeZone != "" && info.TimeZone != "N/A" && !strings.Contains(info.TimeZone, "UTC") {
		info.TimeZone = formatTimeZone(info.TimeZone)
	}
}

type IPDataResponse struct {
	City        string  `json:"city"`
	Region      string  `json:"region"`
	CountryName string  `json:"country_name"`
	CountryCode string  `json:"country_code"`
	Postal      string  `json:"postal"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	TimeZone    struct {
		Name string `json:"name"`
	} `json:"time_zone"`
	ASN struct {
		Asn  string `json:"asn"`
		Name string `json:"name"`
	} `json:"asn"`
	Threat struct {
		IsProxy      bool `json:"is_proxy"`
		IsTor        bool `json:"is_tor"`
		IsDatacenter bool `json:"is_datacenter"`
		IsAnonymous  bool `json:"is_anonymous"`
		IsVpn        bool `json:"is_vpn"`
	} `json:"threat"`
}

func enrichFromIPData(ctx context.Context, info *models.IPInfo, ipStr, apiKey string) bool {
	url := fmt.Sprintf("https://api.ipdata.co/%s?api-key=%s", ipStr, apiKey)
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := geoClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return false
	}

	var data IPDataResponse
	bodyReader := io.LimitReader(resp.Body, 64*1024)
	if err := json.NewDecoder(bodyReader).Decode(&data); err == nil {
		if data.City != "" {
			info.City = data.City
		}
		if data.Region != "" {
			info.Region = data.Region
		}
		if data.CountryName != "" {
			info.Country = data.CountryName
		}
		if data.CountryCode != "" {
			info.CountryCode = strings.ToLower(data.CountryCode)
		}
		if data.Postal != "" {
			info.PostalCode = data.Postal
		}
		if data.Latitude != 0 {
			info.Latitude = data.Latitude
		}
		if data.Longitude != 0 {
			info.Longitude = data.Longitude
		}
		if data.TimeZone.Name != "" {
			info.TimeZone = data.TimeZone.Name
		}

		if data.ASN.Name != "" {
			info.ISP = data.ASN.Name
			info.ASN = data.ASN.Asn
		}

		info.IsProxy = data.Threat.IsProxy || data.Threat.IsTor || data.Threat.IsAnonymous || data.Threat.IsVpn
		info.IsHosting = data.Threat.IsDatacenter

		var services []string
		if info.IsProxy {
			services = append(services, "VPN Server")
		}
		if info.IsHosting {
			services = append(services, "Datacenter/Hosting")
		}
		if len(services) > 0 {
			info.Services = strings.Join(services, ", ")
		} else {
			info.Services = "N/A"
		}
		return true
	}
	return false
}

type IPWhoisResponse struct {
	Success     bool    `json:"success"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	Region      string  `json:"region"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	Timezone    string  `json:"timezone"`
}

type FreeIPAPIResponse struct {
	CityName    string  `json:"cityName"`
	RegionName  string  `json:"regionName"`
	CountryName string  `json:"countryName"`
	CountryCode string  `json:"countryCode"`
	ZipCode     string  `json:"zipCode"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	TimeZone    string  `json:"timeZone"`
	IsProxy     bool    `json:"isProxy"`
}

type IPAPIISResponse struct {
	Location struct {
		CountryCode string  `json:"country_code"`
		Country     string  `json:"country"`
		State       string  `json:"state"`
		City        string  `json:"city"`
		Zip         string  `json:"zip"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		Timezone    string  `json:"timezone"`
	} `json:"location"`
	IsVpn   bool `json:"is_vpn"`
	IsProxy bool `json:"is_proxy"`
	IsTor   bool `json:"is_tor"`
}

var (
	fallbackMutex    sync.Mutex
	ipwhoisBackoff   time.Time
	freeipapiBackoff time.Time
	ipapiisBackoff   time.Time
)

func enrichFallbackParallel(ctx context.Context, info *models.IPInfo, ipStr string) {
	var wg sync.WaitGroup
	var whoisData *IPWhoisResponse
	var freeData *FreeIPAPIResponse
	var isData *IPAPIISResponse

	// Luồng 1: Gọi ipwhois.app

	wg.Add(1)
	go func() {
		defer wg.Done()
		fallbackMutex.Lock()
		if time.Now().Before(ipwhoisBackoff) {
			fallbackMutex.Unlock()
			return
		}
		fallbackMutex.Unlock()

		url := fmt.Sprintf("https://ipwhois.app/json/%s", ipStr)
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := geoClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
			fallbackMutex.Lock()
			ipwhoisBackoff = time.Now().Add(1 * time.Minute)
			fallbackMutex.Unlock()
			return
		}
		if resp.StatusCode == 200 {
			var data IPWhoisResponse
			bodyReader := io.LimitReader(resp.Body, 64*1024)
			if err := json.NewDecoder(bodyReader).Decode(&data); err == nil && data.Success {
				whoisData = &data
			}
		}
	}()

	// Luồng 2: Gọi freeipapi.com
	wg.Add(1)
	go func() {
		defer wg.Done()
		fallbackMutex.Lock()
		if time.Now().Before(freeipapiBackoff) {
			fallbackMutex.Unlock()
			return
		}
		fallbackMutex.Unlock()

		url := fmt.Sprintf("https://free.freeipapi.com/api/json/%s", ipStr)
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := geoClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			fallbackMutex.Lock()
			freeipapiBackoff = time.Now().Add(1 * time.Minute)
			fallbackMutex.Unlock()
			return
		}
		if resp.StatusCode == 200 {
			var data FreeIPAPIResponse
			bodyReader := io.LimitReader(resp.Body, 64*1024)
			if err := json.NewDecoder(bodyReader).Decode(&data); err == nil {
				freeData = &data
			}
		}
	}()

	// Luồng 3: Gọi ipapi.is (Chính xác cao, trả về được Zip Code cực xịn)
	wg.Add(1)
	go func() {
		defer wg.Done()
		fallbackMutex.Lock()
		if time.Now().Before(ipapiisBackoff) {
			fallbackMutex.Unlock()
			return
		}
		fallbackMutex.Unlock()

		url := fmt.Sprintf("https://api.ipapi.is/?q=%s", ipStr)
		req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
		resp, err := geoClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusForbidden {
			fallbackMutex.Lock()
			ipapiisBackoff = time.Now().Add(1 * time.Minute)
			fallbackMutex.Unlock()
			return
		}
		if resp.StatusCode == 200 {
			var data IPAPIISResponse
			bodyReader := io.LimitReader(resp.Body, 64*1024)
			if err := json.NewDecoder(bodyReader).Decode(&data); err == nil {
				isData = &data
			}
		}
	}()

	wg.Wait()

	// Gộp dữ liệu: Ưu tiên IPAPI.IS -> IPWhois -> FreeIPAPI
	if isData != nil {
		if isData.Location.City != "" { info.City = isData.Location.City }
		if isData.Location.State != "" { info.Region = isData.Location.State }
		if isData.Location.Country != "" { info.Country = isData.Location.Country }
		if isData.Location.CountryCode != "" { info.CountryCode = strings.ToLower(isData.Location.CountryCode) }
		if isData.Location.Latitude != 0 { info.Latitude = isData.Location.Latitude }
		if isData.Location.Longitude != 0 { info.Longitude = isData.Location.Longitude }
		if isData.Location.Timezone != "" { info.TimeZone = isData.Location.Timezone }
		if isData.Location.Zip != "" { info.PostalCode = isData.Location.Zip }
		
		if isData.IsProxy || isData.IsVpn || isData.IsTor {
			info.IsProxy = true
			if info.Services == "N/A" {
				info.Services = "VPN Server"
			} else if !strings.Contains(info.Services, "VPN Server") {
				info.Services = "VPN Server, " + info.Services
			}
		}
	}

	if whoisData != nil {
		if info.City == "" || info.City == "N/A" {
			if whoisData.City != "" { info.City = whoisData.City }
		}
		if info.Region == "" || info.Region == "N/A" {
			if whoisData.Region != "" { info.Region = whoisData.Region }
		}
		if info.Country == "" || info.Country == "N/A" {
			if whoisData.Country != "" { info.Country = whoisData.Country }
		}
		if info.CountryCode == "" || info.CountryCode == "N/A" {
			if whoisData.CountryCode != "" { info.CountryCode = strings.ToLower(whoisData.CountryCode) }
		}
		if info.Latitude == 0 {
			if whoisData.Latitude != 0 { info.Latitude = whoisData.Latitude }
		}
		if info.Longitude == 0 {
			if whoisData.Longitude != 0 { info.Longitude = whoisData.Longitude }
		}
		if info.TimeZone == "" || info.TimeZone == "N/A" {
			if whoisData.Timezone != "" { info.TimeZone = whoisData.Timezone }
		}
	}

	if freeData != nil {
		// Tránh lỗi "râu ông nọ cắm cằm bà kia": Chỉ lấy Zip Code của freeipapi nếu nó cùng Region với ipapi.is hoặc ipwhois
		isSameRegion := true
		if freeData.RegionName != "" && info.Region != "" && info.Region != "N/A" {
			// So sánh tương đối (VD: "Gia Lai" vs "Binh Dinh Province")
			regionFree := strings.ToLower(freeData.RegionName)
			regionCurrent := strings.ToLower(info.Region)
			if !strings.Contains(regionCurrent, regionFree) && !strings.Contains(regionFree, regionCurrent) {
				isSameRegion = false
			}
		}

		if freeData.ZipCode != "" && freeData.ZipCode != "-" && info.PostalCode == "" && isSameRegion {
			info.PostalCode = freeData.ZipCode
		}
		if info.City == "" || info.City == "N/A" {
			if freeData.CityName != "" && freeData.CityName != "-" {
				info.City = freeData.CityName
			}
		}
		if info.Region == "" || info.Region == "N/A" {
			if freeData.RegionName != "" && freeData.RegionName != "-" {
				info.Region = freeData.RegionName
			}
		}
		if info.TimeZone == "" || info.TimeZone == "N/A" {
			if freeData.TimeZone != "" && freeData.TimeZone != "-" {
				info.TimeZone = freeData.TimeZone
			}
		}
		if freeData.IsProxy {
			info.IsProxy = true
			if info.Services == "N/A" {
				info.Services = "VPN Server"
			} else if !strings.Contains(info.Services, "VPN Server") {
				info.Services = "VPN Server, " + info.Services
			}
		}
	}
}

func formatTimeZone(tz string) string {
	if tz == "" || tz == "N/A" {
		return tz
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return tz
	}
	t := time.Now().In(loc)
	_, offset := t.Zone()

	hours := offset / 3600
	mins := (offset % 3600) / 60
	if mins < 0 {
		mins = -mins
	}

	return fmt.Sprintf("%s - UTC %+03d:%02d", tz, hours, mins)
}
