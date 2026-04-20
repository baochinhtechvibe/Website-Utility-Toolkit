package iana

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/singleflight"
)

var (
	// RootServerOrgs maps Root Server IPs/Hostnames to their managing organizations
	RootServerOrgs = map[string]string{
		"198.41.0.4":     "Verisign, Inc.",
		"199.9.14.201":   "University of Southern California (ISI)",
		"192.33.4.12":    "Cogent Communications",
		"199.7.91.13":    "University of Maryland",
		"192.203.230.10": "NASA (Ames Research Center)",
		"192.5.5.241":    "Internet Systems Consortium, Inc. (ISC)",
		"192.112.36.4":   "U.S. Department of Defense (NIC)",
		"198.97.190.53":  "U.S. Army (Research Lab)",
		"192.36.148.17":  "Netnod (Autonomica)",
		"192.58.128.30":  "Verisign, Inc.",
		"193.0.14.129":   "RIPE NCC",
		"199.7.83.42":    "ICANN",
		"202.12.27.33":   "WIDE Project",

		"A.ROOT-SERVERS.NET": "Verisign, Inc.",
		"B.ROOT-SERVERS.NET": "University of Southern California (ISI)",
		"C.ROOT-SERVERS.NET": "Cogent Communications",
		"D.ROOT-SERVERS.NET": "University of Maryland",
		"E.ROOT-SERVERS.NET": "NASA (Ames Research Center)",
		"F.ROOT-SERVERS.NET": "Internet Systems Consortium, Inc. (ISC)",
		"G.ROOT-SERVERS.NET": "U.S. Department of Defense (NIC)",
		"H.ROOT-SERVERS.NET": "U.S. Army (Research Lab)",
		"I.ROOT-SERVERS.NET": "Netnod (Autonomica)",
		"J.ROOT-SERVERS.NET": "Verisign, Inc.",
		"K.ROOT-SERVERS.NET": "RIPE NCC",
		"L.ROOT-SERVERS.NET": "ICANN",
		"M.ROOT-SERVERS.NET": "WIDE Project",
	}

	rdapBootstrap       sync.Map // TLD → Base RDAP URL
	tldNSBootstrap      sync.Map // TLD → TLD Nameserver IP
	registryNSBootstrap atomic.Pointer[map[string]bool]
	tldNSInflight       singleflight.Group
	rootZoneSynced      atomic.Bool
)

// Init initializes the IANA bootstrap data
func Init() {
	go func() {
		// Initial load
		if err := FetchAndCacheRDAPBootstrap(); err != nil {
			log.Warn().Err(err).Msg("IANA RDAP Bootstrap: initial load failed")
		}

		// Fetch Registry NS from Root Zone (Dùng cho WHOIS filter)
		if err := FetchAndCacheRegistryNSBootstrap(); err != nil {
			log.Warn().Err(err).Msg("IANA Registry NS Bootstrap: initial load failed")
		}

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			if err := FetchAndCacheRDAPBootstrap(); err != nil {
				log.Warn().Err(err).Msg("IANA RDAP Bootstrap: periodic refresh failed")
			}
			if err := FetchAndCacheRegistryNSBootstrap(); err != nil {
				log.Warn().Err(err).Msg("IANA Registry NS Bootstrap: periodic refresh failed")
			}
		}
	}()
}

// FetchAndCacheRDAPBootstrap loads the IANA RDAP Bootstrap JSON
func FetchAndCacheRDAPBootstrap() error {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get("https://data.iana.org/rdap/dns.json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var data struct {
		Services [][]json.RawMessage `json:"services"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return err
	}

	for _, service := range data.Services {
		if len(service) < 2 {
			continue
		}
		var tlds []string
		if err := json.Unmarshal(service[0], &tlds); err != nil {
			continue
		}
		var urls []string
		if err := json.Unmarshal(service[1], &urls); err != nil {
			continue
		}
		if len(urls) > 0 {
			baseURL := urls[0]
			if !strings.HasSuffix(baseURL, "/") {
				baseURL += "/"
			}
			for _, tld := range tlds {
				rdapBootstrap.Store(strings.ToLower(tld), baseURL)
			}
		}
	}
	log.Info().Msg("IANA Bootstrap: Loaded RDAP data")
	return nil
}

// GetRDAPURL returns the base RDAP URL for a TLD
func GetRDAPURL(tld string) string {
	if val, ok := rdapBootstrap.Load(strings.ToLower(tld)); ok {
		return val.(string)
	}
	return ""
}

// GetTLDNS returns the IP of a TLD nameserver. Uses Lazy-resolve if not cached.
func GetTLDNS(tld string) string {
	tldLower := strings.ToLower(tld)
	if val, ok := tldNSBootstrap.Load(tldLower); ok {
		return val.(string)
	}

	// Lazy Resolve with singleflight to prevent duplicate queries
	result, err, _ := tldNSInflight.Do(tldLower, func() (interface{}, error) {
		client := new(dns.Client)
		client.Timeout = 2 * time.Second

		// 1. Hỏi root server để lấy NS của TLD
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(tldLower), dns.TypeNS)
		msg.RecursionDesired = false

		// Hỏi a.root-servers.net
		resp, _, err := client.Exchange(msg, "198.41.0.4:53")
		if err != nil || resp == nil || len(resp.Ns) == 0 {
			return "", nil
		}

		var nsName string
		for _, rr := range resp.Ns {
			if ns, ok := rr.(*dns.NS); ok {
				nsName = ns.Ns
				break
			}
		}

		if nsName == "" {
			return "", nil
		}

		// 2. Resolve IP cho NS vừa tìm được
		msgA := new(dns.Msg)
		msgA.SetQuestion(nsName, dns.TypeA)
		msgA.RecursionDesired = true
		respA, _, errA := client.Exchange(msgA, "8.8.8.8:53")
		if errA == nil && respA != nil && len(respA.Answer) > 0 {
			for _, rr := range respA.Answer {
				if a, ok := rr.(*dns.A); ok {
					ip := a.A.String()
					tldNSBootstrap.Store(tldLower, ip)
					return ip, nil
				}
			}
		}

		return "", nil
	})

	if err == nil {
		if val, ok := result.(string); ok && val != "" {
			return val
		}
	}
	return ""
}

// GetAuthoritativeRDAPServer returns the record-specific RDAP URL
func GetAuthoritativeRDAPServer(domain string) string {
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return ""
	}
	tld := parts[len(parts)-1]
	baseURL := GetRDAPURL(tld)
	if baseURL != "" {
		return baseURL + "domain/" + domain
	}
	return ""
}

// FetchAndCacheRegistryNSBootstrap tải và parse file root.zone từ IANA để xác định danh sách Nameserver của Registry.
// Việc này giúp loại bỏ chính xác các Nameserver thuộc hạ tầng TLD khi tra cứu WHOIS.
func FetchAndCacheRegistryNSBootstrap() error {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get("https://www.internic.net/domain/root.zone")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("iana root zone: status %d", resp.StatusCode)
	}

	newMap := make(map[string]bool)
	count := 0
	scanner := bufio.NewScanner(resp.Body)
	// Buffer 1MB để chống panic do file zone chứa RRSIG/DNSSEC keys siêu dài
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		// Format: <tld>. <ttl> IN NS <ns>.
		// Ví dụ: com. 172800 IN NS a.gtld-servers.net.
		parts := strings.Fields(line)
		if len(parts) >= 5 && parts[2] == "in" && parts[3] == "ns" {
			owner := parts[0]
			ns := strings.TrimSuffix(parts[4], ".")

			// Chỉ lấy NS của TLD (domain chỉ có đúng 1 label trước dấu chấm cuối)
			domainLabels := strings.Split(strings.TrimSuffix(owner, "."), ".")
			if len(domainLabels) == 1 {
				newMap[ns] = true
				count++
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	// Atomic swap to new map to clear old/stale entries
	registryNSBootstrap.Store(&newMap)

	log.Info().Int("count", count).Msg("IANA Bootstrap: Loaded Registry Nameservers from root zone")
	rootZoneSynced.Store(true)
	return nil
}

// IsRegistryNS kiểm tra xem một Nameserver có phải thuộc hạ tầng quản lý TLD (Registry) không.
func IsRegistryNS(ns string) bool {
	ns = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ns), "."))

	// 1. Kiểm tra trong map được fetch động từ IANA
	if m := registryNSBootstrap.Load(); m != nil {
		if (*m)[ns] {
			return true
		}
	}

	// 2. Fallback: Đề phòng chưa fetch xong hoặc lỗi mạng
	if !rootZoneSynced.Load() {
		fallbackSuffixes := []string{
			".gtld-servers.net",
			".tld-servers.net",
			".dns-servers.vn",
			".nic.vn",
			".afilias-nst.org",
			".afilias-nst.info",
			".afilias-nst.net",
			".afilias.net",
			".donuts.co",
			".centralnic.net",
			".uniregistry.net",
			"dns1.vnnic.vn",
			"dns2.vnnic.vn",
		}
		for _, suffix := range fallbackSuffixes {
			if strings.HasSuffix(ns, suffix) {
				return true
			}
		}
	}

	return false
}
