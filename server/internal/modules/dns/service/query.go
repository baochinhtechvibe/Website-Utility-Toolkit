// ============================================
// FILE: internal/dns/query.go
// PURPOSE:
//   - Public DNS query facade used by handlers
//   - Internally delegates to ResolverManager
//   - Keeps legacy UDP logic intact
//
// ============================================
package dns

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tools.bctechvibe.com/server/internal/modules/dns/models"

	"github.com/miekg/dns"
	"github.com/oschwald/geoip2-golang"
)

// ErrNXDOMAIN is returned when DNS server confirms domain does not exist.
// Used to short-circuit fallback chains — no point querying other servers.
var ErrNXDOMAIN = errors.New("NXDOMAIN")

var GeoIPDB *geoip2.Reader
var GeoASNDB *geoip2.Reader

// ============================================
// PUBLIC FACADE (USED BY HANDLERS)
// ============================================

// QueryDNSDirect is used for specific lookups like PTR where we explicitly want to target a DoH server.
func QueryDNSDirect(server string, domain string, qtype uint16) []interface{} {
	_, result := queryDNSDirectWithStatus(server, domain, qtype)
	return result
}

// queryDNSDirectWithStatus returns (isNXDOMAIN, records).
// isNXDOMAIN=true means the server authoritatively confirmed the domain does not exist.
func queryDNSDirectWithStatus(server string, domain string, qtype uint16) (bool, []interface{}) {
	doh, ok := DoHServers[server]
	if !ok {
		doh = DoHServers["cloudflare"]
	}
	rm := NewResolverManager(doh, &UDPResolver{Server: "8.8.8.8:53", Timeout: 5 * time.Second})
	records, err := rm.Resolve(domain, qtype, "doh")
	if err != nil {
		if errors.Is(err, ErrNXDOMAIN) {
			return true, []interface{}{}
		}
		return false, []interface{}{}
	}
	result := make([]interface{}, 0, len(records))
	for i := range records {
		rec := records[i]
		switch rec.Type {
		case "A", "AAAA":
			ip := net.ParseIP(rec.Address)
			if ip != nil {
				enrichIPInfo(&rec, ip)
			}
		case "PTR":
			EnrichIPInfoByString(&rec, rec.Value)
		}
		result = append(result, rec)
	}
	return false, result
}

// isSuspendedOrNotFound checks if an error from the resolver indicates a potential domain suspension or NXDOMAIN
func isSuspendedOrNotFound(err error, records []models.DNSRecord) bool {
	if err != nil && (strings.Contains(err.Error(), "NXDOMAIN") || strings.Contains(err.Error(), "SERVFAIL")) {
		return true
	}
	return len(records) == 0 && err == nil
}

// queryTLDServer traces the authorities for a domain using Root servers
// Since this is a utility tool, we can perform a basic implementation or fallback to google.
// Note: true Root DNS tracing is complex. To keep it robust, we use Google and OpenDNS as immediate fallbacks.
// If all fail, it returns an empty slice.
func QueryDNS(domain string, qtype uint16) ([]interface{}, string) {
	// 1. Thử Cloudflare trước (Nhanh, đầy đủ nhất)
	isNX, recordsCloudflare := queryDNSDirectWithStatus("cloudflare", domain, qtype)
	if len(recordsCloudflare) > 0 {
		return recordsCloudflare, "cloudflare"
	}
	// NXDOMAIN = domain chắc chắn không tồn tại → không cần hỏi server khác
	if isNX {
		return []interface{}{}, "cloudflare"
	}

	// 2. Chuỗi Fallback dự phòng (Quad9 -> Google -> OpenDNS)
	fallbacks := []string{"quad9", "google", "opendns"}
	for _, fb := range fallbacks {
		isNX, recordsFB := queryDNSDirectWithStatus(fb, domain, qtype)
		if len(recordsFB) > 0 {
			return recordsFB, fb
		}
		if isNX {
			return []interface{}{}, fb
		}
	}

	// 3. Tất cả server đều fail hoặc không có record
	return []interface{}{}, "none"
}

// ============================================
// LEGACY / LOW-LEVEL UDP IMPLEMENTATION
// ============================================

// QueryDNSUDP performs a raw DNS query over UDP.
//
// This function is kept for:
//   - Low-level access
//   - Debugging
//   - Future explicit UDP endpoints
func QueryDNSUDP(server, domain string, qtype uint16) []interface{} {
	var records []interface{}

	client := new(dns.Client)
	client.Timeout = 5 * time.Second

	msg := new(dns.Msg)
	msg.SetQuestion(domain, qtype)
	msg.RecursionDesired = true
	msg.SetEdns0(4096, true)

	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		log.Printf("DNS query error for %s (type %d): %v", domain, qtype, err)
		return records
	}

	if resp.Rcode != dns.RcodeSuccess {
		log.Printf("DNS query failed for %s (type %d): Rcode=%d", domain, qtype, resp.Rcode)
		return records
	}

	log.Printf("DNS query success for %s (type %d): %d answers", domain, qtype, len(resp.Answer))

	// Parse answers
	for _, answer := range resp.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			record := models.DNSRecord{
				Type:    "A",
				Address: rr.A.String(),
				TTL:     rr.Hdr.Ttl,
			}
			enrichIPInfo(&record, rr.A)
			records = append(records, record)

		case *dns.AAAA:
			record := models.DNSRecord{
				Type:    "AAAA",
				Address: rr.AAAA.String(),
				TTL:     rr.Hdr.Ttl,
			}
			enrichIPInfo(&record, rr.AAAA)
			records = append(records, record)

		case *dns.NS:
			records = append(records, models.DNSRecord{
				Type:       "NS",
				Nameserver: rr.Ns,
				TTL:        rr.Hdr.Ttl,
			})

		case *dns.MX:
			records = append(records, models.DNSRecord{
				Type:     "MX",
				Exchange: rr.Mx,
				Priority: rr.Preference,
				TTL:      rr.Hdr.Ttl,
			})

		case *dns.CNAME:
			records = append(records, models.DNSRecord{
				Type:  "CNAME",
				Value: rr.Target,
				TTL:   rr.Hdr.Ttl,
			})

		case *dns.TXT:
			txtValue := strings.Join(rr.Txt, " ")
			records = append(records, models.DNSRecord{
				Type:  "TXT",
				Value: txtValue,
				TTL:   rr.Hdr.Ttl,
			})

		case *dns.PTR:
			record := models.DNSRecord{
				Type:  "PTR",
				Value: rr.Ptr,
				TTL:   rr.Hdr.Ttl,
			}
			records = append(records, record)

		default:
			log.Printf("Unknown record type: %T", rr)
		}
	}

	return records
}

// ============================================
// GEO-IP HELPERS (UNCHANGED)
// ============================================

func enrichIPInfo(record *models.DNSRecord, ip net.IP) {
	if GeoIPDB != nil {
		if city, err := GeoIPDB.City(ip); err == nil {
			record.Country = city.Country.Names["en"]
			record.CountryCode = strings.ToLower(city.Country.IsoCode)
		}
	}

	if GeoASNDB != nil {
		if asn, err := GeoASNDB.ASN(ip); err == nil {
			org := strings.TrimSpace(asn.AutonomousSystemOrganization)
			if org != "" {
				record.Org = org
				record.ISP = org
			}
		}
	}

	// Task 1: Skip external API if local DB is available, even if it failed for this specific IP.
	// This avoids 3s latency per record in the trace path.
	if GeoIPDB != nil || GeoASNDB != nil {
		return
	}

	geoInfo := getGeoIPInfo(ip.String())
	if geoInfo != nil {
		record.Country = geoInfo.Country
		record.CountryCode = strings.ToLower(geoInfo.CountryCode)
		record.ISP = geoInfo.ISP
		record.Org = geoInfo.Org
	}
}

func EnrichIPInfoByString(record *models.DNSRecord, ipStr string) {
	ip := net.ParseIP(ipStr)
	if ip != nil {
		enrichIPInfo(record, ip)
	}
}

type GeoIPInfo struct {
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
}

func getGeoIPInfo(ip string) *GeoIPInfo {
	client := &http.Client{Timeout: 3 * time.Second}
	// Note: ip-api.com Free Tier ONLY supports HTTP. HTTPS will return 403.
	urlStr := fmt.Sprintf("http://ip-api.com/json/%s?fields=country,countryCode,isp,org", url.PathEscape(ip))
	resp, err := client.Get(urlStr)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var info GeoIPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil
	}
	return &info
}
