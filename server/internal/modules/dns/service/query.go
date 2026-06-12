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
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"tools.bctechvibe.com/server/internal/modules/dns/models"
	"tools.bctechvibe.com/server/internal/pkg/geoip"

	"github.com/miekg/dns"
)

// ErrNXDOMAIN is returned when DNS server confirms domain does not exist.
// Used to short-circuit fallback chains — no point querying other servers.
var ErrNXDOMAIN = errors.New("NXDOMAIN")
var ErrSERVFAIL = errors.New("SERVFAIL")
var ErrREFUSED = errors.New("REFUSED")
var ErrFORMERR = errors.New("FORMERR")

// ============================================
// PUBLIC FACADE (USED BY HANDLERS)
// ============================================

// QueryDNSDirect is used for specific lookups like PTR where we explicitly want to target a DoH server.
func QueryDNSDirect(server string, domain string, qtype uint16) ([]interface{}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return QueryDNSDirectContext(ctx, server, domain, qtype)
}

func QueryDNSDirectContext(ctx context.Context, server string, domain string, qtype uint16) ([]interface{}, error) {
	err, result := queryDNSDirectWithStatus(ctx, server, domain, qtype)
	return result, err
}

// queryDNSDirectWithStatus returns (error, records).
// If error is nil, the query was successful.
func queryDNSDirectWithStatus(ctx context.Context, server string, domain string, qtype uint16) (error, []interface{}) {
	doh, ok := DoHServers[server]
	if !ok {
		doh = DoHServers["cloudflare"]
	}
	rm := NewResolverManager(doh, &UDPResolver{Server: "8.8.8.8:53", Timeout: 5 * time.Second})
	records, err := rm.ResolveContext(ctx, domain, qtype, "doh")
	if err != nil {
		return err, []interface{}{}
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
	return nil, result
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
func QueryDNS(domain string, qtype uint16) ([]interface{}, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return QueryDNSContext(ctx, domain, qtype)
}

func QueryDNSContext(ctx context.Context, domain string, qtype uint16) ([]interface{}, string, error) {
	if err := ctx.Err(); err != nil {
		return []interface{}{}, "none", err
	}

	// 1. Thử Google trước (Google trả về đầy đủ các bản ghi A round-robin hơn Cloudflare)
	errGoogle, recordsGoogle := queryDNSDirectWithStatus(ctx, "google", domain, qtype)
	if len(recordsGoogle) > 0 {
		return recordsGoogle, "google", nil
	}
	// NXDOMAIN = domain chắc chắn không tồn tại → không cần hỏi server khác
	if errors.Is(errGoogle, ErrNXDOMAIN) {
		return []interface{}{}, "google", errGoogle
	}

	// 2. Chuỗi Fallback dự phòng (Cloudflare -> Quad9 -> OpenDNS)
	fallbacks := []string{"cloudflare", "quad9", "opendns"}
	var lastErr error = errGoogle

	for _, fb := range fallbacks {
		if err := ctx.Err(); err != nil {
			return []interface{}{}, "none", err
		}
		errFB, recordsFB := queryDNSDirectWithStatus(ctx, fb, domain, qtype)
		if len(recordsFB) > 0 {
			return recordsFB, fb, nil
		}
		if errors.Is(errFB, ErrNXDOMAIN) {
			return []interface{}{}, fb, errFB
		}
		if errFB != nil {
			lastErr = errFB
		}
	}

	// 3. Tất cả server đều fail hoặc không có record
	return []interface{}{}, "none", lastErr
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
	if geoip.GeoIPDB != nil {
		if city, err := geoip.GeoIPDB.City(ip); err == nil {
			record.Country = city.Country.Names["en"]
			record.CountryCode = strings.ToLower(city.Country.IsoCode)
		}
	}

	if geoip.GeoASNDB != nil {
		if asn, err := geoip.GeoASNDB.ASN(ip); err == nil {
			org := strings.TrimSpace(asn.AutonomousSystemOrganization)
			
			// Attempt to get shorter AS name from Team Cymru DNS
			if asn.AutonomousSystemNumber > 0 {
				if shortName := getCymruASName(asn.AutonomousSystemNumber); shortName != "" {
					org = shortName
				}
			}

			if org != "" {
				record.Org = org
				record.ISP = org
			}
		}
	}

	// GeoIP enrichment is intentionally local-only. DNS lookups must not leak
	// queried addresses to a third-party HTTP service when MMDB files are absent.
}

func EnrichIPInfoByString(record *models.DNSRecord, ipStr string) {
	ip := net.ParseIP(ipStr)
	if ip != nil {
		enrichIPInfo(record, ip)
	}
}

// getCymruASName queries Team Cymru DNS to get a short AS Name (e.g. VNNIC-AS-VN)
func getCymruASName(asn uint) string {
	if asn == 0 {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	query := fmt.Sprintf("AS%d.asn.cymru.com", asn)
	var resolver net.Resolver
	txtRecords, err := resolver.LookupTXT(ctx, query)
	if err != nil || len(txtRecords) == 0 {
		return ""
	}

	// Format: "45944 | VN | apnic | 2002-08-28 | VNNIC-AS-VN, VN"
	parts := strings.Split(txtRecords[0], "|")
	if len(parts) >= 5 {
		asInfo := strings.TrimSpace(parts[4])
		
		// "VNNIC-AS-VN, VN" -> extract "VNNIC-AS-VN"
		nameParts := strings.Split(asInfo, ",")
		if len(nameParts) > 0 {
			return strings.TrimSpace(nameParts[0])
		}
		return asInfo
	}
	return ""
}
