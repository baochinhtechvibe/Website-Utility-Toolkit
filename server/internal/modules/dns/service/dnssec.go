/*
File: server/internal/dns/dnssec.go
Description: DNSSEC validation logic for domains.
*/
package dns

import (
	"fmt"
	"strings"

	"tools.bctechvibe.com/server/internal/modules/dns/models"

	"github.com/miekg/dns"
)

func ValidateDNSSEC(serverKey, domain string) models.DNSSECInfo {
	fqdn := dns.Fqdn(domain)
	udpServer := ResolveUDPServer(serverKey)

	var records []models.DNSSECRecord

	dnskeys, dnskeyErr := fetchDNSKEY(udpServer, fqdn)
	dsRecords, dsErr := fetchDS(udpServer, fqdn)
	rrsigs, rrsigErr := fetchRRSIG(udpServer, fqdn, dns.TypeDNSKEY)

	records = append(records, dnskeys...)
	records = append(records, dsRecords...)
	records = append(records, rrsigs...)

	// ❗ Lỗi nghiêm trọng: không lấy được DNSKEY và RRSIG
	if dnskeyErr != nil && rrsigErr != nil {
		return models.DNSSECInfo{
			Enabled: false,
			Status:  "ERROR",
			Message: dnskeyErr.Error(),
		}
	}

	hasDNSKEY := len(dnskeys) > 0
	hasDS := len(dsRecords) > 0
	hasRRSIG := len(rrsigs) > 0

	// ❗ Có DNSKEY nhưng không lấy được DS → broken chain
	if hasDNSKEY && !hasDS && dsErr != nil {
		return models.DNSSECInfo{
			Enabled: true,
			Status:  "BOGUS",
			Message: "DS record not found in parent zone",
			Records: records,
		}
	}

	// ✅ Secure
	if hasDNSKEY && hasDS && hasRRSIG {
		return models.DNSSECInfo{
			Enabled: true,
			Status:  "SECURE",
			Records: records,
		}
	}

	// ⚠️ DNSSEC tồn tại nhưng thiếu thành phần
	if hasDNSKEY || hasRRSIG {
		return models.DNSSECInfo{
			Enabled: true,
			Status:  "BOGUS",
			Message: buildPartialMessage(hasDNSKEY, hasDS, hasRRSIG),
			Records: records,
		}
	}

	// ❌ Không có DNSSEC
	return models.DNSSECInfo{
		Enabled: false,
		Status:  "INSECURE",
		Message: "Domain does not have DNSSEC enabled",
	}
}

func buildPartialMessage(hasDNSKEY, hasDS, hasRRSIG bool) string {
	var missing []string

	if !hasDNSKEY {
		missing = append(missing, "DNSKEY")
	}
	if !hasDS {
		missing = append(missing, "DS (parent zone)")
	}
	if !hasRRSIG {
		missing = append(missing, "RRSIG")
	}

	return fmt.Sprintf(
		"DNSSEC misconfigured, missing: %s",
		strings.Join(missing, ", "),
	)
}
