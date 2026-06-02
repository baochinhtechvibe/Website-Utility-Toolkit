/*
File: server/internal/dns/dnssec.go
Description: DNSSEC validation logic for domains.
*/
package dns

import (
	"context"
	"fmt"
	"strings"
	"time"

	"tools.bctechvibe.com/server/internal/modules/dns/models"

	"github.com/miekg/dns"
)

// Root trust anchors published by IANA in root-anchors.xml.
// Source: https://data.iana.org/root-anchors/root-anchors.xml
// Includes KSK-2017 and KSK-2024 for the 2026 rollover period.
var rootTrustAnchors = []*dns.DS{
	{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     20326,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest:     "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
	},
	{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeDS, Class: dns.ClassINET},
		KeyTag:     38696,
		Algorithm:  dns.RSASHA256,
		DigestType: dns.SHA256,
		Digest:     "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
	},
}

func ValidateDNSSEC(serverKey, domain string) models.DNSSECInfo {
	return ValidateDNSSECContext(context.Background(), serverKey, domain)
}

func ValidateDNSSECContext(ctx context.Context, serverKey, domain string) models.DNSSECInfo {
	endpoint := dnssecDoHEndpoint(serverKey)
	zone, err := findAuthoritativeZoneContext(ctx, endpoint, domain)
	if err != nil {
		return dnssecError("Không thể xác định zone DNS authoritative của tên miền. Vui lòng thử lại sau.")
	}

	targetRecords, result := validateDNSSECChainContext(ctx, endpoint, zone)
	result.Records = targetRecords
	return result
}

func validateDNSSECChain(server, targetZone string) ([]models.DNSSECRecord, models.DNSSECInfo) {
	return validateDNSSECChainContext(context.Background(), server, targetZone)
}

func validateDNSSECChainContext(ctx context.Context, server, targetZone string) ([]models.DNSSECRecord, models.DNSSECInfo) {
	return validateDNSSECChainWithFetcher(networkDNSSECChainFetcher{ctx: ctx, server: server}, targetZone, rootTrustAnchors)
}

type dnssecChainFetcher interface {
	DNSKEY(zone string) ([]*dns.DNSKEY, []*dns.RRSIG, error)
	DS(zone string) ([]*dns.DS, []*dns.RRSIG, dnssecDenialProof, error)
}

type dnssecDenialProof struct {
	nsecs      []*dns.NSEC
	nsec3s     []*dns.NSEC3
	signatures []*dns.RRSIG
}

type networkDNSSECChainFetcher struct {
	ctx    context.Context
	server string
}

func (f networkDNSSECChainFetcher) DNSKEY(zone string) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	return fetchDNSKEYRRsContext(f.ctx, f.server, zone)
}

func (f networkDNSSECChainFetcher) DS(zone string) ([]*dns.DS, []*dns.RRSIG, dnssecDenialProof, error) {
	return fetchDSRRsContext(f.ctx, f.server, zone)
}

func validateDNSSECChainWithFetcher(fetcher dnssecChainFetcher, targetZone string, anchors []*dns.DS) ([]models.DNSSECRecord, models.DNSSECInfo) {
	zones := buildZoneChain(targetZone)
	rootKeys, rootSignatures, err := fetcher.DNSKEY(".")
	if err != nil {
		return nil, dnssecError("Không thể truy vấn DNSKEY của Root Zone. Vui lòng thử lại sau.")
	}

	trustedRootKeys := matchingKeysForDS(rootKeys, anchors)
	if len(trustedRootKeys) == 0 {
		return nil, dnssecBogus("DNSKEY của Root Zone không khớp trust anchor IANA.")
	}
	if !hasValidRRSetSignature(dnskeyRRSet(rootKeys), rootSignatures, trustedRootKeys) {
		return nil, dnssecBogus("Chữ ký DNSKEY của Root Zone không hợp lệ.")
	}

	parentKeys := rootKeys
	var targetRecords []models.DNSSECRecord
	if len(zones) == 1 {
		targetRecords = append(mapDNSKEYRecords(rootKeys), mapRRSIGRecords(rootSignatures)...)
	}

	for _, childZone := range zones[1:] {
		dsRecords, dsSignatures, denialProof, err := fetcher.DS(childZone)
		if err != nil {
			return nil, dnssecError(fmt.Sprintf("Không thể truy vấn bản ghi DS của zone %s. Vui lòng thử lại sau.", childZone))
		}
		if len(dsRecords) == 0 {
			if !hasAuthenticatedDSDenial(childZone, denialProof, parentKeys) {
				return nil, dnssecBogus(fmt.Sprintf("Không thể xác minh an toàn rằng zone %s không công bố bản ghi DS.", childZone))
			}
			return nil, dnssecInsecure(fmt.Sprintf("Chuỗi tin cậy DNSSEC kết thúc tại zone %s vì delegation không công bố bản ghi DS.", childZone))
		}
		if len(dsSignatures) == 0 || !hasValidRRSetSignature(dsRRSet(dsRecords), dsSignatures, parentKeys) {
			return nil, dnssecBogus(fmt.Sprintf("Chữ ký DS của zone %s không hợp lệ.", childZone))
		}

		childKeys, childSignatures, err := fetcher.DNSKEY(childZone)
		if err != nil {
			return nil, dnssecError(fmt.Sprintf("Không thể truy vấn DNSKEY của zone %s. Vui lòng thử lại sau.", childZone))
		}
		matchingChildKeys := matchingKeysForDS(childKeys, dsRecords)
		if len(matchingChildKeys) == 0 {
			return nil, dnssecBogus(fmt.Sprintf("Bản ghi DS của zone %s không khớp với DNSKEY.", childZone))
		}
		if len(childSignatures) == 0 || !hasValidRRSetSignature(dnskeyRRSet(childKeys), childSignatures, matchingChildKeys) {
			return nil, dnssecBogus(fmt.Sprintf("Chữ ký DNSKEY của zone %s không hợp lệ.", childZone))
		}

		parentKeys = childKeys
		if childZone == dns.Fqdn(targetZone) {
			targetRecords = append(mapDNSKEYRecords(childKeys), mapDSRecords(dsRecords)...)
			targetRecords = append(targetRecords, mapRRSIGRecords(childSignatures)...)
		}
	}

	return targetRecords, models.DNSSECInfo{
		Enabled: true,
		Status:  "SECURE",
		Message: fmt.Sprintf("Chuỗi tin cậy DNSSEC từ Root Zone tới %s đã được xác minh hợp lệ.", dns.Fqdn(targetZone)),
	}
}

func buildZoneChain(zone string) []string {
	labels := dns.SplitDomainName(dns.Fqdn(zone))
	zones := make([]string, 1, len(labels)+1)
	zones[0] = "."
	for i := len(labels) - 1; i >= 0; i-- {
		zones = append(zones, dns.Fqdn(strings.Join(labels[i:], ".")))
	}
	return zones
}

func matchingKeysForDS(keys []*dns.DNSKEY, records []*dns.DS) []*dns.DNSKEY {
	var matches []*dns.DNSKEY
	for _, key := range keys {
		for _, record := range records {
			ds := key.ToDS(record.DigestType)
			if ds != nil &&
				ds.KeyTag == record.KeyTag &&
				ds.Algorithm == record.Algorithm &&
				strings.EqualFold(ds.Digest, record.Digest) {
				matches = append(matches, key)
				break
			}
		}
	}
	return matches
}

func hasMatchingDS(keys []*dns.DNSKEY, records []*dns.DS) bool {
	return len(matchingKeysForDS(keys, records)) > 0
}

func hasValidDNSKEYSignature(keys []*dns.DNSKEY, signatures []*dns.RRSIG) bool {
	return hasValidRRSetSignature(dnskeyRRSet(keys), signatures, keys)
}

func hasValidRRSetSignature(rrset []dns.RR, signatures []*dns.RRSIG, keys []*dns.DNSKEY) bool {
	now := time.Now()
	for _, signature := range signatures {
		if !signature.ValidityPeriod(now) {
			continue
		}
		for _, key := range keys {
			if signature.KeyTag == key.KeyTag() && signature.Verify(key, rrset) == nil {
				return true
			}
		}
	}
	return false
}

func hasAuthenticatedDSDenial(zone string, proof dnssecDenialProof, parentKeys []*dns.DNSKEY) bool {
	zone = dns.Fqdn(zone)

	for _, record := range proof.nsecs {
		if strings.EqualFold(record.Hdr.Name, zone) &&
			!typeBitmapContains(record.TypeBitMap, dns.TypeDS) &&
			hasValidRRSetSignature([]dns.RR{record}, proof.signatures, parentKeys) {
			return true
		}
	}

	for _, record := range proof.nsec3s {
		provesNoDS := record.Match(zone) && !typeBitmapContains(record.TypeBitMap, dns.TypeDS)
		provesOptOut := record.Flags&1 == 1 && record.Cover(zone)
		if (provesNoDS || provesOptOut) &&
			hasValidRRSetSignature([]dns.RR{record}, proof.signatures, parentKeys) {
			return true
		}
	}

	return false
}

func typeBitmapContains(bitmap []uint16, recordType uint16) bool {
	for _, item := range bitmap {
		if item == recordType {
			return true
		}
	}
	return false
}

func dnskeyRRSet(keys []*dns.DNSKEY) []dns.RR {
	records := make([]dns.RR, 0, len(keys))
	for _, key := range keys {
		records = append(records, key)
	}
	return records
}

func dsRRSet(records []*dns.DS) []dns.RR {
	rrset := make([]dns.RR, 0, len(records))
	for _, record := range records {
		rrset = append(rrset, record)
	}
	return rrset
}

func dnssecError(message string) models.DNSSECInfo {
	return models.DNSSECInfo{Enabled: false, Status: "ERROR", Message: message}
}

func dnssecBogus(message string) models.DNSSECInfo {
	return models.DNSSECInfo{Enabled: true, Status: "BOGUS", Message: message}
}

func dnssecInsecure(message string) models.DNSSECInfo {
	return models.DNSSECInfo{Enabled: false, Status: "INSECURE", Message: message}
}

func findAuthoritativeZone(server, domain string) (string, error) {
	return findAuthoritativeZoneContext(context.Background(), server, domain)
}

func findAuthoritativeZoneContext(ctx context.Context, server, domain string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	resp, err := exchangeDNSSECQueryContext(ctx, server, m)
	if err != nil {
		return "", err
	}
	if resp == nil {
		return "", fmt.Errorf("máy chủ DNS không trả về phản hồi")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("máy chủ DNS trả về mã lỗi %s", dns.RcodeToString[resp.Rcode])
	}

	for _, section := range [][]dns.RR{resp.Answer, resp.Ns} {
		for _, rr := range section {
			if soa, ok := rr.(*dns.SOA); ok {
				return dns.Fqdn(soa.Hdr.Name), nil
			}
		}
	}
	return "", fmt.Errorf("không tìm thấy bản ghi SOA cho tên miền")
}

func dnssecDoHEndpoint(serverKey string) string {
	server, ok := DoHServers[serverKey]
	if ok && !server.SupportsJSON {
		return server.Endpoint
	}
	return DoHServers["cloudflare"].Endpoint
}
