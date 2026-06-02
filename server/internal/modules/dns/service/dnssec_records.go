/*
	File: server/internal/dns/dnssec_records.go
	Description: DNSSEC record fetching functions.
*/

package dns

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	"tools.bctechvibe.com/server/internal/modules/dns/models"

	"github.com/miekg/dns"
)

func fetchDNSSECRecords(server, fqdn string, qtype uint16) ([]dns.RR, error) {
	return fetchDNSSECRecordsContext(context.Background(), server, fqdn, qtype)
}

func fetchDNSSECRecordsContext(ctx context.Context, server, fqdn string, qtype uint16) ([]dns.RR, error) {
	resp, err := fetchDNSSECResponseContext(ctx, server, fqdn, qtype)
	if err != nil {
		return nil, err
	}
	return resp.Answer, nil
}

func fetchDNSSECResponse(server, fqdn string, qtype uint16) (*dns.Msg, error) {
	return fetchDNSSECResponseContext(context.Background(), server, fqdn, qtype)
}

func fetchDNSSECResponseContext(ctx context.Context, server, fqdn string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), qtype)
	m.SetEdns0(4096, true)

	resp, err := exchangeDNSSECQueryContext(ctx, server, m)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("máy chủ DNS không trả về phản hồi")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("máy chủ DNS trả về mã lỗi %s", dns.RcodeToString[resp.Rcode])
	}
	return resp, nil
}

func exchangeDNSSECQuery(endpoint string, msg *dns.Msg) (*dns.Msg, error) {
	return exchangeDNSSECQueryContext(context.Background(), endpoint, msg)
}

func exchangeDNSSECQueryContext(ctx context.Context, endpoint string, msg *dns.Msg) (*dns.Msg, error) {
	payload, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("máy chủ DoH trả về HTTP %d", resp.StatusCode)
	}

	body, err := readLimitedDoHBody(resp.Body)
	if err != nil {
		return nil, err
	}

	result := new(dns.Msg)
	if err := result.Unpack(body); err != nil {
		return nil, err
	}
	return result, nil
}

func fetchDNSKEYRRs(server, fqdn string) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	return fetchDNSKEYRRsContext(context.Background(), server, fqdn)
}

func fetchDNSKEYRRsContext(ctx context.Context, server, fqdn string) ([]*dns.DNSKEY, []*dns.RRSIG, error) {
	answers, err := fetchDNSSECRecordsContext(ctx, server, fqdn, dns.TypeDNSKEY)
	if err != nil {
		return nil, nil, err
	}

	var keys []*dns.DNSKEY
	var signatures []*dns.RRSIG
	for _, rr := range answers {
		switch record := rr.(type) {
		case *dns.DNSKEY:
			keys = append(keys, record)
		case *dns.RRSIG:
			if record.TypeCovered == dns.TypeDNSKEY {
				signatures = append(signatures, record)
			}
		}
	}
	return keys, signatures, nil
}

func fetchDSRRs(server, fqdn string) ([]*dns.DS, []*dns.RRSIG, dnssecDenialProof, error) {
	return fetchDSRRsContext(context.Background(), server, fqdn)
}

func fetchDSRRsContext(ctx context.Context, server, fqdn string) ([]*dns.DS, []*dns.RRSIG, dnssecDenialProof, error) {
	resp, err := fetchDNSSECResponseContext(ctx, server, fqdn, dns.TypeDS)
	if err != nil {
		return nil, nil, dnssecDenialProof{}, err
	}

	var records []*dns.DS
	var signatures []*dns.RRSIG
	for _, rr := range resp.Answer {
		switch record := rr.(type) {
		case *dns.DS:
			records = append(records, record)
		case *dns.RRSIG:
			if record.TypeCovered == dns.TypeDS {
				signatures = append(signatures, record)
			}
		}
	}

	var proof dnssecDenialProof
	for _, rr := range resp.Ns {
		switch record := rr.(type) {
		case *dns.NSEC:
			proof.nsecs = append(proof.nsecs, record)
		case *dns.NSEC3:
			proof.nsec3s = append(proof.nsec3s, record)
		case *dns.RRSIG:
			if record.TypeCovered == dns.TypeNSEC || record.TypeCovered == dns.TypeNSEC3 {
				proof.signatures = append(proof.signatures, record)
			}
		}
	}
	return records, signatures, proof, nil
}

func mapDNSKEYRecords(records []*dns.DNSKEY) []models.DNSSECRecord {
	out := make([]models.DNSSECRecord, 0, len(records))
	for _, record := range records {
		out = append(out, models.DNSSECRecord{
			Type:      "DNSKEY",
			Flags:     record.Flags,
			Protocol:  record.Protocol,
			Algorithm: record.Algorithm,
			KeyTag:    record.KeyTag(),
			PublicKey: record.PublicKey,
		})
	}
	return out
}

func mapDSRecords(records []*dns.DS) []models.DNSSECRecord {
	out := make([]models.DNSSECRecord, 0, len(records))
	for _, record := range records {
		out = append(out, models.DNSSECRecord{
			Type:       "DS",
			KeyTag:     record.KeyTag,
			Algorithm:  record.Algorithm,
			DigestType: record.DigestType,
			Digest:     record.Digest,
		})
	}
	return out
}

func mapRRSIGRecords(records []*dns.RRSIG) []models.DNSSECRecord {
	out := make([]models.DNSSECRecord, 0, len(records))
	for _, record := range records {
		out = append(out, models.DNSSECRecord{
			Type:        "RRSIG",
			TypeCovered: dns.TypeToString[record.TypeCovered],
			Algorithm:   record.Algorithm,
			KeyTag:      record.KeyTag,
			SignerName:  record.SignerName,
			Expiration:  time.Unix(int64(record.Expiration), 0),
		})
	}
	return out
}
