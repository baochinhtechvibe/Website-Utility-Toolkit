/*
	File: server/internal/dns/dnssec_records.go
	Description: DNSSEC record fetching functions.
*/

package dns

import (
	"strings"
	"time"

	"tools.bctechvibe.com/server/internal/modules/dns/models"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

func fetchDNSKEY(server, fqdn string) ([]models.DNSSECRecord, error) {
	c := &dns.Client{Timeout: 5 * time.Second}

	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeDNSKEY)
	m.SetEdns0(4096, true)

	resp, _, err := c.Exchange(m, server)
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		return nil, err
	}

	var out []models.DNSSECRecord
	for _, rr := range resp.Answer {
		if k, ok := rr.(*dns.DNSKEY); ok {
			out = append(out, models.DNSSECRecord{
				Type:      "DNSKEY",
				Flags:     k.Flags,
				Protocol:  k.Protocol,
				Algorithm: k.Algorithm,
				KeyTag:    k.KeyTag(),
				PublicKey: k.PublicKey,
			})
		}
	}

	return out, nil
}

func fetchDS(server, fqdn string) ([]models.DNSSECRecord, error) {
	parent, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(fqdn, "."))
	if err != nil {
		return nil, err
	}

	zone := dns.Fqdn(parent)

	c := &dns.Client{Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeDS)
	m.SetEdns0(4096, true)

	resp, _, err := c.Exchange(m, server)
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		return nil, err
	}

	var out []models.DNSSECRecord
	for _, rr := range resp.Answer {
		if ds, ok := rr.(*dns.DS); ok {
			out = append(out, models.DNSSECRecord{
				Type:       "DS",
				KeyTag:     ds.KeyTag,
				Algorithm:  ds.Algorithm,
				DigestType: ds.DigestType,
				Digest:     ds.Digest,
			})
		}
	}

	return out, nil
}

func fetchRRSIG(server, fqdn string, qtype uint16) ([]models.DNSSECRecord, error) {
	c := &dns.Client{Timeout: 5 * time.Second}

	m := new(dns.Msg)
	m.SetQuestion(fqdn, qtype)
	m.SetEdns0(4096, true)

	resp, _, err := c.Exchange(m, server)
	if err != nil || resp.Rcode != dns.RcodeSuccess {
		return nil, err
	}

	var out []models.DNSSECRecord
	for _, rr := range resp.Answer {
		if sig, ok := rr.(*dns.RRSIG); ok {
			out = append(out, models.DNSSECRecord{
				Type:        "RRSIG",
				TypeCovered: dns.TypeToString[sig.TypeCovered],
				Algorithm:   sig.Algorithm,
				KeyTag:      sig.KeyTag,
				SignerName:  sig.SignerName,
				Expiration:  time.Unix(int64(sig.Expiration), 0),
			})
		}
	}

	return out, nil
}
