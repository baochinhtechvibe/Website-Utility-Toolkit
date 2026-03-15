package dns

import (
	"context"
	"strings"
	"time"

	"github.com/miekg/dns"
	"tools.bctechvibe.com/server/internal/modules/dns/models"
)

// UDPResolver implements raw DNS queries over UDP.
//
// Use cases:
//   - RBL / Blacklist lookups
//   - Low-level DNS queries
//   - Environments where DoH is not suitable
//
// Features:
//   - Configurable timeout
//   - Optional EDNS0 disable (required for many RBL providers)
type UDPResolver struct {
	Server  string        // DNS server address (ip:port)
	Timeout time.Duration // Query timeout
	NoEDNS0 bool          // Disable EDNS0 if true (recommended for RBL)
}

// Query performs a single UDP DNS query.
func (r *UDPResolver) Query(domain string, qtype uint16) ([]models.DNSRecord, error) {
	var records []models.DNSRecord

	// Default timeout
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// DNS client (UDP)
	client := &dns.Client{
		Net:     "udp",
		Timeout: timeout,
	}

	// Build DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(domain, qtype)
	msg.RecursionDesired = true

	// Enable EDNS0 only if allowed
	if !r.NoEDNS0 {
		msg.SetEdns0(4096, true)
	}

	// Hard timeout using context (CRITICAL for RBL)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Execute query
	resp, _, err := client.ExchangeContext(ctx, msg, r.Server)
	if err != nil {
		return records, err
	}

	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		return records, nil
	}

	// Parse answers
	for _, ans := range resp.Answer {
		rec := models.DNSRecord{
			Domain: domain,
			TTL:    ans.Header().Ttl,
		}

		switch rr := ans.(type) {

		case *dns.A:
			rec.Type = "A"
			rec.Address = rr.A.String()

		case *dns.AAAA:
			rec.Type = "AAAA"
			rec.Address = rr.AAAA.String()

		case *dns.CNAME:
			rec.Type = "CNAME"
			rec.Value = strings.TrimSuffix(rr.Target, ".")

		case *dns.MX:
			rec.Type = "MX"
			rec.Priority = rr.Preference
			rec.Exchange = strings.TrimSuffix(rr.Mx, ".")

		case *dns.NS:
			rec.Type = "NS"
			rec.Nameserver = strings.TrimSuffix(rr.Ns, ".")

		case *dns.TXT:
			rec.Type = "TXT"
			rec.Value = strings.Join(rr.Txt, " ")

		case *dns.PTR:
			rec.Type = "PTR"
			rec.Value = strings.TrimSuffix(rr.Ptr, ".")

		default:
			continue
		}

		records = append(records, rec)
	}

	return records, nil
}
