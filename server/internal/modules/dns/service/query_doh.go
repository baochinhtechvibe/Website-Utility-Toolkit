package dns

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"tools.bctechvibe.com/server/internal/modules/dns/models"
)

// ✅ FIX: Add Authority section to struct
type dohResponse struct {
	Status    int         `json:"Status"`
	Answer    []dohRecord `json:"Answer,omitempty"`
	Authority []dohRecord `json:"Authority,omitempty"` // ✅ NEW
}

type dohRecord struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

func (r *DoHResolver) Query(domain string, qtype uint16) ([]models.DNSRecord, error) {
	if r.SupportsJSON {
		return r.queryJSON(domain, qtype)
	}
	return r.queryRFC8484(domain, qtype)
}

func (r *DoHResolver) queryJSON(domain string, qtype uint16) ([]models.DNSRecord, error) {
	var records []models.DNSRecord

	req, err := http.NewRequest("GET", r.Endpoint, nil)
	if err != nil {
		return records, err
	}

	q := req.URL.Query()
	q.Set("name", domain)
	q.Set("type", fmt.Sprintf("%d", qtype))
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Accept", "application/dns-json")

	timeout := r.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return records, err
	}
	defer resp.Body.Close()

	var result dohResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return records, err
	}

	if result.Status != 0 {
		return records, nil
	}

	// ✅ Parse Answer section first
	for _, ans := range result.Answer {
		if rec := parseDohRecord(ans, domain); rec != nil {
			records = append(records, *rec)
		}
	}

	// ✅ FIX: Parse Authority section for NS records when Answer is empty
	// Some DNS servers return NS records in Authority section instead of Answer
	// Examples: auraperfume.com.vn, subhosting.com, and other domains with misconfigured zones
	if qtype == 2 && len(records) == 0 { // qtype 2 = NS
		for _, auth := range result.Authority {
			// Only parse NS records (type 2) from Authority section
			if auth.Type == 2 {
				if rec := parseDohRecord(auth, domain); rec != nil {
					records = append(records, *rec)
				}
			}
		}
	}

	return records, nil
}

// ✅ Helper function to parse individual DoH record
func parseDohRecord(ans dohRecord, domain string) *models.DNSRecord {
	rec := models.DNSRecord{
		Domain: domain,
		TTL:    ans.TTL,
	}

	switch ans.Type {
	case 1: // A
		rec.Type = "A"
		rec.Address = ans.Data
		return &rec

	case 28: // AAAA
		rec.Type = "AAAA"
		rec.Address = ans.Data
		return &rec

	case 5: // CNAME
		rec.Type = "CNAME"
		rec.Value = strings.TrimSuffix(ans.Data, ".")
		return &rec

	case 2: // NS
		rec.Type = "NS"
		rec.Nameserver = strings.TrimSuffix(ans.Data, ".")
		return &rec

	case 12: // PTR
		rec.Type = "PTR"
		rec.Value = strings.TrimSuffix(ans.Data, ".")
		return &rec

	case 16: // TXT
		rec.Type = "TXT"
		rec.Value = strings.Trim(ans.Data, "\"")
		return &rec

	case 15: // MX
		rec.Type = "MX"
		parts := strings.SplitN(ans.Data, " ", 2)
		if len(parts) == 2 {
			p, _ := strconv.Atoi(parts[0])
			rec.Priority = uint16(p)
			rec.Exchange = strings.TrimSuffix(parts[1], ".")
			return &rec
		}
		return nil

	default:
		return nil
	}
}

func (r *DoHResolver) queryRFC8484(domain string, qtype uint16) ([]models.DNSRecord, error) {
	var records []models.DNSRecord

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)

	payload, err := m.Pack()
	if err != nil {
		return records, err
	}

	req, err := http.NewRequest("POST", r.Endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return records, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	client := &http.Client{Timeout: r.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return records, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return records, err
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		return records, err
	}

	// ✅ Parse Answer section
	for _, ans := range msg.Answer {
		if rec := parseRFC8484Record(ans, domain); rec != nil {
			records = append(records, *rec)
		}
	}

	// ✅ FIX: Parse Authority section for NS records when Answer is empty
	if qtype == dns.TypeNS && len(records) == 0 {
		for _, auth := range msg.Ns {
			if nsRec, ok := auth.(*dns.NS); ok {
				records = append(records, models.DNSRecord{
					Type:       "NS",
					Domain:     domain,
					Nameserver: strings.TrimSuffix(nsRec.Ns, "."),
					TTL:        nsRec.Hdr.Ttl,
				})
			}
		}
	}

	return records, nil
}

// ✅ Helper function to parse RFC8484 records
func parseRFC8484Record(ans dns.RR, domain string) *models.DNSRecord {
	switch rr := ans.(type) {
	case *dns.A:
		return &models.DNSRecord{
			Type:    "A",
			Domain:  domain,
			Address: rr.A.String(),
			TTL:     rr.Hdr.Ttl,
		}
	case *dns.AAAA:
		return &models.DNSRecord{
			Type:    "AAAA",
			Domain:  domain,
			Address: rr.AAAA.String(),
			TTL:     rr.Hdr.Ttl,
		}
	case *dns.CNAME:
		return &models.DNSRecord{
			Type:   "CNAME",
			Domain: domain,
			Value:  strings.TrimSuffix(rr.Target, "."),
			TTL:    rr.Hdr.Ttl,
		}
	case *dns.MX:
		return &models.DNSRecord{
			Type:     "MX",
			Domain:   domain,
			Exchange: strings.TrimSuffix(rr.Mx, "."),
			Priority: rr.Preference,
			TTL:      rr.Hdr.Ttl,
		}
	case *dns.NS:
		return &models.DNSRecord{
			Type:       "NS",
			Domain:     domain,
			Nameserver: strings.TrimSuffix(rr.Ns, "."),
			TTL:        rr.Hdr.Ttl,
		}
	case *dns.TXT:
		return &models.DNSRecord{
			Type:   "TXT",
			Domain: domain,
			Value:  strings.Join(rr.Txt, " "),
			TTL:    rr.Hdr.Ttl,
		}
	case *dns.PTR:
		return &models.DNSRecord{
			Type:   "PTR",
			Domain: domain,
			Value:  strings.TrimSuffix(rr.Ptr, "."),
			TTL:    rr.Hdr.Ttl,
		}
	default:
		return nil
	}
}
