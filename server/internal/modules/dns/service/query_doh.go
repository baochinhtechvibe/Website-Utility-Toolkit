package dns

import (
	"bytes"
	"context"
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

var dohClient *http.Client

func init() {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxConnsPerHost = 100
	t.MaxIdleConnsPerHost = 100
	t.IdleConnTimeout = 90 * time.Second

	dohClient = &http.Client{
		Transport: t,
		// Timeout is handled by request context
	}
}

const maxDoHResponseBody = 1024 * 1024

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
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return r.QueryContext(ctx, domain, qtype)
}

func (r *DoHResolver) QueryContext(ctx context.Context, domain string, qtype uint16) ([]models.DNSRecord, error) {
	if r.SupportsJSON {
		return r.queryJSON(ctx, domain, qtype)
	}
	return r.queryRFC8484(ctx, domain, qtype)
}

func (r *DoHResolver) queryJSON(ctx context.Context, domain string, qtype uint16) ([]models.DNSRecord, error) {
	var records []models.DNSRecord

	req, err := http.NewRequestWithContext(ctx, "GET", r.Endpoint, nil)
	if err != nil {
		return records, err
	}

	q := req.URL.Query()
	q.Set("name", domain)
	q.Set("type", fmt.Sprintf("%d", qtype))
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Accept", "application/dns-json")

	resp, err := dohClient.Do(req)
	if err != nil {
		return records, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return records, fmt.Errorf("máy chủ DoH trả về HTTP %d", resp.StatusCode)
	}

	body, err := readLimitedDoHBody(resp.Body)
	if err != nil {
		return records, err
	}

	var result dohResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return records, err
	}

	// Standard Rcode mapping
	switch result.Status {
	case 1:
		return records, ErrFORMERR
	case 2:
		return records, ErrSERVFAIL
	case 3:
		return records, ErrNXDOMAIN
	case 5:
		return records, ErrREFUSED
	}
	if result.Status != 0 {
		return records, fmt.Errorf("DNS error code %d", result.Status)
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

	case 33: // SRV
		rec.Type = "SRV"
		parts := strings.Split(ans.Data, " ")
		if len(parts) >= 4 {
			p, _ := strconv.Atoi(parts[0])
			w, _ := strconv.Atoi(parts[1])
			port, _ := strconv.Atoi(parts[2])
			rec.Priority = uint16(p)
			rec.Weight = uint16(w)
			rec.Port = uint16(port)
			rec.Target = strings.TrimSuffix(parts[3], ".")
			return &rec
		}
		return nil

	default:
		return nil
	}
}

func (r *DoHResolver) queryRFC8484(ctx context.Context, domain string, qtype uint16) ([]models.DNSRecord, error) {
	var records []models.DNSRecord

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)

	payload, err := m.Pack()
	if err != nil {
		return records, err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", r.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return records, err
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")

	resp, err := dohClient.Do(req)
	if err != nil {
		return records, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return records, fmt.Errorf("máy chủ DoH trả về HTTP %d", resp.StatusCode)
	}

	body, err := readLimitedDoHBody(resp.Body)
	if err != nil {
		return records, err
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		return records, err
	}

	// Standard Rcode mapping
	switch msg.Rcode {
	case dns.RcodeFormatError:
		return records, ErrFORMERR
	case dns.RcodeServerFailure:
		return records, ErrSERVFAIL
	case dns.RcodeNameError:
		return records, ErrNXDOMAIN
	case dns.RcodeRefused:
		return records, ErrREFUSED
	}
	if msg.Rcode != dns.RcodeSuccess {
		return records, fmt.Errorf("DNS error code %d", msg.Rcode)
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

func readLimitedDoHBody(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxDoHResponseBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxDoHResponseBody {
		return nil, fmt.Errorf("phản hồi DoH vượt quá giới hạn dung lượng")
	}
	return body, nil
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
	case *dns.SRV:
		return &models.DNSRecord{
			Type:     "SRV",
			Domain:   domain,
			Priority: rr.Priority,
			Weight:   rr.Weight,
			Port:     rr.Port,
			Target:   strings.TrimSuffix(rr.Target, "."),
			TTL:      rr.Hdr.Ttl,
		}
	default:
		return nil
	}
}
