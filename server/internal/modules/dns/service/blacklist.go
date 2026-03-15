package dns

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"tools.bctechvibe.com/server/internal/modules/dns/models"
)

const (
	rblMaxConcurrency = 10
	rblTimeout        = 1200 * time.Millisecond
)

// =======================
// HELPERS
// =======================

func ReverseIP(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s", parts[3], parts[2], parts[1], parts[0])
}

func FormatRBLProviderName(host string) string {
	switch {
	case strings.Contains(host, "spamhaus.org"):
		return "Spamhaus"
	case strings.Contains(host, "sorbs.net"):
		return "SORBS"
	case strings.Contains(host, "spamcop.net"):
		return "SpamCop"
	default:
		return host
	}
}

// =======================
// DNS LOW LEVEL
// =======================

func newDNSClient() *dns.Client {
	return &dns.Client{
		Net:     "udp",
		Timeout: rblTimeout,
	}
}

func lookupNS(zone string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(zone), dns.TypeNS)

	c := newDNSClient()
	r, _, err := c.Exchange(m, "1.1.1.1:53")
	if err != nil {
		return nil, err
	}

	var out []string
	for _, ans := range r.Answer {
		if ns, ok := ans.(*dns.NS); ok {
			out = append(out, ns.Ns)
		}
	}
	return out, nil
}

func queryRBL(qname, provider string) ([]dns.RR, error) {
	nsList, err := lookupNS(provider)
	if err != nil || len(nsList) == 0 {
		return nil, err
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeA)

	c := newDNSClient()

	for _, ns := range nsList {
		r, _, err := c.Exchange(m, ns+":53")
		if err == nil && r != nil {
			return r.Answer, nil
		}
	}

	return nil, fmt.Errorf("all NS failed")
}

// =======================
// NON STREAM
// =======================

func CheckBlacklist(ip string) ([]models.BlacklistRecord, int, int) {
	reversed := ReverseIP(ip)
	if reversed == "" {
		return nil, 0, 0
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		records []models.BlacklistRecord
		checked int
		listed  int
	)

	sem := make(chan struct{}, rblMaxConcurrency)

	for _, rbl := range RBLProviders {
		wg.Add(1)
		sem <- struct{}{}

		go func(rbl models.RBLProvider) {
			defer wg.Done()
			defer func() { <-sem }()

			query := fmt.Sprintf("%s.%s", reversed, rbl.Host)
			recs, err := queryRBL(query, rbl.Host)

			status := "OK"
			if err != nil {
				status = "TIMEOUT"
			} else if len(recs) > 0 {
				status = "LISTED"
			}

			mu.Lock()
			if err == nil {
				checked++
				if status == "LISTED" {
					listed++
				}
			}
			records = append(records, models.BlacklistRecord{
				Type:     "BLACKLIST",
				Provider: rbl.Host,
				Level:    rbl.Level,
				Status:   status,
				IP:       ip,
			})
			mu.Unlock()
		}(rbl)
	}

	wg.Wait()
	return records, checked, listed
}

// =======================
// STREAM
// =======================

func StreamBlacklist(ip string, cb func(models.BlacklistStreamEvent)) {
	total := len(RBLProviders) // ← đưa lên đầu
	reversed := ReverseIP(ip)

	// === PHASE 1: INIT ===
	cb(models.BlacklistStreamEvent{
		Type:   "BLACKLIST_INIT",
		IP:     ip,
		Listed: 0,
		Total:  total,
	})

	if reversed == "" {
		cb(models.BlacklistStreamEvent{
			Type:   "BLACKLIST_SUMMARY",
			IP:     ip,
			Listed: 0,
			Total:  total,
		})
		return
	}

	// total := len(RBLProviders)   // ← đưa lên trên

	type result struct {
		host   string
		level  string
		status string
	}

	results := make(chan result, total)
	sem := make(chan struct{}, rblMaxConcurrency)

	for _, rbl := range RBLProviders {
		sem <- struct{}{}
		go func(rbl models.RBLProvider) {
			defer func() { <-sem }()

			query := fmt.Sprintf("%s.%s", reversed, rbl.Host)
			recs, err := queryRBL(query, rbl.Host)

			status := "OK"
			if err != nil {
				status = "TIMEOUT"
			} else if len(recs) > 0 {
				status = "LISTED"
			}

			results <- result{
				host:   rbl.Host,
				level:  rbl.Level,
				status: status,
			}
		}(rbl)
	}

	listed := 0

	for i := 0; i < total; i++ {
		r := <-results

		if r.status == "LISTED" {
			listed++
		}

		cb(models.BlacklistStreamEvent{
			Type:     "BLACKLIST",
			Provider: r.host,
			Status:   r.status,
			Level:    r.level,
		})
	}

	cb(models.BlacklistStreamEvent{
		Type:     "BLACKLIST_SUMMARY",
		Provider: "",
		Status:   "",
		IP:       ip,
		Listed:   listed,
		Total:    total,
	})
}
