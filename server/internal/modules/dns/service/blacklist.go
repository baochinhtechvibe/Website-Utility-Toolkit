package dns

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"tools.bctechvibe.com/server/internal/modules/dns/models"
)

const (
	rblMaxConcurrency = 10
	rblTimeout        = 3500 * time.Millisecond
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

// Task 3: Cache RBL provider nameservers to avoid redundant lookups.
var rblNSCache sync.Map // map[string][]string

func queryRBL(qname, provider string) ([]dns.RR, error) {
	var nsList []string
	if cached, ok := rblNSCache.Load(provider); ok {
		nsList = cached.([]string)
	} else {
		var err error
		nsList, err = lookupNS(provider)
		if err != nil || len(nsList) == 0 {
			return nil, err
		}
		rblNSCache.Store(provider, nsList)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeA)

	c := newDNSClient()

	// Thử tối đa 2 NS Server để tránh treo quá lâu nếu RBL provider chặn kết nối
	maxAttempts := len(nsList)
	if maxAttempts > 2 {
		maxAttempts = 2
	}

	for i := 0; i < maxAttempts; i++ {
		ns := nsList[i]
		c.Timeout = 2500 * time.Millisecond // Ép Timeout thấp xuống 2.5s mỗi retry
		r, _, err := c.Exchange(m, ns+":53")
		if err == nil && r != nil {
			return r.Answer, nil
		}
	}

	return nil, fmt.Errorf("all attempted NS failed or timed out")
}

// =======================
// STREAM
// =======================

func StreamBlacklist(ctx context.Context, ip string, cb func(models.BlacklistStreamEvent)) {
	total := len(RBLProviders)
	reversed := ReverseIP(ip)

	// === PHASE 1: INIT ===
	cb(models.BlacklistStreamEvent{
		Type:      "BLACKLIST_INIT",
		IP:        ip,
		Listed:    0,
		Total:     total,
		Providers: RBLProviders,
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

	// Heartbeat ticker: gửi SSE comment mỗi 5s để giữ kết nối sống
	heartbeat := time.NewTicker(5 * time.Second)
	defer heartbeat.Stop()

	for i := 0; i < total; i++ {
		// Chờ kết quả kế tiếp HOẶC context bị hủy HOẶC heartbeat tick
		select {
		case <-ctx.Done():
			// Client đã ngắt kết nối, dừng stream
			return
		case r := <-results:
			if r.status == "LISTED" {
				listed++
			}

			cb(models.BlacklistStreamEvent{
				Type:     "BLACKLIST",
				Provider: r.host,
				Status:   r.status,
				Level:    r.level,
			})
		case <-heartbeat.C:
			// Gửi SSE comment (: heartbeat) để giữ kết nối sống
			// Callback sẽ bỏ qua vì type rỗng, nhưng cần ghi trực tiếp
			cb(models.BlacklistStreamEvent{
				Type: "HEARTBEAT",
			})
			i-- // Không tính heartbeat vào counter
		}
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
