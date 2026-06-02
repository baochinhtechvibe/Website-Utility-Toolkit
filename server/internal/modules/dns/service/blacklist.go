package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"tools.bctechvibe.com/server/internal/modules/dns/models"
)

const (
	rblMaxConcurrency = 10
	rblTimeout        = 3500 * time.Millisecond
	rblResolver       = "1.1.1.1:53"
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

func queryRBL(ctx context.Context, qname string) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(qname), dns.TypeA)
	m.RecursionDesired = true

	c := newDNSClient()
	r, _, err := c.ExchangeContext(ctx, m, rblResolver)
	if err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("recursive resolver không trả về phản hồi")
	}
	switch r.Rcode {
	case dns.RcodeSuccess:
		return r.Answer, nil
	case dns.RcodeNameError:
		return nil, nil
	default:
		return nil, fmt.Errorf("recursive resolver trả về mã lỗi %s", dns.RcodeToString[r.Rcode])
	}
}

func classifyRBLRecords(records []dns.RR) string {
	listed := false
	for _, record := range records {
		a, ok := record.(*dns.A)
		if !ok {
			continue
		}
		if strings.HasPrefix(a.A.String(), "127.255.255.") {
			return "ERROR"
		}
		if a.A.IsLoopback() {
			listed = true
			continue
		}
		return "ERROR"
	}
	if listed {
		return "LISTED"
	}
	return "OK"
}

func rblQueryHost(provider models.RBLProvider) string {
	if provider.QueryHost != "" {
		return provider.QueryHost
	}
	return provider.Host
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
		host           string
		level          string
		category       string
		status         string
		responseTimeMs int64
	}

	results := make(chan result, total)
	sem := make(chan struct{}, rblMaxConcurrency)

	for _, rbl := range RBLProviders {
		go func(rbl models.RBLProvider) {
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			query := fmt.Sprintf("%s.%s", reversed, rblQueryHost(rbl))
			startedAt := time.Now()
			recs, err := queryRBL(ctx, query)
			responseTimeMs := time.Since(startedAt).Milliseconds()

			status := classifyRBLRecords(recs)
			if isTimeoutError(err) {
				status = "TIMEOUT"
			} else if err != nil {
				status = "ERROR"
			}

			select {
			case results <- result{
				host:           rbl.Host,
				level:          rbl.Level,
				category:       rbl.Category,
				status:         status,
				responseTimeMs: responseTimeMs,
			}:
			case <-ctx.Done():
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
				Type:           "BLACKLIST",
				Provider:       r.host,
				Status:         r.status,
				Level:          r.level,
				Category:       r.category,
				ResponseTimeMs: r.responseTimeMs,
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

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
