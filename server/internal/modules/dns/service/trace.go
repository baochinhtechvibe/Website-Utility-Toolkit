package dns

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"tools.bctechvibe.com/server/internal/modules/dns/models"
)

var RootServers = []string{
	"198.41.0.4",     // A.ROOT-SERVERS.NET
	"199.9.14.201",   // B.ROOT-SERVERS.NET
	"192.33.4.12",    // C.ROOT-SERVERS.NET
	"199.7.91.13",    // D.ROOT-SERVERS.NET
	"192.203.230.10", // E.ROOT-SERVERS.NET
	"192.5.5.241",    // F.ROOT-SERVERS.NET
	"192.112.36.4",   // G.ROOT-SERVERS.NET
	"198.97.190.53",  // H.ROOT-SERVERS.NET
	"192.36.148.17",  // I.ROOT-SERVERS.NET
	"192.58.128.30",  // J.ROOT-SERVERS.NET
	"193.0.14.129",   // K.ROOT-SERVERS.NET
	"199.7.83.42",    // L.ROOT-SERVERS.NET
	"202.12.27.33",   // M.ROOT-SERVERS.NET
}

var RootServerNames = map[string]string{
	"198.41.0.4":     "A.ROOT-SERVERS.NET",
	"199.9.14.201":   "B.ROOT-SERVERS.NET",
	"192.33.4.12":    "C.ROOT-SERVERS.NET",
	"199.7.91.13":    "D.ROOT-SERVERS.NET",
	"192.203.230.10": "E.ROOT-SERVERS.NET",
	"192.5.5.241":    "F.ROOT-SERVERS.NET",
	"192.112.36.4":   "G.ROOT-SERVERS.NET",
	"198.97.190.53":  "H.ROOT-SERVERS.NET",
	"192.36.148.17":  "I.ROOT-SERVERS.NET",
	"192.58.128.30":  "J.ROOT-SERVERS.NET",
	"193.0.14.129":   "K.ROOT-SERVERS.NET",
	"199.7.83.42":    "L.ROOT-SERVERS.NET",
	"202.12.27.33":   "M.ROOT-SERVERS.NET",
}

type TraceResolver struct {
	Timeout time.Duration
}

func NewTraceResolver(timeout time.Duration) *TraceResolver {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &TraceResolver{Timeout: timeout}
}

func getRandomRoot() (string, string) {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(RootServers))))
	ip := RootServers[n.Int64()]
	return ip, RootServerNames[ip]
}

func (tr *TraceResolver) DoTrace(domain string, qtype uint16) ([]models.DNSRecord, []models.TraceStep, error) {
	domain = dns.Fqdn(domain)
	var logs []models.TraceStep
	var records []models.DNSRecord

	// Pick a random root server to start
	nsIP, nsName := getRandomRoot()

	ctx, cancel := context.WithTimeout(context.Background(), tr.Timeout)
	defer cancel()

	client := &dns.Client{
		Net:     "udp",
		Timeout: 2 * time.Second, // Timeout per hop
	}

	visited := make(map[string]bool)

	for {
		if ctx.Err() != nil {
			return nil, logs, fmt.Errorf("trace timeout exceeded")
		}

		if visited[nsIP] {
			logs = append(logs, models.TraceStep{
				ServerName: nsName, ServerIP: nsIP, Message: "Loop detected, aborting trace.",
			})
			break
		}
		visited[nsIP] = true

		msg := new(dns.Msg)
		msg.SetQuestion(domain, qtype)
		// Root iteration -> NO recursion
		msg.RecursionDesired = false

		start := time.Now()
		resp, _, err := client.ExchangeContext(ctx, msg, net.JoinHostPort(nsIP, "53"))
		duration := time.Since(start).Milliseconds()

		targetTypeStr := dns.TypeToString[qtype]
		logMsg := fmt.Sprintf("Searching for %s %s record at %s. [%s] ...took %d ms", strings.TrimSuffix(domain, "."), targetTypeStr, nsName, nsIP, duration)
		logs = append(logs, models.TraceStep{
			ServerName: nsName,
			ServerIP:   nsIP,
			DurationMs: duration,
			Message:    logMsg,
		})

		if err != nil {
			logs = append(logs, models.TraceStep{ServerName: nsName, ServerIP: nsIP, Message: fmt.Sprintf("Error: %v", err)})
			return nil, logs, err
		}

		// 1. Check Answer section
		if len(resp.Answer) > 0 {
			// Found answers!
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

			// If we got a CNAME but asked for A/AAAA/etc, we should technically follow the CNAME.
			// But for a simple trace, returning the CNAME is fine. (DNSWatch does this if tracing stops).
			// Let's just return what we got.
			logs = append(logs, models.TraceStep{
				Message: fmt.Sprintf("\n%d record(s) found.", len(records)),
			})
			return records, logs, nil
		}

		// Check for NXDOMAIN or other errors
		if resp.Rcode != dns.RcodeSuccess {
			logs = append(logs, models.TraceStep{
				Message: fmt.Sprintf("\nResponse Code: %s", dns.RcodeToString[resp.Rcode]),
			})
			return records, logs, nil
		}

		// 2. No Answer -> Check Authority for Delegation (NS records for the next zone)
		if len(resp.Ns) > 0 {
			var nextNsName string
			for _, rr := range resp.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					nextNsName = strings.TrimSuffix(ns.Ns, ".")
					break
				}
			}

			if nextNsName == "" {
				logs = append(logs, models.TraceStep{Message: "Authority section has no NS records. Trace stopped."})
				break
			}

			// Find glue IP in Extra
			var nextNsIP string
			for _, extra := range resp.Extra {
				if a, ok := extra.(*dns.A); ok {
					if strings.TrimSuffix(a.Hdr.Name, ".") == nextNsName {
						nextNsIP = a.A.String()
						break
					}
				}
			}

			// If no glue record, we would normally resolve the NS name.
			// For simplicity in this implementation, if no glue, try resolving it using system resolver.
			if nextNsIP == "" {
				logs = append(logs, models.TraceStep{Message: fmt.Sprintf("No glue record found for %s, resolving...", nextNsName)})
				ips, err := net.LookupHost(nextNsName)
				if err == nil && len(ips) > 0 {
					nextNsIP = ips[0]
				} else {
					logs = append(logs, models.TraceStep{Message: fmt.Sprintf("Failed to resolve NS %s. Trace aborted.", nextNsName)})
					break
				}
			}

			// Descend to the next NS
			nsName = nextNsName
			nsIP = nextNsIP
			continue
		}

		// No Answer and No Authority
		logs = append(logs, models.TraceStep{Message: "No answer and no delegation found. Trace stopped."})
		break
	}

	return records, logs, nil
}
