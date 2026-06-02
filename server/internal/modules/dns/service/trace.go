package dns

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
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
	Timeout         time.Duration
	BypassCache     bool
	cacheMu         sync.RWMutex
	delegationCache map[string][]models.NameserverInfo
	enricher        *EnrichmentManager
}

func NewTraceResolver(timeout time.Duration) *TraceResolver {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &TraceResolver{
		Timeout:         timeout,
		delegationCache: make(map[string][]models.NameserverInfo),
		enricher:        NewEnrichmentManager(),
	}
}

func getRandomRoot() (string, string) {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(RootServers))))
	ip := RootServers[n.Int64()]
	return ip, RootServerNames[ip]
}

// =======================================================================
// FIX 1: exchangeWithFallback — UDP trước, nếu Truncated thì switch TCP
// =======================================================================
func exchangeWithFallback(ctx context.Context, msg *dns.Msg, addr string, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	udpClient := &dns.Client{Net: "udp", Timeout: timeout}
	resp, rtt, err := udpClient.ExchangeContext(ctx, msg, addr)
	if err != nil {
		return nil, rtt, err
	}

	// Nếu response bị cắt cụt (TC=1), retry ngay bằng TCP
	if resp.Truncated {
		tcpClient := &dns.Client{Net: "tcp", Timeout: timeout}
		respTCP, rttTCP, errTCP := tcpClient.ExchangeContext(ctx, msg, addr)
		if errTCP != nil {
			// TCP thất bại → trả về bản UDP cắt cụt để caller tự xử lý
			return resp, rtt, nil
		}
		return respTCP, rttTCP, nil
	}

	return resp, rtt, nil
}

// =====================================================================================
// FIX 2+3: queryParallel — Hỏi song song tối đa 3 Nameserver, lấy thằng nhanh nhất
// =====================================================================================
type queryResult struct {
	resp     *dns.Msg
	ns       models.NameserverInfo
	duration int64
}

func queryParallel(ctx context.Context, nsList []models.NameserverInfo, msg *dns.Msg, timeout time.Duration) (*queryResult, error) {
	limit := 3
	if len(nsList) < limit {
		limit = len(nsList)
	}

	resultCh := make(chan *queryResult, limit)
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for i := 0; i < limit; i++ {
		ns := nsList[i]
		wg.Add(1)
		go func(ns models.NameserverInfo) {
			defer wg.Done()

			// Resolve IP trong goroutine nếu chưa có (glueless hoặc in-bailiwick)
			if ns.IP == "" {
				ns.IP = resolveNSIP(cancelCtx, ns.Nameserver)
			}
			if ns.IP == "" {
				return
			}

			addr := net.JoinHostPort(ns.IP, "53")
			msgCopy := msg.Copy()
			start := time.Now()
			resp, _, err := exchangeWithFallback(cancelCtx, msgCopy, addr, timeout)
			elapsed := time.Since(start).Milliseconds()

			if err != nil || resp == nil {
				return
			}

			select {
			case <-cancelCtx.Done():
				return
			case resultCh <- &queryResult{resp: resp, ns: ns, duration: elapsed}:
				cancel()
			}
		}(ns)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	if result, ok := <-resultCh; ok {
		return result, nil
	}
	return nil, fmt.Errorf("không nhận được phản hồi từ bất kỳ nameserver nào")
}

// =======================================================================
// FIX 4: resolveNSIP — Phân giải IP cho Nameserver "Glueless" (không có Glue Record)
// FIX 2: Hỗ trợ cả AAAA glue records
// =======================================================================
func buildNSMap(extra []dns.RR) map[string]string {
	nsMap := make(map[string]string)
	for _, rr := range extra {
		name := strings.ToLower(strings.TrimSuffix(rr.Header().Name, "."))
		if a, ok := rr.(*dns.A); ok {
			nsMap[name] = a.A.String()
		} else if aaaa, ok := rr.(*dns.AAAA); ok {
			if _, exists := nsMap[name]; !exists {
				nsMap[name] = aaaa.AAAA.String()
			}
		}
	}
	return nsMap
}

func resolveNSIP(ctx context.Context, nsName string) string {
	// Bước 1: Thử OS resolver với Context Timeout
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, nsName)
	if err == nil && len(ips) > 0 {
		return ips[0].IP.String()
	}

	// Bước 2: Fallback — query trực tiếp tới public DNS (8.8.8.8) với ExchangeContext
	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(nsName), dns.TypeA)
	msg.RecursionDesired = true // recursive để get answer nhanh

	resp, _, err := client.ExchangeContext(ctx, msg, "8.8.8.8:53")
	if err != nil || resp == nil {
		return ""
	}
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A.String()
		}
	}
	return ""
}

// ==========
// MAIN TRACE
// ==========
func (tr *TraceResolver) DoTrace(domain string, qtype uint16) ([]models.DNSRecord, []models.TraceStep, error) {
	var logs []models.TraceStep
	var allRecords []models.DNSRecord

	ctx, cancel := context.WithTimeout(context.Background(), tr.Timeout)
	defer cancel()

	currentQName := dns.Fqdn(domain)
	cnameVisited := make(map[string]bool)

	for cnameHops := 0; cnameHops < 5; cnameHops++ {
		if ctx.Err() != nil {
			return nil, logs, fmt.Errorf("quá thời gian chờ khi thực hiện DNS Trace")
		}

		if cnameVisited[currentQName] {
			return allRecords, logs, fmt.Errorf("phát hiện vòng lặp CNAME tại %s", currentQName)
		}
		cnameVisited[currentQName] = true

		// Tìm entry point gần nhất trong delegation cache
		var currentNS []models.NameserverInfo
		var startingZone string

		labels := dns.SplitDomainName(currentQName)
		if !tr.BypassCache {
			for i := 0; i < len(labels); i++ {
				zone := strings.Join(labels[i:], ".") + "."
				tr.cacheMu.RLock()
				cached, exists := tr.delegationCache[zone]
				tr.cacheMu.RUnlock()
				if exists {
					currentNS = cached
					startingZone = zone
					break
				}
			}
		}

		if len(currentNS) == 0 {
			rootIP, rootName := getRandomRoot()
			currentNS = []models.NameserverInfo{
				{Nameserver: rootName, IP: rootIP},
			}
			startingZone = "."
		} else if cnameHops == 0 {
			logs = append(logs, models.TraceStep{
				Message: fmt.Sprintf("Sử dụng delegation đã cache cho zone %s", startingZone),
			})
		}

		visitedIPs := make(map[string]bool)
		foundAnswer := false

		// Inner loop: theo đường delegation xuống dần
		for {
			if ctx.Err() != nil {
				return nil, logs, fmt.Errorf("quá thời gian chờ khi thực hiện DNS Trace")
			}

			if len(currentNS) == 0 {
				logs = append(logs, models.TraceStep{Message: "Không còn nameserver để truy vấn. Trace đã dừng."})
				break
			}

			// FIX 4: Điền IP cho các NS chưa có (Glueless)
			var resolvedNS []models.NameserverInfo
			for _, ns := range currentNS {
				if ns.IP == "" {
					ns.IP = resolveNSIP(ctx, ns.Nameserver)
				}
				if ns.IP != "" && !visitedIPs[ns.IP] {
					resolvedNS = append(resolvedNS, ns)
					visitedIPs[ns.IP] = true
				}
			}

			if len(resolvedNS) == 0 {
				var debugErr string
				for _, ns := range currentNS {
					debugErr += fmt.Sprintf("[%s:%s(đã thử:%v)] ", ns.Nameserver, ns.IP, visitedIPs[ns.IP])
				}
				logs = append(logs, models.TraceStep{Message: "Không thể phân giải IP cho bất kỳ nameserver nào: " + debugErr + ". Trace đã dừng."})
				break
			}

			// Build query message
			msg := new(dns.Msg)
			msg.SetQuestion(currentQName, qtype)
			msg.RecursionDesired = false
			msg.SetEdns0(4096, true)

			// FIX 3: Parallel query — hỏi 3 ông cùng lúc
			qr, err := queryParallel(ctx, resolvedNS, msg, 3*time.Second)
			if err != nil {
				// Nếu NS từ cache thất bại, xóa cache và thử lại từ Root ngay lần này
				if startingZone != "." {
					tr.cacheMu.Lock()
					delete(tr.delegationCache, startingZone)
					tr.cacheMu.Unlock()
					// Fallback: thử lại với Root Server
					rootIP, rootName := getRandomRoot()
					rootMsg := msg.Copy()
					qrRoot, errRoot := queryParallel(ctx, []models.NameserverInfo{{Nameserver: rootName, IP: rootIP}}, rootMsg, 3*time.Second)
					if errRoot != nil {
						return nil, logs, fmt.Errorf("không nhận được phản hồi từ bất kỳ nameserver authoritative nào")
					}
					qr = qrRoot
					startingZone = "." // Reset để inner loop tiếp tục trace từ root response
				} else {
					return nil, logs, fmt.Errorf("không nhận được phản hồi từ bất kỳ nameserver authoritative nào")
				}
			}

			resp := qr.resp
			lastNS := qr.ns
			duration := qr.duration

			// Log thành công
			targetTypeStr := dns.TypeToString[qtype]
			domainNoDot := strings.TrimSuffix(currentQName, ".")
			logMsg := fmt.Sprintf("Đang tìm %s. Bản ghi %s tại %s. [%s] mất %d ms",
				domainNoDot, targetTypeStr, lastNS.Nameserver, lastNS.IP, duration)
			newStep := models.TraceStep{
				ServerName: lastNS.Nameserver,
				ServerIP:   lastNS.IP,
				DurationMs: duration,
				Message:    logMsg,
			}
			tr.enricher.EnrichStep(&newStep, domain)
			logs = append(logs, newStep)

			// Priority 1: Có Answer
			if len(resp.Answer) > 0 {
				foundAnswer = true
				var currentHopsRecords []models.DNSRecord
				var cnameTarget string

				for _, ans := range resp.Answer {
					rec := models.DNSRecord{
						Domain: currentQName,
						TTL:    ans.Header().Ttl,
					}
					valStr := ""
					switch rr := ans.(type) {
					case *dns.A:
						rec.Type = "A"
						rec.Address = rr.A.String()
						valStr = rec.Address
					case *dns.AAAA:
						rec.Type = "AAAA"
						rec.Address = rr.AAAA.String()
						valStr = rec.Address
					case *dns.CNAME:
						rec.Type = "CNAME"
						rec.Value = strings.TrimSuffix(rr.Target, ".")
						valStr = rec.Value
						cnameTarget = dns.Fqdn(rr.Target)
					case *dns.MX:
						rec.Type = "MX"
						rec.Priority = rr.Preference
						rec.Exchange = strings.TrimSuffix(rr.Mx, ".")
						valStr = fmt.Sprintf("%s (ưu tiên: %d)", rec.Exchange, rec.Priority)
					case *dns.NS:
						rec.Type = "NS"
						rec.Nameserver = strings.TrimSuffix(rr.Ns, ".")
						valStr = rec.Nameserver
					case *dns.TXT:
						rec.Type = "TXT"
						rec.Value = strings.Join(rr.Txt, " ")
						valStr = rec.Value
					case *dns.PTR:
						rec.Type = "PTR"
						rec.Value = strings.TrimSuffix(rr.Ptr, ".")
						valStr = rec.Value
					default:
						continue
					}

					currentHopsRecords = append(currentHopsRecords, rec)
					logs = append(logs, models.TraceStep{Message: fmt.Sprintf("Tìm thấy bản ghi %s: %s", rec.Type, valStr)})
				}

				allRecords = append(allRecords, currentHopsRecords...)

				// CNAME following (A/AAAA only)
				hasTargetType := false
				targetType := dns.TypeToString[qtype]
				for _, r := range currentHopsRecords {
					if r.Type == targetType {
						hasTargetType = true
						break
					}
				}

				if !hasTargetType && cnameTarget != "" && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
					logs = append(logs, models.TraceStep{
						Message: fmt.Sprintf("\nChưa tìm thấy bản ghi đích, tiếp tục theo CNAME tới %s...", strings.TrimSuffix(cnameTarget, ".")),
					})
					currentQName = cnameTarget
					break // Restart trace với target mới
				}

				logs = append(logs, models.TraceStep{Message: fmt.Sprintf("\nTrace hoàn tất: tìm thấy %d bản ghi.", len(allRecords))})
				return allRecords, logs, nil
			}

			// Priority 2: NXDOMAIN hoặc lỗi DNS khác
			if resp.Rcode != dns.RcodeSuccess {
				statusMsg := dns.RcodeToString[resp.Rcode]
				if resp.Rcode == dns.RcodeNameError {
					statusMsg = "Không tồn tại tên miền " + domainNoDot
				}
				logs = append(logs, models.TraceStep{Message: fmt.Sprintf("Nameserver %s báo cáo: %s", lastNS.Nameserver, statusMsg)})
				return allRecords, logs, nil
			}

			// Priority 3: Delegation (Authority section)
			if len(resp.Ns) > 0 {
				// FIX 2: Lấy cả IPv4 và IPv6 từ Glue Records
				nsMap := buildNSMap(resp.Extra)

				var nextCandidates []models.NameserverInfo
				for _, rr := range resp.Ns {
					if ns, ok := rr.(*dns.NS); ok {
						nsNameFound := strings.TrimSuffix(ns.Ns, ".")
						lookupKey := strings.ToLower(nsNameFound)
						nextCandidates = append(nextCandidates, models.NameserverInfo{
							Nameserver: nsNameFound,
							IP:         nsMap[lookupKey], // Có thể rỗng, sẽ resolve ở vòng tiếp theo
						})
					}
				}

				if len(nextCandidates) == 0 {
					isSOA := false
					for _, rr := range resp.Ns {
						if _, ok := rr.(*dns.SOA); ok {
							isSOA = true
							break
						}
					}
					if isSOA {
						logs = append(logs, models.TraceStep{
							Message: fmt.Sprintf("Nameserver %s báo cáo: Không tìm thấy bản ghi %s cho %s", lastNS.Nameserver, targetTypeStr, domainNoDot),
						})
					} else {
						logs = append(logs, models.TraceStep{Message: "Phần authority trả về dữ liệu nhưng không tìm thấy delegation. Trace đã dừng."})
					}
					return allRecords, logs, nil
				}

				currentNS = nextCandidates

				// Cache delegation zone đúng cách: key là zone NS đang quản lý
				// Chỉ cache khi NS đã có Glue IP để tránh lưu NS rỗng IP
				for _, ns := range nextCandidates {
					if ns.IP != "" {
						if firstNS, ok := resp.Ns[0].(*dns.NS); ok {
							zone := firstNS.Hdr.Name
							tr.cacheMu.Lock()
							tr.delegationCache[zone] = nextCandidates
							tr.cacheMu.Unlock()
						}
						break
					}
				}
				continue

			}

			// Không có Answer, NXDOMAIN, cũng không có delegation → dead end
			logs = append(logs, models.TraceStep{
				Message: fmt.Sprintf("Nameserver %s báo cáo: Không tìm thấy bản ghi %s (delegation không đầy đủ).", lastNS.Nameserver, targetTypeStr),
			})
			return allRecords, logs, nil
		}

		if foundAnswer {
			continue // Đang follow CNAME
		}
		break
	}

	return allRecords, logs, nil
}

// DiscoverAuthorities traces from Root to find the authoritative nameservers for a domain.
// It returns the NS records that the PARENT zone (Registry) delegates to — not the zone's own NS.
func (tr *TraceResolver) DiscoverAuthorities(domain string) ([]models.NameserverInfo, error) {
	domain = dns.Fqdn(domain)
	targetDomain := strings.TrimSuffix(domain, ".")

	ctx, cancel := context.WithTimeout(context.Background(), tr.Timeout)
	defer cancel()

	// Try to find the closest ancestor in the cache
	var currentNS []models.NameserverInfo
	if !tr.BypassCache {
		labels := dns.SplitDomainName(domain)
		for i := 0; i < len(labels); i++ {
			zone := strings.Join(labels[i:], ".") + "."
			tr.cacheMu.RLock()
			cached, exists := tr.delegationCache[zone]
			tr.cacheMu.RUnlock()
			if exists {
				currentNS = cached
				break
			}
		}
	}

	if len(currentNS) == 0 {
		rootIP, rootName := getRandomRoot()
		currentNS = []models.NameserverInfo{
			{Nameserver: rootName, IP: rootIP},
		}
	}

	visited := make(map[string]bool)
	var lastDelegation []models.NameserverInfo

	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if len(currentNS) == 0 {
			break
		}

		// Resolve IP cho các NS glueless
		var resolvedNS []models.NameserverInfo
		for _, ns := range currentNS {
			if ns.IP == "" {
				ns.IP = resolveNSIP(ctx, ns.Nameserver)
			}
			if ns.IP != "" && !visited[ns.IP] {
				resolvedNS = append(resolvedNS, ns)
				visited[ns.IP] = true
			}
		}

		if len(resolvedNS) == 0 {
			break
		}

		msg := new(dns.Msg)
		msg.SetQuestion(domain, dns.TypeNS)
		msg.RecursionDesired = false
		msg.SetEdns0(4096, true)

		// FIX 3: Parallel query cho DiscoverAuthorities
		qr, err := queryParallel(ctx, resolvedNS, msg, 2*time.Second)
		if err != nil {
			if len(lastDelegation) > 0 {
				return lastDelegation, nil
			}
			return nil, fmt.Errorf("không thể tìm authoritative nameserver cho %s", domain)
		}

		resp := qr.resp

		// Nếu zone tự trả lời về chính mình
		if len(resp.Answer) > 0 {
			if len(lastDelegation) > 0 {
				return lastDelegation, nil
			}
			var nsInfos []models.NameserverInfo
			for _, ans := range resp.Answer {
				if ns, ok := ans.(*dns.NS); ok {
					nsInfos = append(nsInfos, models.NameserverInfo{
						Nameserver: strings.TrimSuffix(ns.Ns, "."),
						TTL:        ns.Header().Ttl,
						Domain:     strings.TrimSuffix(ns.Hdr.Name, "."),
					})
				}
			}
			if len(nsInfos) > 0 {
				return nsInfos, nil
			}
		}

		// Delegation handling
		if len(resp.Ns) > 0 {
			// FIX 2: Hỗ trợ IPv6 glue trong DiscoverAuthorities
			nsMap := buildNSMap(resp.Extra)

			var nextCandidates []models.NameserverInfo
			var delegatedZone string
			for _, rr := range resp.Ns {
				if ns, ok := rr.(*dns.NS); ok {
					nsNameFound := strings.TrimSuffix(ns.Ns, ".")
					hdrZone := strings.TrimSuffix(ns.Hdr.Name, ".")
					lookupKey := strings.ToLower(nsNameFound)
					nextCandidates = append(nextCandidates, models.NameserverInfo{
						Nameserver: nsNameFound,
						IP:         nsMap[lookupKey],
						TTL:        ns.Header().Ttl,
						Domain:     hdrZone,
					})
					if delegatedZone == "" {
						delegatedZone = hdrZone
					}
				}
			}

			// Registry đã delegate đúng domain ta cần
			if strings.EqualFold(delegatedZone, targetDomain) && len(nextCandidates) > 0 {
				tr.cacheMu.Lock()
				tr.delegationCache[domain] = nextCandidates
				tr.cacheMu.Unlock()
				return nextCandidates, nil
			}

			// Intermediate delegation
			if len(nextCandidates) > 0 {
				lastDelegation = nextCandidates
				if ns, ok := resp.Ns[0].(*dns.NS); ok {
					zone := ns.Hdr.Name
					tr.cacheMu.Lock()
					tr.delegationCache[zone] = nextCandidates
					tr.cacheMu.Unlock()
				}
			}
			currentNS = nextCandidates
			continue
		}
		break
	}

	if len(lastDelegation) > 0 {
		return lastDelegation, nil
	}
	return nil, fmt.Errorf("không tìm thấy authoritative nameserver cho %s", domain)
}
