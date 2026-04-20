package service

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	dnslib "github.com/miekg/dns"
	"github.com/rs/zerolog/log"
	dnsModels "tools.bctechvibe.com/server/internal/modules/dns/models"
	dnsservice "tools.bctechvibe.com/server/internal/modules/dns/service"
	"tools.bctechvibe.com/server/internal/modules/whois/models"
	"tools.bctechvibe.com/server/internal/pkg/iana"
)

const (
	cacheTTLDefault = 1 * time.Hour
	cacheTTLVN      = 24 * time.Hour

	// WHOIS server cho VNNIC (toàn bộ .vn và sub-ccTLD như .com.vn, .net.vn, .io.vn...)
	vnnicWhoisServer = "whois.vnnic.vn"

	// Tino API endpoint - Tầng 1 ưu tiên cho .vn
	tinoAPIBase = "http://tino.vn/backend-api/whois/"
	tinoTimeout = 4 * time.Second

	// Timeout cho VNNIC port 43 (tầng fallback)
	vnnicTimeout = 10 * time.Second

	// Thời gian chờ ưu tiên cho kết quả tốt nhất (Tier 1 hoặc Tier 2 xịn)
	genericBestResultTimeout = 5 * time.Second

	// DomScan API endpoint
	domscanAPIBase = "https://domscan.net/v1/status"
)

var (
	// Cache hợp nhất: 1 LRU cache duy nhất chứa cả Response + Meta
	whoisCache cache.Cache[string, *models.WhoisCacheEntry]

	// Limiter cho bypass cache: giới hạn bộ nhớ và thời gian (LRU)
	bypassLimiter  cache.Cache[string, time.Time]
	bypassCooldown = 1 * time.Minute

	// Giới hạn số lần bypass theo IP (5 lần / 1 phút)
	ipLimiter cache.Cache[string, []time.Time]
)

// init khởi tạo cache ở package level, đảm bảo chỉ chạy 1 lần khi import.
func init() {
	whoisCache = cache.NewCache[string, *models.WhoisCacheEntry]().WithLRU().WithTTL(cacheTTLDefault)
	bypassLimiter = cache.NewCache[string, time.Time]().WithLRU().WithTTL(bypassCooldown)
	ipLimiter = cache.NewCache[string, []time.Time]().WithLRU().WithTTL(1 * time.Minute)

	// Tải dữ liệu IANA dùng chung
	iana.Init()
}

// isVNDomain kiểm tra tên miền có phải .vn không (bao gồm .com.vn, .net.vn, .io.vn, ...)
func isVNDomain(domain string) bool {
	lower := strings.ToLower(domain)
	return strings.HasSuffix(lower, ".vn")
}

// LookupWhois thực hiện truy vấn WHOIS cho một domain.
// ctx: context từ Gin request — cancel khi client disconnect.
// bypassCache=true ép tải lại dữ liệu mới (giới hạn 5 lần/phút/IP và 1 lần/phút/domain).
func LookupWhois(ctx context.Context, domain string, bypassCache bool, clientIP string) (*models.WhoisResponse, *models.WhoisMeta, error) {

	isVN := isVNDomain(domain)
	cacheKey := strings.ToLower(domain)

	// Bypass rate limiting: giới hạn bypass cache liên tục
	if bypassCache {
		// 1. Kiểm tra giới hạn theo IP (5 lần / 1 phút)
		now := time.Now()
		var validTimestamps []time.Time
		if timestamps, ok := ipLimiter.Get(clientIP); ok {
			for _, t := range timestamps {
				if time.Since(t) < time.Minute {
					validTimestamps = append(validTimestamps, t)
				}
			}
		}

		if len(validTimestamps) >= 5 {
			log.Warn().Str("ip", clientIP).Msg("WHOIS: IP bypass limit exceeded (5/min)")
			bypassCache = false
		} else {
			// 2. Kiểm tra cooldown theo Domain
			cooldown := bypassCooldown
			if lastBypass, ok := bypassLimiter.Get(cacheKey); ok {
				if time.Since(lastBypass) < cooldown {
					log.Info().Str("domain", domain).Msg("WHOIS: bypass cooldown active, serving from cache")
					bypassCache = false
				}
			}
		}

		// Nếu qua được các màng lọc, tính là 1 lần bypass hợp lệ cho IP
		if bypassCache {
			validTimestamps = append(validTimestamps, now)
			ipLimiter.Set(clientIP, validTimestamps, time.Minute)
		}
	}

	// 1. Lấy dữ liệu từ cache trước (để dành fallback nếu query live lỗi)
	var cachedEntry *models.WhoisCacheEntry
	if entry, ok := whoisCache.Get(cacheKey); ok {
		cachedEntry = entry
	}

	// 2. Nếu không bypass, trả luôn cache nếu có
	if !bypassCache && cachedEntry != nil {
		cachedMeta := *cachedEntry.Meta
		cachedMeta.Cached = true
		return cachedEntry.Response, &cachedMeta, nil
	}

	// Tạo child context với timeout tổng cho toàn bộ lookup
	lookupCtx, lookupCancel := context.WithTimeout(ctx, 20*time.Second)
	defer lookupCancel()

	// Thực hiện truy vấn WHOIS thực tế (và discover Nameservers song song)
	log.Info().Str("domain", domain).Bool("isVN", isVN).Msg("WHOIS: querying live data")

	type whoisResult struct {
		resp *models.WhoisResponse
		err  error
	}
	whoisChan := make(chan whoisResult, 1)
	nsChan := make(chan []string, 1)
	dnssecChan := make(chan dnsModels.DNSSECInfo, 1)

	go func() {
		var resp *models.WhoisResponse
		var err error
		if isVN {
			resp, err = queryVNDomain(lookupCtx, domain)
		} else {
			resp, err = queryGenericDomain(lookupCtx, domain)
		}
		whoisChan <- whoisResult{resp, err}
	}()

	// DNS discover chạy song song luôn, tiết kiệm ~8s nếu WHOIS không trả về NS
	go func() {
		nsChan <- discoverNameservers(lookupCtx, domain)
	}()

	// DNSSEC validation chạy song song, dọn độ trễ 200-500ms
	go func() {
		dnssecChan <- dnsservice.ValidateDNSSEC("cloudflare", domain)
	}()

	wr := <-whoisChan
	if wr.err != nil {
		log.Error().Err(wr.err).Str("domain", domain).Msg("WHOIS all sources failed")
		
		// Fallback: Nếu truy vấn live lỗi nhưng có cache cũ, trả về cache luôn cho user đỡ thấy lỗi đỏ
		if cachedEntry != nil {
			log.Info().Str("domain", domain).Msg("WHOIS fallback to cache after live query failed")
			cachedMeta := *cachedEntry.Meta
			cachedMeta.Cached = true
			return cachedEntry.Response, &cachedMeta, nil
		}

		return nil, nil, wr.err
	}

	resp := wr.resp

	// Gộp và deduplicate Nameservers từ các nguồn (WHOIS và DNS discovery)
	nsMap := make(map[string]bool)
	// Lấy từ WHOIS trước
	for _, n := range resp.Nameservers {
		name := strings.ToLower(strings.TrimSpace(n))
		if name != "" {
			nsMap[name] = true
		}
	}
	// Kiểm tra nếu tên miền chưa đăng ký (Available)
	isAvailable := resp.IsAvailable || (len(resp.Status) > 0 && strings.ToLower(resp.Status[0]) == "available")

	if isAvailable {
		// Lớp bảo vệ DNS Cross-check (Tận dụng nsChan đã chạy song song)
		// Nếu WHOIS báo "Available" nhưng DNS có trả về Nameserver -> Domain ĐÃ đăng ký
		select {
		case dnsNS := <-nsChan:
			// Lọc ra các nameserver thực sự của domain, bỏ qua TLD registries
			var realNS []string
			for _, n := range dnsNS {
				name := strings.ToLower(strings.TrimSpace(n))
				if name != "" && !iana.IsRegistryNS(name) {
					realNS = append(realNS, name)
				}
			}

			if len(realNS) > 0 {
				log.Warn().Str("domain", domain).Msg("WHOIS: Domain reported available but DNS NS check found records -> Overriding to Registered")
				isAvailable = false
				resp.IsAvailable = false
				resp.Status = []string{"Registered (Lookup Limited)"}
				for _, n := range realNS {
					nsMap[n] = true
				}
			}
		case <-time.After(500 * time.Millisecond):
			// Không đợi quá lâu nếu tên miền có vẻ available thật
		}
	} else {
		// Tên miền đã đăng ký: Đợi và gom Nameserver (tối đa 4s)
		select {
		case dnsNS := <-nsChan:
			for _, n := range dnsNS {
				name := strings.ToLower(strings.TrimSpace(n))
				if name != "" {
					nsMap[name] = true
				}
			}
		case <-time.After(4 * time.Second):
			log.Warn().Str("domain", domain).Msg("WHOIS: DNS discover timeout (4s) - skipping to return WHOIS data early")
		case <-lookupCtx.Done():
			log.Warn().Str("domain", domain).Msg("WHOIS: context cancelled during NS discovery")
		}
	}

	// Chuyển lại thành slice (lọc bỏ NS thuộc TLD registry)
	finalNS := make([]string, 0, len(nsMap))
	for ns := range nsMap {
		if !iana.IsRegistryNS(ns) {
			finalNS = append(finalNS, ns)
		}
	}
	resp.Nameservers = finalNS

	// Lấy thông tin DNSSEC từ DNS module với cơ chế nhận kết quả song song
	select {
	case dnssecInfo := <-dnssecChan:
		resp.DNSSEC = &dnssecInfo
	case <-time.After(2 * time.Second):
		log.Warn().Str("domain", domain).Msg("WHOIS: DNSSEC validation timeout (2s), skipping")
	case <-lookupCtx.Done():
		log.Warn().Str("domain", domain).Msg("WHOIS: context cancelled during DNSSEC")
	}

	// Lưu cache với TTL phù hợp
	ttl := cacheTTLDefault
	if isVN {
		ttl = cacheTTLVN
	}

	now := time.Now().UTC().Format(time.RFC3339)
	meta := &models.WhoisMeta{
		FetchedAt: now,
		Cached:    false,
	}
	// Hậu xử lý: Chỉ hiển thị Chủ sở hữu cho tên miền .vn
	if isVN {
		if isPlaceholderRegistrant(resp.Registrant) {
			resp.Registrant = "Domain Admin"
		}
	} else {
		// Tên miền quốc tế: Xóa trắng trường registrant để frontend không hiển thị
		resp.Registrant = ""
	}

	whoisCache.Set(cacheKey, &models.WhoisCacheEntry{
		Response: resp,
		Meta:     meta,
	}, ttl)

	// Ghi nhận thời điểm bypass nếu có
	if bypassCache {
		bypassLimiter.Set(cacheKey, time.Now(), bypassCooldown)
	}

	return resp, meta, nil
}

// =============================================
//  VN DOMAIN: Smart Race + Fallback
// =============================================

// queryVNDomain dùng chiến lược "Smart Race" cho tên miền .vn:
//   - Chạy song song Tino API + VNNIC Port 43
//   - Tino về trước → trả luôn (data sạch nhất)
//   - VNNIC về trước → đợi thêm tối đa 1s cho Tino (vì Tino data đẹp hơn)
//   - Cả 2 tạch sau 5s → Tier 3 Auto-Discover
func queryVNDomain(parentCtx context.Context, domain string) (*models.WhoisResponse, error) {
	ctx, cancel := context.WithTimeout(parentCtx, 12*time.Second) // Tăng lên 12s cho .vn vì VNNIC khá chậm
	defer cancel()

	type result struct {
		resp *models.WhoisResponse
		err  error
		tier int
	}
	resChan := make(chan result, 2)

	// Chạy Tino API (Tier 1)
	go func() {
		r, e := queryTinoAPI(ctx, domain)
		resChan <- result{r, e, 1}
	}()

	// Chạy VNNIC Port 43 (Tier 2)
	go func() {
		raw, e := queryVNNIC(ctx, domain)
		var r *models.WhoisResponse
		if e == nil {
			r = parseWhoisRaw(domain, raw, true)
		}
		resChan <- result{r, e, 2}
	}()

	// Deadline tổng: nếu 10s mà chưa có gì → Tier 3
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()

	var vnnicResult *models.WhoisResponse

	for i := 0; i < 2; i++ {
		select {
		case res := <-resChan:
			if res.err != nil {
				continue
			}

			if res.resp != nil && res.resp.IsAvailable {
				log.Info().Str("domain", domain).Int("tier", res.tier).Str("source", res.resp.AvailableSource).Msg("WHOIS VN: Tier reported domain is available (Early Return)")
				return res.resp, nil
			}

			if res.tier == 1 {
				// Tino về trước (hoặc về sau khi VNNIC đã về) → luôn ưu tiên Tino
				log.Info().Str("domain", domain).Msg("WHOIS VN: Tino returned — using best data")
				return res.resp, nil
			}

			// VNNIC về trước
			vnnicResult = res.resp

			// Nếu VNNIC có đầy đủ dữ liệu (Registrar + Dates + NS) → trả luôn, không đợi Tino
			if isResultComplete(vnnicResult) {
				log.Info().Str("domain", domain).Msg("WHOIS VN: VNNIC returned complete data — Early Return")
				return vnnicResult, nil
			}

			// VNNIC thiếu data → đợi thêm tối đa 1s cho Tino (data sạch hơn)
			log.Info().Str("domain", domain).Msg("WHOIS VN: VNNIC returned incomplete — waiting 1s for Tino")
			graceTimer := time.NewTimer(1 * time.Second)
			select {
			case tinoRes := <-resChan:
				graceTimer.Stop()
				if tinoRes.err == nil && tinoRes.tier == 1 {
					log.Info().Str("domain", domain).Msg("WHOIS VN: Tino arrived within grace — using Tino")
					return tinoRes.resp, nil
				}
				// Tino lỗi → dùng VNNIC
				log.Info().Str("domain", domain).Msg("WHOIS VN: Tino failed in grace — using VNNIC")
				return vnnicResult, nil
			case <-graceTimer.C:
				// Hết 1s, Tino vẫn chưa về → dùng VNNIC
				log.Info().Str("domain", domain).Msg("WHOIS VN: Grace expired — using VNNIC")
				return vnnicResult, nil
			}

		case <-deadline.C:
			if vnnicResult != nil {
				log.Info().Str("domain", domain).Msg("WHOIS VN: Deadline hit — using VNNIC")
				return vnnicResult, nil
			}

			log.Warn().Str("domain", domain).Msg("WHOIS VN: Deadline hit with no results. Falling back to Tier 3.")
			return queryVNTier3Fallback(domain)

		case <-ctx.Done():
			if vnnicResult != nil {
				return vnnicResult, nil
			}
			return queryVNTier3Fallback(domain)
		}
	}

	if vnnicResult != nil {
				return vnnicResult, nil
	}

	return queryVNTier3Fallback(domain)
}

// queryVNTier3Fallback — Tầng cuối: Go-Whois Auto-Discover (Chỉ khi 2 thằng trên đều tạch)
func queryVNTier3Fallback(domain string) (*models.WhoisResponse, error) {
	log.Info().Str("domain", domain).Msg("WHOIS VN: Tier 1 & 2 failed — trying Tier 3 (Auto-Discover)")
	client := whois.NewClient()
	client.SetTimeout(4 * time.Second)
	rawText, err := client.Whois(domain, "whois.vnnic.vn")
	if err != nil && rawText == "" {
		return nil, &WhoisError{
			Message: "Không thể tra cứu thông tin tên miền này. Tên miền chưa được đăng ký hoặc hệ thống WHOIS đang gián đoạn.",
		}
	}

	rawLower := strings.ToLower(rawText)
	if strings.Contains(rawLower, "no match") ||
		strings.Contains(rawLower, "not found") ||
		strings.Contains(rawLower, "no entries found") ||
		strings.Contains(rawLower, "available") ||
		strings.Contains(rawLower, "does not exist") {
		return &models.WhoisResponse{
			Domain:          domain,
			IsVNDomain:      true,
			Status:          []string{"Available"},
			IsAvailable:     true,
			AvailableSource: "whois_port43",
		}, nil
	}

	return parseWhoisRaw(domain, rawText, true), nil
}

// queryTinoAPI gọi API Tino và map kết quả sang WhoisResponse
func queryTinoAPI(ctx context.Context, domain string) (*models.WhoisResponse, error) {
	url := tinoAPIBase + domain

	httpClient := &http.Client{Timeout: tinoTimeout}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("tino: build request failed: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; WUT-Whois/1.0)")
	req.Header.Set("Accept", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tino: http request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotFound {
		return &models.WhoisResponse{
			Domain:          domain,
			IsVNDomain:      true,
			Status:          []string{"Available"},
			IsAvailable:     true,
			AvailableSource: "tino",
		}, nil
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tino: non-200 status: %d", res.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20)) // Giới hạn 1MB tránh cạn kiệt bộ nhớ
	if err != nil {
		return nil, fmt.Errorf("tino: read body failed: %w", err)
	}

	// Sửa lỗi PHP backend: PHP thường trả về [] (empty array) thay vì null cho empty object.
	// Go struct *TinoWhoisData sẽ báo lỗi "cannot unmarshal array into Go struct".
	bodyStr := string(body)
	bodyStr = strings.ReplaceAll(bodyStr, `"whois":[]`, `"whois":null`)

	var tinoResp models.TinoAPIResponse
	if err := json.Unmarshal([]byte(bodyStr), &tinoResp); err != nil {
		return nil, fmt.Errorf("tino: json parse failed: %w", err)
	}

	if !tinoResp.Success {
		return nil, fmt.Errorf("tino: api returned success=false for %s", domain)
	}

	// Map dữ liệu Tino → WhoisResponse
	resp := &models.WhoisResponse{
		IsVNDomain: true,
		Domain:     domain,
	}

	if tinoResp.Whois != nil {
		w := tinoResp.Whois
		resp.Registrar = html.UnescapeString(w.Registrar)
		resp.Registrant = html.UnescapeString(w.RegistrantName)
		resp.RawText = stripHTML(tinoResp.Raw)
		resp.Status = w.Status

		if w.CreateDate != "" {
			resp.RegisteredOn = formatWhoisDate(w.CreateDate)
		}
		if w.ExpiredDate != "" {
			resp.ExpiresOn = formatWhoisDate(w.ExpiredDate)
		}

		// Map nameservers if we don't have them yet
		if len(resp.Nameservers) == 0 {
			for _, n := range w.Nameservers {
				resp.Nameservers = append(resp.Nameservers, strings.ToLower(strings.TrimSpace(n)))
			}
		}
	}

	if tinoResp.Available && tinoResp.Whois == nil {
		return &models.WhoisResponse{
			Domain:          domain,
			IsVNDomain:      true,
			Status:          []string{"Available"},
			IsAvailable:     true,
			AvailableSource: "tino",
		}, nil
	}

	return resp, nil
}

// queryVNNIC truy vấn trực tiếp VNNIC qua port 43 — wrap context để cancel khi parent done
func queryVNNIC(ctx context.Context, domain string) (string, error) {
	type res struct {
		raw string
		err error
	}
	ch := make(chan res, 1)
	go func() {
		client := whois.NewClient()
		client.SetTimeout(vnnicTimeout)
		raw, err := client.Whois(domain, vnnicWhoisServer)
		ch <- res{raw, err}
	}()
	select {
	case r := <-ch:
		return r.raw, r.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// =============================================
//  GENERIC DOMAIN (non-.vn)
// =============================================

func queryGenericDomain(parentCtx context.Context, domain string) (*models.WhoisResponse, error) {
	ctx, cancel := context.WithTimeout(parentCtx, 20*time.Second)
	defer cancel()

	type result struct {
		resp *models.WhoisResponse
		err  error
		tier int
	}
	// Dùng 3 tier cho domain quốc tế: Port 43 + RDAP + DomScan
	resChan := make(chan result, 3)

	// Tier 1: Port 43 (Standard WHOIS) với cơ chế bám đuổi Referral (Referral Following)
	go func() {
		whoisServer := ""
		lowerDomain := strings.ToLower(domain)
		if strings.HasSuffix(lowerDomain, ".com") || strings.HasSuffix(lowerDomain, ".net") {
			whoisServer = "whois.verisign-grs.com"
		} else if strings.HasSuffix(lowerDomain, ".org") {
			whoisServer = "whois.publicinterestregistry.org"
		}

		// Gọi hàm đệ quy để bám theo referral server (nếu có), giới hạn 2 levels
		raw, e := queryWhoisRecursive(ctx, domain, whoisServer, 0)

		var r *models.WhoisResponse
		if e == nil && raw != "" {
			r = parseWhoisRaw(domain, raw, false)
		}
		resChan <- result{r, e, 1}
	}()

	// Tier 2: RDAP Authoritative (qua IANA Bootstrap)
	go func() {
		r, e := queryRDAP(ctx, domain)
		resChan <- result{r, e, 2}
	}()

	// Tier 3: DomScan API (Authoritative Availability Signal)
	go func() {
		r, e := queryDomScanAPI(ctx, domain)
		resChan <- result{r, e, 3}
	}()

	var bestRes *models.WhoisResponse

	// Timer duy nhất — tăng lên 4s để hỗ trợ RDAP/Redirects chậm của domain quốc tế
	timer := time.NewTimer(genericBestResultTimeout)
	defer timer.Stop()

	var graceTimer *time.Timer

	for i := 0; i < 3; i++ {
		// Tạo một channel chỉ hoạt động khi graceTimer đã được thiết lập
		var graceChan <-chan time.Time
		if graceTimer != nil {
			graceChan = graceTimer.C
		}

		select {
		case res := <-resChan:
			if res.err == nil && res.resp != nil {
				if res.resp.IsAvailable {
					log.Info().Str("domain", domain).Int("tier", res.tier).Str("source", res.resp.AvailableSource).Msg("WHOIS Generic: Domain is available (Early Return)")
					return res.resp, nil
				}
				bestRes = mergeWhoisResults(bestRes, res.resp)
				if isResultComplete(bestRes) {
					log.Info().Str("domain", domain).Int("tier", res.tier).Msg("WHOIS Generic: High quality result found (Early Return)")
					return bestRes, nil
				}
				hasBasics := bestRes.Registrar != "" && bestRes.RegisteredOn != "" && len(bestRes.Nameservers) > 0
				if hasBasics && graceTimer == nil {
					log.Info().Str("domain", domain).Msg("WHOIS Generic: Basic data found, activating 1000ms grace period for high-quality data")
					graceTimer = time.NewTimer(1000 * time.Millisecond)
				}
			}
		case <-timer.C:
			if bestRes != nil {
				return bestRes, nil
			}
			// Hết 5s mà chưa có gì -> thoát khỏi vòng lặp để chuyển sang DNS discovery
			goto DoneRace
		case <-graceChan:
			if bestRes != nil {
				log.Info().Str("domain", domain).Msg("WHOIS Generic: Grace period expired")
				return bestRes, nil
			}
			continue
		case <-ctx.Done():
			if bestRes != nil {
				return bestRes, nil
			}
			return nil, &WhoisError{Message: "Yêu cầu tra cứu quá hạn (timeout)."}
		}
	}

DoneRace:

	if bestRes != nil {
		return bestRes, nil
	}

	// Tier 4: DNS Existence Check (Cú chót)
	if ns := discoverNameservers(ctx, domain); len(ns) > 0 {
		return &models.WhoisResponse{
			IsVNDomain:  false,
			Domain:      domain,
			Nameservers: ns,
			Status:      []string{"Registered (Lookup Limited)"},
			RawText:     "WHOIS query failed or blocked. Domain is registered via DNS records.",
		}, nil
	}

	return nil, &WhoisError{Message: "Không thể kết nối đến máy chủ WHOIS. Vui lòng kiểm tra lại tên miền."}
}

// queryDomScanAPI sử dụng dịch vụ bên thứ 3 để check availability cực nhanh cho domain quốc tế
func queryDomScanAPI(ctx context.Context, domain string) (*models.WhoisResponse, error) {
	apiKey := os.Getenv("DOMSCAN_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("domscan: API key not found")
	}

	// Tách name và tld
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("domscan: invalid domain format")
	}
	name := parts[0]
	tld := strings.Join(parts[1:], ".")

	apiURL := fmt.Sprintf("%s?name=%s&tlds=%s&prefer_cache=1", domscanAPIBase, url.QueryEscape(name), url.QueryEscape(tld))

	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	// Header hỗ trợ cả 2 cách như docs yêu cầu
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{Timeout: 5 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("domscan: status code %d", resp.StatusCode)
	}

	var domscanRes struct {
		Results []struct {
			Domain    string `json:"domain"`
			Available bool   `json:"available"`
			Source    string `json:"source"`
			CheckedAt string `json:"checked_at"`
		} `json:"results"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&domscanRes); err != nil {
		return nil, err
	}

	if len(domscanRes.Results) == 0 {
		return nil, fmt.Errorf("domscan: no results found")
	}

	// DomScan trả về array, ta lấy cái đầu tiên vì mình chỉ check 1 TLD
	result := domscanRes.Results[0]
	if result.Available {
		log.Info().Str("domain", domain).Str("source", result.Source).Msg("WHOIS: DomScan confirmed domain is available")
		return &models.WhoisResponse{
			Domain:          domain,
			IsAvailable:     true,
			AvailableSource: "domscan",
			Status:          []string{"Available"},
		}, nil
	}

	// Nếu không available, trả về lỗi để cuộc đua tiếp tục đợi kết quả từ RDAP/Port 43 (lấy info chi tiết hơn)
	return nil, fmt.Errorf("domscan: domain is registered")
}

// queryRDAP gọi rdap.org proxy để lấy dữ liệu json — nhận context để cancel khi cần
func queryRDAP(ctx context.Context, domain string) (*models.WhoisResponse, error) {
	// Dùng IANA RDAP Bootstrap để tìm đúng server authoritative
	url := iana.GetAuthoritativeRDAPServer(domain)
	if url == "" {
		url = "https://rdap.org/domain/" + domain
	}

	httpClient := &http.Client{Timeout: 10 * time.Second}

	// Helper để fetch RDAP JSON với SSRF check
	fetchRDAP := func(targetURL string) (*models.RDAPResponse, error) {
		if !isSafeURL(targetURL) {
			return nil, fmt.Errorf("rdap: unsafe URL detected: %s", targetURL)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; WUT-Whois/1.0)")
		req.Header.Set("Accept", "application/rdap+json")
		res, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			if res.StatusCode == http.StatusNotFound {
				return nil, fmt.Errorf("domain not found (rdap status 404)")
			}
			// Trả về error cụ thể nếu RDAP server báo lỗi
			var errResp models.RDAPResponse
			_ = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&errResp)
			if errResp.ErrorCode != 0 || errResp.Title != "" {
				return nil, fmt.Errorf("rdap error: %s (code %d)", errResp.Title, errResp.ErrorCode)
			}
			return nil, fmt.Errorf("status %d", res.StatusCode)
		}
		var r models.RDAPResponse
		if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&r); err != nil {
			return nil, err
		}
		return &r, nil
	}

	rdapResp, err := fetchRDAP(url)
	if err != nil {
		if strings.Contains(err.Error(), "domain not found (rdap status 404)") {
			return &models.WhoisResponse{
				Domain:          domain,
				IsVNDomain:      false,
				Status:          []string{"Available"},
				IsAvailable:     true,
				AvailableSource: "rdap",
			}, nil
		}
		return nil, fmt.Errorf("rdap registry: %w", err)
	}

	resp := &models.WhoisResponse{
		IsVNDomain: false,
		Domain:     domain,
		Status:     rdapResp.Status,
	}

	// Parse dates & nameservers từ Registry
	parseRDAPMeta(rdapResp, resp)
	extractNamesFromRDAP(rdapResp.Entities, resp)

	// 2. Kiểm tra Referral tới Registrar (Tầng 2 - Thick RDAP)
	if isPlaceholderRegistrant(resp.Registrant) {
		referralURL := ""

		// Ưu tiên tìm trong top-level links (Verisign style)
		for _, link := range rdapResp.Links {
			if link.Rel == "related" && strings.Contains(link.Href, "http") {
				referralURL = link.Href
				break
			}
		}

		// Nếu chưa có, tìm trong entities (Registrar entity)
		if referralURL == "" {
			for _, entity := range rdapResp.Entities {
				isRegistrar := false
				for _, role := range entity.Roles {
					if strings.ToLower(role) == "registrar" {
						isRegistrar = true
						break
					}
				}
				if isRegistrar {
					for _, link := range entity.Links {
						if (link.Rel == "self" || link.Rel == "related") && strings.Contains(link.Href, "http") {
							referralURL = link.Href
							break
						}
					}
				}
				if referralURL != "" {
					break
				}
			}
		}

		if referralURL != "" {
			log.Info().Str("domain", domain).Str("referral", referralURL).Msg("RDAP: Following referral to registrar server (Thick RDAP)")
			fullURL := referralURL
			if !strings.Contains(fullURL, "/domain/") && !strings.HasSuffix(fullURL, domain) {
				if !strings.HasSuffix(fullURL, "/") {
					fullURL += "/"
				}
				fullURL += "domain/" + domain
			}

			thickRDAP, err := fetchRDAP(fullURL)
			if err == nil {
				// Cập nhật thông tin từ Registrar
				extractNamesFromRDAP(thickRDAP.Entities, resp)
				// Gộp thêm status/nameservers nếu Registry bị thiếu
				if len(resp.Nameservers) == 0 {
					for _, ns := range thickRDAP.Nameservers {
						resp.Nameservers = append(resp.Nameservers, strings.ToLower(ns.LDHName))
					}
				}
				log.Info().Str("domain", domain).Str("registrant", resp.Registrant).Msg("RDAP: Successfully fetched Thick data")
			}
		}
	}

	// Mock a RawText response as RDAP returns JSON
	resp.RawText = generateRichRDAPText(*rdapResp)

	return resp, nil
}

// parseRDAPMeta trích xuất các thông tin metadata (dates, nameservers, status) từ RDAP
func parseRDAPMeta(rdap *models.RDAPResponse, resp *models.WhoisResponse) {
	for _, e := range rdap.Events {
		action := strings.ToLower(e.EventAction)
		switch {
		case action == "registration", action == "creation":
			resp.RegisteredOn = formatWhoisDate(e.EventDate)
		case action == "expiration", strings.Contains(action, "expiration"):
			resp.ExpiresOn = formatWhoisDate(e.EventDate)
		case action == "last changed", action == "last update", strings.Contains(action, "update"):
			resp.UpdatedOn = formatWhoisDate(e.EventDate)
		}
	}
	for _, ns := range rdap.Nameservers {
		resp.Nameservers = append(resp.Nameservers, strings.ToLower(ns.LDHName))
	}
}

// generateRichRDAPText chuyển đổi JSON RDAP thành dạng Raw Text WHOIS chuyên nghiệp
func generateRichRDAPText(rdap models.RDAPResponse) string {
	var b strings.Builder
	b.WriteString("Data retrieved via RDAP (rdap.org)\n")
	b.WriteString(fmt.Sprintf("Domain Name: %s\n", strings.ToUpper(rdap.LDHName)))

	if rdap.Handle != "" {
		b.WriteString(fmt.Sprintf("Registry Domain ID: %s\n", rdap.Handle))
	}

	// Registrar info từ obj đã extract
	var tempResp models.WhoisResponse
	extractNamesFromRDAP(rdap.Entities, &tempResp)
	if tempResp.Registrar != "" {
		b.WriteString(fmt.Sprintf("Registrar: %s\n", tempResp.Registrar))
	}

	// WHOIS Server & URL from links
	for _, link := range rdap.Links {
		if link.Rel == "related" || link.Rel == "self" {
			b.WriteString(fmt.Sprintf("Registrar URL: %s\n", link.Href))
		}
	}

	// Status
	for _, s := range rdap.Status {
		b.WriteString(fmt.Sprintf("Domain Status: %s\n", s))
	}

	// Events (Dates)
	for _, e := range rdap.Events {
		b.WriteString(fmt.Sprintf("%s: %s\n", capitalizeFirst(e.EventAction), e.EventDate))
	}

	// Nameservers
	for _, ns := range rdap.Nameservers {
		b.WriteString(fmt.Sprintf("Name Server: %s\n", strings.ToUpper(ns.LDHName)))
	}

	b.WriteString("\n>>> Last update of RDAP database: " + time.Now().UTC().Format(time.RFC3339) + " <<<\n\n")
	b.WriteString("For more information on Whois status codes, please visit https://icann.org/epp\n")
	b.WriteString("\nNOTICE: This raw data is formatted from an RDAP JSON response.\n")

	return b.String()
}

// extractNamesFromRDAP duyệt VCardArray mảng để trích xuất chỉ Registrar và Registrant name
func extractNamesFromRDAP(entities []models.RDAPEntity, resp *models.WhoisResponse) {
	for _, entity := range entities {
		name := ""
		org := ""

		if len(entity.VCardArray) >= 2 {
			if vcardData, ok := entity.VCardArray[1].([]interface{}); ok {
				for _, entry := range vcardData {
					if row, ok := entry.([]interface{}); ok && len(row) >= 4 {
						key, okKey := row[0].(string)
						if !okKey {
							continue
						}
						key = strings.ToLower(key)

						if key == "fn" {
							if s, ok := row[3].(string); ok {
								name = html.UnescapeString(s)
							}
						} else if key == "org" {
							if s, ok := row[3].(string); ok {
								org = html.UnescapeString(s)
							}
						}
					}
				}
			}
		}

		// Ưu tiên ORG hơn FN cho thực thể Registrant/Registrar nếu FN là placeholder
		finalName := name
		if isPlaceholderRegistrant(name) && org != "" {
			finalName = org
		} else if finalName == "" {
			finalName = org
		}

		if finalName != "" {
			for _, role := range entity.Roles {
				roleLower := strings.ToLower(role)
				switch roleLower {
				case "registrar":
					if resp.Registrar == "" || isPlaceholderRegistrant(resp.Registrar) {
						resp.Registrar = finalName
					}
				case "registrant":
					if resp.Registrant == "" || isPlaceholderRegistrant(resp.Registrant) {
						resp.Registrant = finalName
					}
				}
			}
		}

		// Đệ quy sâu xuống để tìm các lồng nhau (Verify cho Verisign .com)
		if len(entity.Entities) > 0 {
			extractNamesFromRDAP(entity.Entities, resp)
		}
	}
}

// =============================================
//  SHARED HELPERS
// =============================================

// mergeWhoisResults gộp thông tin từ hai nguồn để có kết quả đầy đủ nhất
func mergeWhoisResults(base, extra *models.WhoisResponse) *models.WhoisResponse {
	if base == nil {
		if extra != nil {
			extra.Status = deduplicateStatuses(extra.Status)
		}
		return extra
	}
	if extra == nil {
		if base != nil {
			base.Status = deduplicateStatuses(base.Status)
		}
		return base
	}

	// Xử lý Trust Hierarchy cho tín hiệu Available
	if extra.IsAvailable {
		// Nếu extra có độ tin cậy cao (RDAP, Tino) thì luôn ưu tiên ghi đè
		if extra.AvailableSource == "rdap" || extra.AvailableSource == "tino" || extra.AvailableSource == "domscan" {
			base.IsAvailable = true
			base.AvailableSource = extra.AvailableSource
			base.Status = []string{"Available"}
		} else if !base.IsAvailable {
			// Nếu extra là port43 báo available, nhưng base có dữ liệu thì không override
			// Trừ khi base chỉ là record rỗng không có gì
			if base.Registrar == "" && base.RegisteredOn == "" {
				base.IsAvailable = true
				base.AvailableSource = extra.AvailableSource
				base.Status = []string{"Available"}
			}
		}
	}

	// Merge field-by-field: ưu tiên giá trị cụ thể hơn (RDAP thường xịn hơn Port 43 Thin)
	if extra.Registrar != "" {
		if base.Registrar == "" || isPlaceholderRegistrant(base.Registrar) {
			base.Registrar = extra.Registrar
		}
	}

	if extra.Registrant != "" {
		if base.Registrant == "" || isPlaceholderRegistrant(base.Registrant) {
			base.Registrant = extra.Registrant
		}
	}
	if base.RegisteredOn == "" {
		base.RegisteredOn = extra.RegisteredOn
	}
	if base.ExpiresOn == "" {
		base.ExpiresOn = extra.ExpiresOn
	}
	if base.UpdatedOn == "" {
		base.UpdatedOn = extra.UpdatedOn
	}
	if len(base.Nameservers) == 0 {
		base.Nameservers = extra.Nameservers
	} else if len(extra.Nameservers) > 0 {
		// Gộp nameservers từ 2 nguồn, loại bỏ trùng lặp
		nsMap := make(map[string]bool)
		for _, ns := range base.Nameservers {
			nsMap[strings.ToLower(ns)] = true
		}
		for _, ns := range extra.Nameservers {
			lower := strings.ToLower(ns)
			if !nsMap[lower] {
				base.Nameservers = append(base.Nameservers, lower)
				nsMap[lower] = true
			}
		}
	}
	// Gộp Status từ cả 2 nguồn
	allStatus := append(base.Status, extra.Status...)
	base.Status = deduplicateStatuses(allStatus)

	// Luôn giữ RawText dài hơn hoặc text từ WHOIS Port 43
	if len(extra.RawText) > len(base.RawText) && !strings.Contains(extra.RawText, "RDAP") {
		base.RawText = extra.RawText
	}

	return base
}

// deduplicateStatuses xóa các trạng thái trùng lặp, chuẩn hóa chuỗi và loại bỏ URL thừa
func deduplicateStatuses(statuses []string) []string {
	if len(statuses) == 0 {
		return statuses
	}

	statusMap := make(map[string]string)
	for _, s := range statuses {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		// Chuẩn hóa: Một số WHOIS vứt kèm URL hoặc [ICANN] (e.g., "clientDeleteProhibited https://...")
		cleanStatus := s

		// Cắt bỏ phần bắt đầu bằng " http"
		if idx := strings.Index(cleanStatus, " http"); idx != -1 {
			cleanStatus = cleanStatus[:idx]
		}
		// Cắt bỏ phần bắt đầu bằng " ["
		if idx := strings.Index(cleanStatus, " ["); idx != -1 {
			cleanStatus = cleanStatus[:idx]
		}
		// Cắt dính liền (nếu có)
		if idx := strings.Index(cleanStatus, "https://"); idx != -1 {
			cleanStatus = cleanStatus[:idx]
		}
		if idx := strings.Index(cleanStatus, "http://"); idx != -1 {
			cleanStatus = cleanStatus[:idx]
		}

		cleanStatus = strings.TrimSpace(cleanStatus)

		// Gom key về chuẩn chữ thường, không dấu cách để tránh "client transfer prohibited" vs "clientTransferProhibited"
		key := strings.ReplaceAll(strings.ToLower(cleanStatus), " ", "")

		if _, exists := statusMap[key]; !exists {
			statusMap[key] = cleanStatus
		}
	}

	result := make([]string, 0, len(statusMap))
	for _, s := range statusMap {
		result = append(result, s)
	}
	return result

}

// parseWhoisRaw parse raw text WHOIS thành WhoisResponse
func parseWhoisRaw(domain, rawText string, isVN bool) *models.WhoisResponse {
	resp := &models.WhoisResponse{
		Domain:     domain, // Bắt buộc dùng domain input để tránh mất TLD (.com, .net...)
		IsVNDomain: isVN,
		RawText:    rawText,
	}

	result, parseErr := whoisparser.Parse(rawText)
	if parseErr != nil {
		log.Warn().Err(parseErr).Str("domain", domain).Msg("WHOIS parse failed, returning raw text")
		resp.IsParseFailed = true
		return resp
	}

	if result.Domain != nil {
		// GIỮ NGUYÊN: Không ghi đè resp.Domain bằng result.Domain.Name vì parser có thể trả về "google" cho "google.com"
		resp.Status = result.Domain.Status
		for _, ns := range result.Domain.NameServers {
			nsLower := strings.ToLower(strings.TrimSpace(ns))
			// Lọc bỏ NS thuộc TLD registry (không phải NS thực của domain)
			if iana.IsRegistryNS(nsLower) {
				continue
			}
			resp.Nameservers = append(resp.Nameservers, nsLower)
		}
		if result.Domain.CreatedDate != "" {
			resp.RegisteredOn = formatWhoisDate(result.Domain.CreatedDate)
		}
		if result.Domain.ExpirationDate != "" {
			resp.ExpiresOn = formatWhoisDate(result.Domain.ExpirationDate)
		}
		if result.Domain.UpdatedDate != "" {
			resp.UpdatedOn = formatWhoisDate(result.Domain.UpdatedDate)
		}
	}

	// Fallback cho Status của .vn nếu parser mặc định bỏ lỡ
	if isVN && len(resp.Status) == 0 {
		// VNNIC thường dùng "Status: ..." hoặc "Domain Status: ..."
		lines := strings.Split(resp.RawText, "\n")
		for _, line := range lines {
			lowerLine := strings.ToLower(line)
			if strings.Contains(lowerLine, "status:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					status := strings.TrimSpace(parts[1])
					if status != "" {
						resp.Status = append(resp.Status, status)
					}
				}
			}
		}
	}

	if result.Registrar != nil {
		resp.Registrar = html.UnescapeString(result.Registrar.Name)
	}
	if result.Registrant != nil {
		resp.Registrant = html.UnescapeString(result.Registrant.Name)
		if resp.Registrant == "" {
			resp.Registrant = html.UnescapeString(result.Registrant.Organization)
		}
	}

	// High-speed fallback for Registrant
	if resp.Registrant == "" {
		lines := strings.Split(resp.RawText, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "registrant organization:") || strings.HasPrefix(lower, "registrant name:") || strings.HasPrefix(lower, "registrant:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					val := strings.TrimSpace(parts[1])
					if val != "" && val != "-" && !strings.Contains(strings.ToLower(val), "redacted") {
						resp.Registrant = html.UnescapeString(val)
						break
					}
				}
			}
		}
	}

	// Xóa trùng status (gọi cuối cùng sau khi parse xong)
	resp.Status = deduplicateStatuses(resp.Status)

	// Detect domain "Available" từ raw text (domain chưa đăng ký)
	if len(resp.Status) == 0 && resp.Registrar == "" && resp.RegisteredOn == "" {
		rawLower := strings.ToLower(rawText)
		if strings.Contains(rawLower, "no match for") ||
			strings.Contains(rawLower, "not found") ||
			strings.Contains(rawLower, "no data found") ||
			strings.Contains(rawLower, "object does not exist") ||
			strings.Contains(rawLower, "is available for registration") ||
			strings.Contains(rawLower, "domain not found") {
			resp.Status = []string{"Available"}
			resp.IsAvailable = true
			resp.AvailableSource = "whois_port43"
		}
	}

	// Fallback domain name
	if resp.Domain == "" {
		resp.Domain = domain
	}

	return resp
}

func formatWhoisDate(raw string) string {
	// Early return cho RFC3339 (RDAP, hầu hết registry hiện đại)
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t.UTC().Format(time.RFC3339)
	}

	formats := []string{
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"January 02, 2006",
		"2006.01.02",
		"02/01/2006", // VN/International
		"20060102",   // Compact 1
		"2006/01/02", // Generic
		"02-01-2006", // Generic 2
	}
	for _, f := range formats {
		if t, err := time.Parse(f, raw); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return raw
}

// stripHTML xóa các thẻ HTML đơn giản khỏi raw text của Tino API
func stripHTML(s string) string {
	s = strings.ReplaceAll(s, "<br />", "\n")
	s = strings.ReplaceAll(s, "<br>", "\n")
	s = strings.ReplaceAll(s, "<br/>", "\n")

	// Remove remaining HTML tags
	result := strings.Builder{}
	inTag := false
	for _, r := range s {
		if r == '<' {
			inTag = true
			continue
		}
		if r == '>' {
			inTag = false
			continue
		}
		if !inTag {
			result.WriteRune(r)
		}
	}
	return strings.TrimSpace(result.String())
}

// discoverNameservers lấy danh sách nameserver gốc (từ Parent Zone delegation),
// không phải Child Zone NS records.
// Chiến lược: Nhảy thẳng tới TLD nameserver hỏi delegation (nhanh ~0.2s)
// Fallback: Root Trace nếu TLD direct query thất bại.
func discoverNameservers(ctx context.Context, domain string) []string {
	// Tier 1: TLD Direct Query — hỏi thẳng TLD nameserver lấy delegation
	ns := discoverNSViaTLDDirect(domain)
	if len(ns) > 0 {
		log.Info().Str("domain", domain).Strs("nameservers", ns).Msg("WHOIS: NS discovered via TLD direct (fast path)")
		return ns
	}

	// Tier 2: Fallback — Root Trace đầy đủ nếu TLD direct thất bại
	tracer := dnsservice.NewTraceResolver(5 * time.Second)
	nsInfos, err := tracer.DiscoverAuthorities(domain)
	if err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("WHOIS: DNS root trace for nameservers failed")
		return nil
	}

	for _, info := range nsInfos {
		ns = append(ns, strings.ToLower(info.Nameserver))
	}
	log.Info().Str("domain", domain).Strs("nameservers", ns).Msg("WHOIS: NS discovered via root trace (fallback)")
	return ns
}

// discoverNSViaTLDDirect hỏi trực tiếp TLD nameserver để lấy delegation records.
// Ví dụ: Với "google.com", hỏi thẳng a.gtld-servers.net (quản lý .com) xem google.com
// được delegate tới NS nào. Đây chính là NS gốc từ Registry (Parent Zone).
func discoverNSViaTLDDirect(domain string) []string {
	// Xác định TLD
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return nil
	}
	tld := parts[len(parts)-1]

	// Lấy TLD NS IP từ hệ thống IANA (sẽ tự động lazy-resolve nếu chưa có)
	tldNS := iana.GetTLDNS(tld)

	if tldNS == "" {
		return nil
	}

	c := new(dnslib.Client)
	c.Timeout = 2 * time.Second

	msg := new(dnslib.Msg)
	msg.SetQuestion(dnslib.Fqdn(domain), dnslib.TypeNS)
	msg.RecursionDesired = false // NON-recursive → lấy delegation từ parent zone

	resp, _, err := c.Exchange(msg, tldNS+":53")
	if err != nil || resp == nil {
		return nil
	}

	var result []string

	// Nếu Authority section có NS records → đây là delegation từ TLD (Parent Zone)
	if len(resp.Ns) > 0 {
		for _, rr := range resp.Ns {
			if ns, ok := rr.(*dnslib.NS); ok {
				result = append(result, strings.ToLower(strings.TrimSuffix(ns.Ns, ".")))
			}
		}
	}

	// Hoặc nếu Answer section có NS → domain tự quản lý
	if len(result) == 0 && len(resp.Answer) > 0 {
		for _, rr := range resp.Answer {
			if ns, ok := rr.(*dnslib.NS); ok {
				result = append(result, strings.ToLower(strings.TrimSuffix(ns.Ns, ".")))
			}
		}
	}

	return result
}

// WhoisError là custom error với message thân thiện
type WhoisError struct {
	Message string
}

func (e *WhoisError) Error() string {
	return e.Message
}

// isPlaceholderRegistrant kiểm tra xem chuỗi registrant có phải là placeholder vô nghĩa (như Domain Admin) không.
func isPlaceholderRegistrant(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "-" {
		return true
	}
	// Danh sách các placeholder thường gặp trong WHOIS/RDAP khi bị ẩn hoặc dùng info mặc định
	placeholders := []string{
		"domain admin",
		"redacted for privacy",
		"data protected",
		"contact privacy",
		"identity protection",
		"private",
		"whois agent",
		"registrant of",
		"gdpr",
		"statutory mask",
		"data redacted",
		"redacted registrant",
		"redacted by registrar",
		"selectively redacted",
		"redacted registrant name",
		"proprietary",
		"redacted by privacy",
	}
	for _, p := range placeholders {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// isResultComplete kiểm tra xem kết quả đã đủ "chất lượng" để trả về sớm chưa.
func isResultComplete(r *models.WhoisResponse) bool {
	if r == nil {
		return false
	}
	// Với domain quốc tế (.com, .net...), Registrant thường bị ẩn (GDPR).
	// Chỉ cần có Registrar + Dates + Nameservers là đủ để coi là kết quả tốt.
	hasBasics := r.Registrar != "" && r.RegisteredOn != "" && r.ExpiresOn != "" && len(r.Nameservers) > 0

	if r.IsVNDomain {
		// Domain .vn thường có đủ Registrant, nên đợi thêm tí
		return hasBasics && r.Registrant != ""
	}

	return hasBasics
}

// queryWhoisRecursive thực hiện truy vấn WHOIS port 43 và tự động bám theo Referral Server nếu có.
// Hỗ trợ mô hình "Thin WHOIS" của .com/.net.
// depth: giới hạn số lần follow referral để tránh loop vô tận (tối đa 2 levels).
func queryWhoisRecursive(ctx context.Context, domain, startServer string, depth int) (string, error) {
	const maxDepth = 2

	client := whois.NewClient()
	client.SetTimeout(5 * time.Second) // Fail faster if server hangs

	raw, err := doWhoisWithCtx(ctx, client, domain, startServer)
	if err != nil {
		return "", err
	}

	// Đã đạt giới hạn depth → trả kết quả hiện tại, không follow tiếp
	if depth >= maxDepth {
		log.Warn().Str("domain", domain).Int("depth", depth).Msg("WHOIS: max referral depth reached, stopping")
		return raw, nil
	}

	// TỐI ƯU: Nếu là lượt truy vấn đầu tiên và đã có đủ data cốt lõi, không cần follow referral
	// Việc này giúp giảm latency từ ~2.5s xuống còn ~0.5s cho .com/.net
	if depth == 0 {
		parsed := parseWhoisRaw(domain, raw, false)
		if parsed != nil && parsed.Registrar != "" && parsed.RegisteredOn != "" && len(parsed.Nameservers) > 0 {
			log.Info().Str("domain", domain).Msg("WHOIS: Registry data is complete enough, skipping referral for speed")
			return raw, nil
		}
	}

	// Phân tích raw text để tìm "Whois Server" hoặc "Registrar WHOIS Server"
	referralServer := ""
	lines := strings.Split(raw, "\n")
	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		if strings.Contains(lowerLine, "whois server:") || (strings.Contains(lowerLine, "referral") && strings.Contains(lowerLine, "whois://")) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				server := strings.TrimSpace(parts[1])
				server = strings.TrimPrefix(server, "whois://")
				if idx := strings.Index(server, " "); idx != -1 {
					server = server[:idx]
				}
				if server != "" && server != startServer {
					referralServer = server
					break
				}
			}
		}
	}

	// Nếu tìm thấy referral server mới -> truy vấn tiếp
	if referralServer != "" {
		log.Info().Str("domain", domain).Str("registry", startServer).Str("registrar", referralServer).Int("depth", depth+1).Msg("WHOIS: Following referral to registrar server")
		raw2, err2 := doWhoisWithCtx(ctx, client, domain, referralServer)
		if err2 == nil {
			return raw + "\n\n<<< REFERRAL DATA FROM " + referralServer + " >>>\n\n" + raw2, nil
		}
	}

	return raw, nil
}

// doWhoisWithCtx bọc whois.Client bằng goroutine và select context để có thể dừng ngay lập tức khi timeout.
func doWhoisWithCtx(ctx context.Context, client *whois.Client, domain, server string) (string, error) {
	ch := make(chan struct {
		raw string
		err error
	}, 1)

	go func() {
		var r string
		var e error
		if server != "" {
			r, e = client.Whois(domain, server)
		} else {
			r, e = client.Whois(domain)
		}
		ch <- struct {
			raw string
			err error
		}{r, e}
	}()

	select {
	case res := <-ch:
		return res.raw, res.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// capitalizeFirst viết hoa chữ cái đầu tiên của chuỗi (thay thế strings.Title deprecated)
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// isSafeURL kiểm tra URL để ngăn chặn SSRF
func isSafeURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return false
	}

	host := u.Hostname()
	if host == "localhost" {
		return false
	}

	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return false
		}
	}
	return true
}
