package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-pkgz/expirable-cache/v3"
	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
	"github.com/rs/zerolog/log"
	dnsservice "tools.bctechvibe.com/server/internal/modules/dns/service"
	"tools.bctechvibe.com/server/internal/modules/whois/models"
)

const (
	cacheTTLDefault = 1 * time.Hour
	cacheTTLVN      = 24 * time.Hour

	// WHOIS server cho VNNIC (toàn bộ .vn và sub-ccTLD như .com.vn, .net.vn, .io.vn...)
	vnnicWhoisServer = "whois.vnnic.vn"

	// Tino API endpoint - Tầng 1 ưu tiên cho .vn
	tinoAPIBase = "http://tino.vn/backend-api/whois/"
	tinoTimeout = 6 * time.Second

	// Timeout cho VNNIC port 43 (tầng fallback)
	vnnicTimeout = 10 * time.Second
)

var (
	whoisCache cache.Cache[string, *models.WhoisResponse]
	metaCache  cache.Cache[string, *models.WhoisMeta]
)

// init khởi tạo cache ở package level, đảm bảo chỉ chạy 1 lần khi import.
func init() {
	whoisCache = cache.NewCache[string, *models.WhoisResponse]().WithLRU().WithTTL(cacheTTLDefault)
	metaCache = cache.NewCache[string, *models.WhoisMeta]().WithLRU().WithTTL(cacheTTLDefault)
}

// isVNDomain kiểm tra tên miền có phải .vn không (bao gồm .com.vn, .net.vn, .io.vn, ...)
func isVNDomain(domain string) bool {
	lower := strings.ToLower(domain)
	return strings.HasSuffix(lower, ".vn")
}

// LookupWhois thực hiện truy vấn WHOIS cho một domain.
// bypassCache=true ép tải lại dữ liệu mới (không áp dụng cho .vn).
func LookupWhois(domain string, bypassCache bool) (*models.WhoisResponse, *models.WhoisMeta, error) {

	isVN := isVNDomain(domain)
	cacheKey := strings.ToLower(domain)

	// .vn: không cho bypass cache (bảo vệ rate limit VNNIC & Tino)
	if isVN {
		bypassCache = false
	}

	// Kiểm tra cache trước
	if !bypassCache {
		if cached, ok := whoisCache.Get(cacheKey); ok {
			meta, _ := metaCache.Get(cacheKey)
			if meta != nil {
				cachedMeta := *meta
				cachedMeta.Cached = true
				return cached, &cachedMeta, nil
			}
			return cached, meta, nil
		}
	}

	// Thực hiện truy vấn WHOIS thực tế (và discover Nameservers song song)
	log.Info().Str("domain", domain).Bool("isVN", isVN).Msg("WHOIS: querying live data")

	type whoisResult struct {
		resp *models.WhoisResponse
		err  error
	}
	whoisChan := make(chan whoisResult, 1)
	nsChan := make(chan []string, 1)

	go func() {
		var resp *models.WhoisResponse
		var err error
		if isVN {
			resp, err = queryVNDomain(domain)
		} else {
			resp, err = queryGenericDomain(domain)
		}
		whoisChan <- whoisResult{resp, err}
	}()

	// DNS discover chạy song song luôn, tiết kiệm ~8s nếu WHOIS không trả về NS
	go func() {
		nsChan <- discoverNameservers(domain)
	}()

	wr := <-whoisChan
	if wr.err != nil {
		log.Error().Err(wr.err).Str("domain", domain).Msg("WHOIS all sources failed")
		return nil, nil, wr.err
	}

	resp := wr.resp

	// Nếu WHOIS không có NS thì dùng kết quả DNS (đã chạy song song từ trước)
	if len(resp.Nameservers) == 0 {
		resp.Nameservers = <-nsChan
	}
	// Nếu WHOIS đã có NS rồ̀i thì channel nsChan bị bỏ rơi kệ nó, GC sẽ tự dọn

	// Lấy thông tin DNSSEC từ DNS module (tái sử dụng)
	dnssecInfo := dnsservice.ValidateDNSSEC("cloudflare", domain)
	resp.DNSSEC = &dnssecInfo

	// Lưu cache với TTL phù hợp
	ttl := cacheTTLDefault
	if isVN {
		ttl = cacheTTLVN
	}
	whoisCache.Set(cacheKey, resp, ttl)

	now := time.Now().UTC().Format(time.RFC3339)
	meta := &models.WhoisMeta{
		FetchedAt: now,
		Cached:    false,
	}
	metaCache.Set(cacheKey, meta, ttl)

	return resp, meta, nil
}

// =============================================
//  VN DOMAIN: Fallback 3 tầng
// =============================================

// queryVNDomain thực hiện 3 tầng fallback cho tên miền .vn:
// Tầng 1: Tino API + Tầng 2: VNNIC Port 43 (Chạy song song) → Tầng 3: Go-Whois Auto-Discover
func queryVNDomain(domain string) (*models.WhoisResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type result struct {
		resp *models.WhoisResponse
		err  error
		tier int
	}
	resChan := make(chan result, 2)

	// Chạy Tino API (Tier 1) — truyền context để cancel khi không cần nữa
	go func() {
		r, e := queryTinoAPI(ctx, domain)
		resChan <- result{r, e, 1}
	}()

	// Chạy VNNIC Port 43 (Tier 2) — truyền context để cancel khi không cần nữa
	go func() {
		raw, e := queryVNNIC(ctx, domain)
		var r *models.WhoisResponse
		if e == nil {
			r = parseWhoisRaw(domain, raw, true)
		}
		resChan <- result{r, e, 2}
	}()

	// Timer duy nhất bên ngoài select — giảm xuống 3s để tăng tốc độ nếu Tier 2 đã xong trước
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()

	var tier2Res *result
	for i := 0; i < 2; i++ {
		select {
		case res := <-resChan:
			if res.err == nil {
				if res.tier == 1 {
					// Tino về → trả luôn vì Tino parse rất chuẩn
					log.Info().Str("domain", domain).Msg("WHOIS VN: Tier 1 (Tino) returned")
					return res.resp, nil
				}
				tier2Res = &res
			}
		case <-timer.C:
			// Hết 6s, nếu đã có Tier 2 thì dùng luôn
			if tier2Res != nil {
				log.Info().Str("domain", domain).Msg("WHOIS VN: Timer expired, using Tier 2 (VNNIC)")
				return tier2Res.resp, nil
			}
			// Không có gì sau 6s → chạy ngay tier3, không đợi thêm
			goto tier3Fallback
		case <-ctx.Done():
			if tier2Res != nil {
				return tier2Res.resp, nil
			}
			// Context hết hạn, thoát loop hoàn toàn
			goto tier3Fallback
		}
	}

	// Loop kết thúc bình thường — kiểm tra kết quả cuối cùng
	if tier2Res != nil {
		log.Info().Str("domain", domain).Msg("WHOIS VN: Falling back to Tier 2 (VNNIC)")
		return tier2Res.resp, nil
	}

tier3Fallback:
	// ---- Tầng cuối: Go-Whois Auto-Discover (Chỉ khi 2 thằng trên đều tạch) ----
	log.Info().Str("domain", domain).Msg("WHOIS VN: Tier 1 & 2 failed, trying Tier 3 (Auto-Discover)")
	client := whois.NewClient()
	client.SetTimeout(5 * time.Second)
	rawText, err := client.Whois(domain)
	if err != nil {
		return nil, &WhoisError{
			Message: "Không thể tra cứu thông tin tên miền này. Tên miền chưa được đăng ký hoặc hệ thống WHOIS đang gián đoạn.",
		}
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

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tino: non-200 status: %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("tino: read body failed: %w", err)
	}

	var tinoResp models.TinoAPIResponse
	if err := json.Unmarshal(body, &tinoResp); err != nil {
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
		resp.Registrar = w.Registrar
		resp.Registrant = w.RegistrantName
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

	// Nếu available=true và không có whois data → tên miền chưa đăng ký
	if tinoResp.Available && tinoResp.Whois == nil {
		return nil, fmt.Errorf("tino: domain %s is available (not registered)", domain)
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

func queryGenericDomain(domain string) (*models.WhoisResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	type result struct {
		resp *models.WhoisResponse
		err  error
		tier int
	}
	resChan := make(chan result, 3)

	// Tier 1: Port 43 (Standard WHOIS)
	go func() {
		client := whois.NewClient()
		client.SetTimeout(5 * time.Second)
		raw, e := client.Whois(domain)
		var r *models.WhoisResponse
		if e == nil {
			r = parseWhoisRaw(domain, raw, false)
		}
		resChan <- result{r, e, 1}
	}()

	// Tier 2: RDAP — truyền context
	go func() {
		r, e := queryRDAP(ctx, domain)
		resChan <- result{r, e, 2}
	}()

	// Tier 3: Tino API (Dùng làm fallback nhanh) — truyền context
	go func() {
		r, e := queryTinoAPI(ctx, domain)
		resChan <- result{r, e, 3}
	}()

	var bestRes *models.WhoisResponse

	// Timer duy nhất — chỉ fire 1 lần, giảm xuống 2s để tăng tối đa tốc độ (RDAP/Tino thường nhanh)
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()

	deadlineFired := false

	for i := 0; i < 3; i++ {
		select {
		case res := <-resChan:
			if res.err == nil {
				// Nếu có Port 43 (Tier 1) - Trả về ngay vì nó đầy đủ nhất
				if res.tier == 1 {
					log.Info().Str("domain", domain).Msg("WHOIS Generic: Port 43 success (fast)")
					return res.resp, nil
				}
				// Lưu lại kết quả Tier 2/3 để dùng nếu Tier 1 chậm
				if bestRes == nil || res.tier < 3 {
					bestRes = res.resp
				}
				// Nếu deadline đã hết mà có result → trả luôn
				if deadlineFired && bestRes != nil {
					log.Info().Str("domain", domain).Msg("WHOIS Generic: Post-deadline result, using fallback")
					return bestRes, nil
				}
			}
		case <-timer.C:
			deadlineFired = true
			// Đã hết thời gian chờ ưu tiên, nếu có bất kỳ kết quả nào thì dùng luôn
			if bestRes != nil {
				log.Info().Str("domain", domain).Msg("WHOIS Generic: Port 43 slow, using fallback")
				return bestRes, nil
			}
			// Timer đã consumed, loop tiếp tục nhưng case này không fire lại
		case <-ctx.Done():
			if bestRes != nil {
				return bestRes, nil
			}
			return nil, &WhoisError{Message: "Yêu cầu tra cứu quá hạn (timeout)."}
		}
	}

	if bestRes != nil {
		return bestRes, nil
	}

	// Tier 4: DNS Existence Check (Cú chót)
	if ns := discoverNameservers(domain); len(ns) > 0 {
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

// queryRDAP gọi rdap.org proxy để lấy dữ liệu json — nhận context để cancel khi cần
func queryRDAP(ctx context.Context, domain string) (*models.WhoisResponse, error) {
	url := "https://rdap.org/domain/" + domain
	httpClient := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("rdap: build request failed: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; WUT-Whois/1.0)")
	req.Header.Set("Accept", "application/rdap+json")

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rdap: request failed: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rdap: non-200 status: %d", res.StatusCode)
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("rdap: read body failed: %w", err)
	}

	var rdapResp models.RDAPResponse
	if err := json.Unmarshal(body, &rdapResp); err != nil {
		return nil, fmt.Errorf("rdap: json parse failed: %w", err)
	}

	if rdapResp.ErrorCode != 0 {
		return nil, fmt.Errorf("rdap: error code returned")
	}

	resp := &models.WhoisResponse{
		IsVNDomain: false,
		Domain:     domain, // Bắt buộc dùng domain input
		Status:     rdapResp.Status,
	}

	// Parse events (Registration, Expiration, Updated)
	for _, e := range rdapResp.Events {
		switch e.EventAction {
		case "registration":
			resp.RegisteredOn = formatWhoisDate(e.EventDate)
		case "expiration":
			resp.ExpiresOn = formatWhoisDate(e.EventDate)
		case "last changed":
			resp.UpdatedOn = formatWhoisDate(e.EventDate)
		}
	}

	// Extract Registrar
	resp.Registrar = getRegistrarFromRDAP(rdapResp)

	// Fallback to title if registrar still empty and title looks like a registrar
	if resp.Registrar == "" && rdapResp.Title != "" && !strings.Contains(strings.ToLower(rdapResp.Title), "domain") {
		resp.Registrar = rdapResp.Title
	}

	// Nameservers
	for _, ns := range rdapResp.Nameservers {
		resp.Nameservers = append(resp.Nameservers, strings.ToLower(ns.LDHName))
	}

	// Mock a RawText response as RDAP returns JSON
	resp.RawText = generateRichRDAPText(rdapResp)

	return resp, nil
}

// generateRichRDAPText chuyển đổi JSON RDAP thành dạng Raw Text WHOIS chuyên nghiệp
func generateRichRDAPText(rdap models.RDAPResponse) string {
	var b strings.Builder
	b.WriteString("Data retrieved via RDAP (rdap.org)\n")
	b.WriteString(fmt.Sprintf("Domain Name: %s\n", strings.ToUpper(rdap.LDHName)))
	
	if rdap.Handle != "" {
		b.WriteString(fmt.Sprintf("Registry Domain ID: %s\n", rdap.Handle))
	}

	// Registrar info — tái sử dụng getRegistrarFromRDAP thay vì duplicate vCard parsing
	registrar := getRegistrarFromRDAP(rdap)
	if registrar != "" {
		b.WriteString(fmt.Sprintf("Registrar: %s\n", registrar))
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

// getRegistrarFromRDAP trích xuất tên nhà đăng ký từ cấu trúc vcardArray của RDAP entities
func getRegistrarFromRDAP(rdap models.RDAPResponse) string {
	for _, entity := range rdap.Entities {
		isRegistrar := false
		for _, role := range entity.Roles {
			if role == "registrar" {
				isRegistrar = true
				break
			}
		}
		if !isRegistrar {
			continue
		}
		// vCardArray format: ["vcard", [ ["fn", {}, "text", "Name"], ... ]]
		if len(entity.VCardArray) < 2 {
			continue
		}
		vcardData, ok := entity.VCardArray[1].([]interface{})
		if !ok {
			continue
		}
		for _, entry := range vcardData {
			row, ok := entry.([]interface{})
			if !ok || len(row) < 4 {
				continue
			}
			// row[0] là tên field (ví dụ: "fn"), row[3] là giá trị (ví dụ: "WebNic.cc")
			if name, ok := row[0].(string); ok && strings.ToLower(name) == "fn" {
				if fullName, ok := row[3].(string); ok {
					return fullName
				}
			}
		}
	}
	return ""
}

// =============================================
//  SHARED HELPERS
// =============================================

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
			resp.Nameservers = append(resp.Nameservers, strings.ToLower(strings.TrimSpace(ns)))
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
		resp.Registrar = result.Registrar.Name
	}
	if result.Registrant != nil {
		resp.Registrant = result.Registrant.Name
	}

	// Fallback domain name
	if resp.Domain == "" {
		resp.Domain = domain
	}

	return resp
}

// formatWhoisDate cố gắng parse và format lại ngày tháng từ WHOIS
func formatWhoisDate(raw string) string {
	formats := []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z07:00",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
		"02-Jan-2006",
		"January 02, 2006",
		"2006.01.02",
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

// discoverNameservers truy vấn DNS Root Trace để lấy danh sách nameserver chuẩn xác
// Sử dụng cùng logic DiscoverAuthorities như tool DNS Lookup
func discoverNameservers(domain string) []string {
	tracer := dnsservice.NewTraceResolver(8 * time.Second)
	nsInfos, err := tracer.DiscoverAuthorities(domain)
	if err != nil {
		log.Warn().Err(err).Str("domain", domain).Msg("WHOIS: DNS root trace for nameservers failed")
		return nil
	}

	var ns []string
	for _, info := range nsInfos {
		ns = append(ns, strings.ToLower(info.Nameserver))
	}
	log.Info().Str("domain", domain).Strs("nameservers", ns).Msg("WHOIS: nameservers discovered via DNS root trace")
	return ns
}

// WhoisError là custom error với message thân thiện
type WhoisError struct {
	Message string
}

func (e *WhoisError) Error() string {
	return e.Message
}

// capitalizeFirst viết hoa chữ cái đầu tiên của chuỗi (thay thế strings.Title deprecated)
func capitalizeFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
