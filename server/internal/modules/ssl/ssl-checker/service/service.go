// ============================================
// FILE: ssl-checker/service/service.go
//
// Core SSL Scanner:
// - DNS Resolution (dual-lookup)
// - TLS Handshake (strict → insecure fallback)
// - Trust Analyzer
// - Certificate Chain Builder
// ============================================

package service

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"tools.bctechvibe.com/server/internal/modules/ssl/ssl-checker/models"
)

var (
	ErrDNSFailed      = errors.New("dns resolve failed")
	ErrTLSFailed      = errors.New("tls dial failed")
	ErrNoCertificates = errors.New("no certificates found")
	ErrNoIP           = errors.New("no valid ip")
)

// ===========================
// DNS RESOLUTION
// ===========================

func resolveIP(ctx context.Context, domain string) (string, error) {

	type result struct {
		ips []net.IP
		err error
	}

	// Tạo context con với timeout
	dnsCtx, dnsCancel := context.WithTimeout(ctx, DNSResolveTimeout)
	defer dnsCancel()

	// Pattern cancel context để tránh leak goroutine khi hàm return sớm
	gCtx, gCancel := context.WithCancel(dnsCtx)
	defer gCancel()

	ch := make(chan result, 2)

	// Google DNS
	go func() {
		ips, err := lookupWithDNS(gCtx, domain, "8.8.8.8:53")
		select {
		case ch <- result{ips, err}:
		case <-gCtx.Done():
		}
	}()

	// System resolver
	go func() {
		r := &net.Resolver{}
		ips, err := r.LookupIP(gCtx, "ip", domain)
		select {
		case ch <- result{ips, err}:
		case <-gCtx.Done():
		}
	}()

	var lastErr error

	for i := 0; i < 2; i++ {
		select {
		case res := <-ch:
			if res.err == nil && len(res.ips) > 0 {
				return pickIP(res.ips)
			}
			if res.err != nil {
				lastErr = res.err
			}
		case <-ctx.Done():
			return "", ErrDNSFailed
		}
	}

	if lastErr != nil {
		return "", fmt.Errorf("%w: %v", ErrDNSFailed, lastErr)
	}

	return "", ErrNoIP
}

func pickIP(ips []net.IP) (string, error) {
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			return v4.String(), nil
		}
	}
	for _, ip := range ips {
		if ip.To16() != nil && ip.IsGlobalUnicast() && !ip.IsPrivate() {
			return ip.String(), nil
		}
	}
	return "", ErrNoIP
}

func lookupWithDNS(parent context.Context, domain, dnsAddr string) ([]net.IP, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", dnsAddr)
		},
	}
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	return r.LookupIP(ctx, "ip", domain)
}

// ===========================
// TLS HELPERS
// ===========================

func detectTLSVersion(state tls.ConnectionState) string {
	switch state.Version {
	case tls.VersionTLS13:
		return TLSVersion13
	case tls.VersionTLS12:
		return TLSVersion12
	case tls.VersionTLS11:
		return TLSVersion11
	case tls.VersionTLS10:
		return TLSVersion10
	default:
		return "Unknown"
	}
}

func dialTLS(
	ctx context.Context,
	dialer *net.Dialer,
	addr string,
	conf *tls.Config,
) (*tls.Conn, error) {

	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	conn := tls.Client(raw, conf)
	if err = conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, err
	}
	return conn, nil
}

// ===========================
// CERTIFICATE CHAIN HELPERS
// ===========================

func detectChainLevel(index int, total int) models.CertLevel {
	if index == 0 {
		return models.CertLevelDomain
	}
	if index == total-1 {
		return models.CertLevelRoot
	}
	return models.CertLevelIntermediate
}

func isSelfSigned(cert *x509.Certificate) bool {
	// Let's Encrypt / IdenTrust cross-sign bypass: Subject == Issuer is not enough
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	// Check signature and basic constraints
	return cert.CheckSignatureFrom(cert) == nil && cert.IsCA && cert.BasicConstraintsValid
}

func isOpenSSLSelfSignedLeaf(leaf *x509.Certificate, certs []*x509.Certificate) bool {
	if leaf.Subject.String() != leaf.Issuer.String() {
		return false
	}
	for i := 1; i < len(certs); i++ {
		if leaf.CheckSignatureFrom(certs[i]) == nil {
			return false
		}
	}
	return true
}

func hasSelfSignedInChain(certs []*x509.Certificate) bool {
	for i := 1; i < len(certs); i++ {
		if isSelfSigned(certs[i]) {
			return true
		}
	}
	return false
}

func buildFullCertChain(certs []*x509.Certificate, trusted bool) []models.CertDetail {

	var chainCerts []*x509.Certificate

	verified, err := buildVerifiedChain(certs)
	if err == nil && len(verified) > 0 {
		chainCerts = verified
	} else {
		chainCerts = certs
	}

	// Ẩn Root CA hệ thống (cert cuối self-signed)
	if len(chainCerts) > 1 {
		lastIdx := len(chainCerts) - 1
		lastCert := chainCerts[lastIdx]
		if isSelfSigned(lastCert) {
			chainCerts = chainCerts[:lastIdx]
		}
	}

	out := make([]models.CertDetail, 0, len(chainCerts))
	total := len(chainCerts)

	for i, cert := range chainCerts {
		level := detectChainLevel(i, total)

		out = append(out, models.CertDetail{
			CommonName:   cert.Subject.CommonName,
			Issuer:       cert.Issuer.CommonName,
			Level:        level,
			Organization: cert.Subject.Organization,
			Country:      cert.Subject.Country,
			Locality:     cert.Subject.Locality,
			Province:     cert.Subject.Province,
			SANs:         cert.DNSNames,
			NotBefore:    cert.NotBefore,
			NotAfter:     cert.NotAfter,

			SerialNumberDec: cert.SerialNumber.String(),
			SerialNumberHex: cert.SerialNumber.Text(16),
			SignatureAlgo:   cert.SignatureAlgorithm.String(),
		})
	}

	return out
}

func buildVerifiedChain(certs []*x509.Certificate) ([]*x509.Certificate, error) {
	if len(certs) == 0 {
		return nil, errors.New("empty certificate chain")
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		return nil, err
	}
	intermediates := x509.NewCertPool()
	for i := 1; i < len(certs); i++ {
		intermediates.AddCert(certs[i])
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	chains, err := certs[0].Verify(opts)
	if err != nil {
		return nil, err
	}
	if len(chains) == 0 {
		return nil, errors.New("verify returned empty chain")
	}
	return chains[0], nil
}

// ===========================
// TRUST ANALYZER
// ===========================

type TrustResult struct {
	Trusted bool
	Issues  []models.TrustIssue
}

func analyzeTrust(certs []*x509.Certificate, domain string) TrustResult {

	var issues []models.TrustIssue
	now := time.Now()
	total := len(certs)

	// 1. Leaf cert expired
	leaf := certs[0]
	if now.After(leaf.NotAfter) {
		days := int64(now.Sub(leaf.NotAfter).Hours() / 24)
		issues = append(issues, models.TrustIssue{
			Code:    models.TrustCertExpired,
			Message: fmt.Sprintf("Chứng chỉ của website đã hết hạn (%d ngày trước).", days),
		})
	}

	// 2. Intermediate / Root expired
	for i := 1; i < total; i++ {
		cert := certs[i]
		if now.After(cert.NotAfter) {
			days := int64(now.Sub(cert.NotAfter).Hours() / 24)
			issues = append(issues, models.TrustIssue{
				Code:    models.TrustChainExpired,
				Message: fmt.Sprintf("Một trong các chứng chỉ trung gian hoặc gốc đã hết hạn (%d ngày trước).", days),
			})
		}
	}

	// 3. Chain verify
	if _, err := buildVerifiedChain(certs); err != nil && !hasFatalCause(issues) {
		if isOpenSSLSelfSignedLeaf(leaf, certs) {
			issues = append(issues, models.TrustIssue{
				Code:    models.TrustSelfSignedLeaf,
				Message: "Chứng chỉ website là chứng chỉ tự ký (self-signed), không được CA tin cậy xác thực: 18 (self-signed certificate)",
			})
		} else if hasSelfSignedInChain(certs) {
			issues = append(issues, models.TrustIssue{
				Code:    models.TrustSelfSignedChain,
				Message: "Chuỗi chứng chỉ có chứa chứng chỉ tự ký, làm mất độ tin cậy của website: 19 (self-signed certificate in certificate chain)",
			})
		} else {
			var unknownAuth x509.UnknownAuthorityError
			var certInvalid x509.CertificateInvalidError

			if errors.As(err, &unknownAuth) {
				issues = append(issues, models.TrustIssue{
					Code:    models.TrustUntrustedRoot,
					Message: "Chứng chỉ được ký bởi tổ chức chứng thực không nằm trong danh sách tin cậy của hệ thống.",
				})
			} else if errors.As(err, &certInvalid) {
				// Cụ thể hóa lỗi nếu cần, ở đây dùng chung MissingIssuer cho case không lấy được issuer
				issues = append(issues, models.TrustIssue{
					Code:    models.TrustMissingIssuer,
					Message: "Chuỗi chứng chỉ bị thiếu chứng chỉ trung gian (intermediate) hoặc không thể xác thực issuer.",
				})
			} else {
				issues = append(issues, models.TrustIssue{
					Code:    models.TrustBadChain,
					Message: "Chuỗi chứng chỉ không hợp lệ hoặc bị hỏng, không thể xác minh.",
				})
			}
		}
	}

	// 4. Hostname mismatch (Luôn chạy)
	if err := certs[0].VerifyHostname(domain); err != nil {
		issues = append(issues, models.TrustIssue{
			Code: models.TrustNameMismatch,
			Message: fmt.Sprintf(
				"Không có tên thông dụng nào trong chứng chỉ trùng khớp với hostname đã nhập (%s). Bạn có thể gặp lỗi khi truy cập trang web này bằng trình duyệt web.",
				domain,
			),
		})
	}

	// 5. Result
	trusted := true
	for _, issue := range issues {
		if isFatalTrustIssue(issue.Code) {
			trusted = false
			break
		}
	}

	return TrustResult{Trusted: trusted, Issues: issues}
}

func isFatalTrustIssue(code models.TrustCode) bool {
	switch code {
	case models.TrustSelfSignedLeaf,
		models.TrustSelfSignedChain,
		models.TrustMissingIssuer,
		models.TrustBadChain,
		models.TrustUntrustedRoot,
		models.TrustCertExpired,
		models.TrustChainExpired,
		models.TrustUnknown:
		return true
	}
	return false
}

func hasFatalCause(issues []models.TrustIssue) bool {
	for _, i := range issues {
		switch i.Code {
		case models.TrustSelfSignedLeaf,
			models.TrustSelfSignedChain,
			models.TrustMissingIssuer,
			models.TrustBadChain,
			models.TrustUntrustedRoot,
			models.TrustCertExpired,
			models.TrustChainExpired,
			models.TrustNameMismatch,
			models.TrustUnknown:
			return true
		}
	}
	return false
}

// ===========================
// MAIN SCANNER
// ===========================

// Scan là entry point chính: DNS → TLS → Analyze → Response
func Scan(ctx context.Context, domain string) (*models.SSLCheckResponse, error) {

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 1. DNS resolve
	ip, err := resolveIP(ctx, domain)
	if err != nil {
		return nil, err // Đã có ErrDNSFailed bên trong resolveIP
	}

	// 2. TLS handshake
	dialer := &net.Dialer{Timeout: TLSDialTimeout}
	addrDomain := net.JoinHostPort(domain, "443")
	addrIP := net.JoinHostPort(ip, "443")
	baseConf := &tls.Config{ServerName: domain}

	var conn *tls.Conn

	conn, err = dialTLS(ctx, dialer, addrIP, baseConf)
	if err != nil {
		conn, err = dialTLS(ctx, dialer, addrDomain, baseConf)
	}

	var insecureConn bool
	if err != nil {
		insecure := baseConf.Clone()
		insecure.InsecureSkipVerify = true

		conn, err = dialTLS(ctx, dialer, addrIP, insecure)
		if err != nil {
			conn, err = dialTLS(ctx, dialer, addrDomain, insecure)
		}

		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrTLSFailed, err)
		}
		insecureConn = true
	}

	defer conn.Close()

	state := conn.ConnectionState()
	certs := state.PeerCertificates

	if len(certs) == 0 {
		return nil, ErrNoCertificates
	}

	// 3. Detect server type
	srvCtx, srvCancel := context.WithTimeout(ctx, 6*time.Second) // Dùng ctx truyền vào thay vì Background
	defer srvCancel()
	serverType := DetectServerType(srvCtx, domain, ip)

	// 4. TLS version
	tlsVersion := detectTLSVersion(state)

	// 5. Hostname match
	hostnameOK := certs[0].VerifyHostname(domain) == nil

	// 6. Trust analysis
	trust := analyzeTrust(certs, domain)

	// 7. Build certificate chain
	chain := buildFullCertChain(certs, trust.Trusted)

	// 8. Validity & days left
	mainCert := certs[0]
	now := time.Now()
	daysLeft := int64(time.Until(mainCert.NotAfter).Hours() / 24)
	isExpired := now.After(mainCert.NotAfter)
	valid := !isExpired && now.After(mainCert.NotBefore)

	return &models.SSLCheckResponse{
		Hostname:           domain,
		IP:                 ip,
		ServerType:         serverType,
		Valid:              valid,
		IsExpired:          isExpired,
		DaysLeft:           daysLeft,
		TLSVersion:         tlsVersion,
		InsecureConnection: insecureConn,
		HostnameOK:         hostnameOK,
		Trusted:            trust.Trusted,
		TrustIssues:        trust.Issues,
		CertChain:          chain,
		CheckTime:          now,
	}, nil
}
