// ============================================
// FILE: ssl-checker/service/service.go
//
// Core SSL Scanner:
// - DNS Resolution (dual-lookup parallel)
// - TLS Handshake (strict → insecure fallback)
// - Parallel: Server Type detection + TLS scan
// - Trust Analyzer (Critical/Warning + OpenSSL codes)
// - Certificate Chain Builder with security metadata
// ============================================

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
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
	// Nếu domain đã là một IP hợp lệ, trả về luôn để đỡ tốn thời gian DNS
	if net.ParseIP(domain) != nil {
		return domain, nil
	}

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

// detectCipherSuite chuyển cipher suite ID thành tên chuỗi dễ đọc
func detectCipherSuite(state tls.ConnectionState) string {
	// TLS 1.3: CipherSuite field is 0 but the suite is implicit
	if state.Version == tls.VersionTLS13 {
		switch state.CipherSuite {
		case tls.TLS_AES_128_GCM_SHA256:
			return "TLS_AES_128_GCM_SHA256"
		case tls.TLS_AES_256_GCM_SHA384:
			return "TLS_AES_256_GCM_SHA384"
		case tls.TLS_CHACHA20_POLY1305_SHA256:
			return "TLS_CHACHA20_POLY1305_SHA256"
		}
	}
	// TLS 1.2 và cũ hơn
	if name := tls.CipherSuiteName(state.CipherSuite); name != "" {
		return name
	}
	if state.CipherSuite != 0 {
		return fmt.Sprintf("0x%04X", state.CipherSuite)
	}
	return ""
}

func dialTLS(
	ctx context.Context,
	dialer *net.Dialer,
	addr string,
	conf *tls.Config,
) (*tls.Conn, bool, error) {

	raw, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, false, err
	}
	conn := tls.Client(raw, conf)
	if err = conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, true, err // TCP success, Handshake failed
	}
	return conn, true, nil
}

// ===========================
// CERTIFICATE SECURITY METADATA
// ===========================

// extractPublicKeyInfo trả về loại thuật toán và số bits của public key
func extractPublicKeyInfo(cert *x509.Certificate) (algo string, bits int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return "EC (P-256)", 256
		case elliptic.P384():
			return "EC (P-384)", 384
		case elliptic.P521():
			return "EC (P-521)", 521
		default:
			return "EC", pub.Params().BitSize
		}
	default:
		return "Unknown", 0
	}
}

// fingerprintSHA256 tính SHA-256 fingerprint của DER-encoded cert
func fingerprintSHA256(cert *x509.Certificate) string {
	h := sha256.Sum256(cert.Raw)
	return formatFingerprint(h[:])
}

// fingerprintSHA1 tính SHA-1 fingerprint của DER-encoded cert
func fingerprintSHA1(cert *x509.Certificate) string {
	h := sha1.Sum(cert.Raw) //nolint:gosec
	return formatFingerprint(h[:])
}

// formatFingerprint format fingerprint thành chuỗi hex có dấu ":"
func formatFingerprint(b []byte) string {
	var sb strings.Builder
	for i, v := range b {
		if i > 0 {
			sb.WriteByte(':')
		}
		fmt.Fprintf(&sb, "%02X", v)
	}
	return sb.String()
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
		algo, bits := extractPublicKeyInfo(cert)

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

			// Security metadata
			PublicKeyAlgorithm: algo,
			PublicKeyBits:      bits,
			FingerprintSHA256:  fingerprintSHA256(cert),
			FingerprintSHA1:    fingerprintSHA1(cert),
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
	leaf := certs[0]

	// ==========================
	// CRITICAL CHECKS
	// ==========================

	// 1. Leaf cert expired (OpenSSL: 10)
	if now.After(leaf.NotAfter) {
		days := int64(now.Sub(leaf.NotAfter).Hours() / 24)
		issues = append(issues, models.TrustIssue{
			Code:    models.TrustCertExpired,
			Level:   models.TrustLevelCritical,
			Message: fmt.Sprintf("Chứng chỉ của website đã hết hạn %d ngày trước: 10 (certificate has expired)", days),
		})
	}

	// 2. Intermediate / Root expired (OpenSSL: 10)
	for i := 1; i < total; i++ {
		cert := certs[i]
		if now.After(cert.NotAfter) {
			days := int64(now.Sub(cert.NotAfter).Hours() / 24)
			issues = append(issues, models.TrustIssue{
				Code:    models.TrustChainExpired,
				Level:   models.TrustLevelCritical,
				Message: fmt.Sprintf("Một chứng chỉ trong chuỗi (trung gian/gốc) đã hết hạn %d ngày trước: 10 (certificate has expired)", days),
			})
		}
	}

	// 3. Chain verify → Self-signed, Unknown Authority, Bad Chain
	if _, err := buildVerifiedChain(certs); err != nil && !hasFatalCause(issues) {
		if isOpenSSLSelfSignedLeaf(leaf, certs) {
			issues = append(issues, models.TrustIssue{
				Code:    models.TrustSelfSignedLeaf,
				Level:   models.TrustLevelCritical,
				Message: "Chứng chỉ website là chứng chỉ tự ký (self-signed), không được CA tin cậy xác thực: 18 (self-signed certificate)",
			})
		} else if hasSelfSignedInChain(certs) {
			issues = append(issues, models.TrustIssue{
				Code:    models.TrustSelfSignedChain,
				Level:   models.TrustLevelCritical,
				Message: "Chuỗi chứng chỉ có chứa chứng chỉ tự ký, làm mất độ tin cậy của website: 19 (self-signed certificate in certificate chain)",
			})
		} else {
			var unknownAuth x509.UnknownAuthorityError
			var certInvalid x509.CertificateInvalidError

			if errors.As(err, &unknownAuth) {
				issues = append(issues, models.TrustIssue{
					Code:    models.TrustUntrustedRoot,
					Level:   models.TrustLevelCritical,
					Message: "Chứng chỉ được ký bởi tổ chức chứng thực không nằm trong danh sách tin cậy của hệ thống: 20 (unable to get local issuer certificate)",
				})
			} else if errors.As(err, &certInvalid) {
				issues = append(issues, models.TrustIssue{
					Code:    models.TrustMissingIssuer,
					Level:   models.TrustLevelCritical,
					Message: "Chuỗi chứng chỉ bị thiếu chứng chỉ trung gian (intermediate) hoặc không thể xác thực issuer: 20 (unable to get local issuer certificate)",
				})
			} else {
				issues = append(issues, models.TrustIssue{
					Code:    models.TrustBadChain,
					Level:   models.TrustLevelCritical,
					Message: "Chuỗi chứng chỉ không hợp lệ hoặc bị hỏng, không thể xác minh.",
				})
			}
		}
	}

	// 4. Hostname mismatch (Critical - luôn chạy)
	if err := leaf.VerifyHostname(domain); err != nil {
		issues = append(issues, models.TrustIssue{
			Code:    models.TrustNameMismatch,
			Level:   models.TrustLevelCritical,
			Message: fmt.Sprintf("Hostname '%s' không khớp với bất kỳ tên nào trong chứng chỉ. Trình duyệt sẽ hiển thị cảnh báo bảo mật khi truy cập.", domain),
		})
	}

	// ==========================
	// WARNING CHECKS
	// ==========================

	// 5. Expiring soon (Warning: < 30 days left, cert still valid)
	daysLeft := int64(time.Until(leaf.NotAfter).Hours() / 24)
	if !now.After(leaf.NotAfter) && daysLeft < 30 {
		issues = append(issues, models.TrustIssue{
			Code:    models.TrustExpiringSoon,
			Level:   models.TrustLevelWarning,
			Message: fmt.Sprintf("Chứng chỉ sẽ hết hạn sau %d ngày. Hãy gia hạn sớm để tránh gián đoạn dịch vụ.", daysLeft),
		})
	}

	// 6. Weak Public Key (Warning)
	if algo, bits := extractPublicKeyInfo(leaf); algo == "RSA" && bits > 0 && bits < 2048 {
		issues = append(issues, models.TrustIssue{
			Code:    models.TrustWeakKey,
			Level:   models.TrustLevelWarning,
			Message: fmt.Sprintf("Chứng chỉ dùng khóa RSA %d-bit. Khóa RSA dưới 2048-bit được xem là không đủ an toàn theo tiêu chuẩn hiện đại.", bits),
		})
	}

	// 7. Weak Signature Algorithm (Warning: MD5 or SHA-1)
	sigAlgo := leaf.SignatureAlgorithm.String()
	sigAlgoLower := strings.ToLower(sigAlgo)
	if strings.Contains(sigAlgoLower, "md5") {
		issues = append(issues, models.TrustIssue{
			Code:    models.TrustWeakAlgorithm,
			Level:   models.TrustLevelWarning,
			Message: fmt.Sprintf("Chứng chỉ dùng thuật toán ký MD5 (%s). MD5 đã bị phá vỡ và không an toàn, không được tin cậy bởi các trình duyệt hiện đại.", sigAlgo),
		})
	} else if strings.Contains(sigAlgoLower, "sha1") {
		issues = append(issues, models.TrustIssue{
			Code:    models.TrustWeakAlgorithm,
			Level:   models.TrustLevelWarning,
			Message: fmt.Sprintf("Chứng chỉ dùng thuật toán ký SHA-1 (%s). SHA-1 đã lỗi thời và bị các trình duyệt đánh dấu không an toàn.", sigAlgo),
		})
	}

	// ==========================
	// DETERMINE TRUSTED BOOL
	// Critical issues → not trusted
	// ==========================
	trusted := true
	for _, issue := range issues {
		if issue.Level == models.TrustLevelCritical {
			trusted = false
			break
		}
	}

	return TrustResult{Trusted: trusted, Issues: issues}
}

func hasFatalCause(issues []models.TrustIssue) bool {
	for _, i := range issues {
		if i.Level == models.TrustLevelCritical {
			return true
		}
	}
	return false
}

// ===========================
// MAIN SCANNER
// ===========================

// Scan là entry point chính: DNS → Parallel(TLS + ServerType) → Analyze → Response
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
	// SECURITY: Chỉ dial tới addrIP (đã qua filter private IP trong resolveIP).
	// Không fallback sang domain để tránh SSRF bypass qua DNS rebinding.
	dialer := &net.Dialer{Timeout: TLSDialTimeout}
	addrIP := net.JoinHostPort(ip, "443")
	baseConf := &tls.Config{ServerName: domain}

	var conn *tls.Conn
	var tcpSuccess bool

	conn, tcpSuccess, err = dialTLS(ctx, dialer, addrIP, baseConf)

	var insecureConn bool
	var handshakeErr string

	if err != nil {
		// Nếu TCP fail (timeout/connection refused), return lỗi ngay
		if !tcpSuccess {
			return nil, fmt.Errorf("%w: %v", ErrTLSFailed, err)
		}

		// TCP thành công nhưng Handshake fail -> Thử Insecure fallback
		insecure := baseConf.Clone()
		insecure.InsecureSkipVerify = true //nolint:gosec

		conn2, _, err2 := dialTLS(ctx, dialer, addrIP, insecure)
		if err2 == nil {
			conn = conn2
			insecureConn = true
			log.Warn().Str("domain", domain).Str("ip", ip).Msg("SSL: fell back to InsecureSkipVerify")
		} else {
			// Cả 2 đều fail -> Đánh dấu lỗi handshake nhưng vẫn tiếp tục để lấy Server Type
			handshakeErr = fmt.Sprintf("Không tìm thấy chứng chỉ SSL hoặc không thể thiết lập kết nối an toàn tới %s. Vui lòng đảm bảo tên miền đã trỏ đúng IP máy chủ và cổng SSL (mặc định là 443) đang mở.", domain)
		}
	}

	// 3. PARALLEL: Detect server type + OCSP revocation check
	var (
		serverType string
		ocspStatus string
		wg         sync.WaitGroup
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		srvCtx, srvCancel := context.WithTimeout(ctx, ProbeTimeout)
		defer srvCancel()
		serverType = DetectServerType(srvCtx, domain, ip)
	}()

	now := time.Now()

	// Trường hợp lỗi handshake hoàn toàn
	if handshakeErr != "" {
		wg.Wait()
		return &models.SSLCheckResponse{
			Hostname:       domain,
			IP:             ip,
			ServerType:     serverType,
			HandshakeError: handshakeErr,
			CheckTime:      now,
		}, nil
	}

	defer conn.Close()
	state := conn.ConnectionState()
	certs := state.PeerCertificates

	log.Debug().Str("domain", domain).Int("peerCerts", len(certs)).Int("verifiedChains", len(state.VerifiedChains)).Msg("SSL Scan: connection state")

	if len(certs) == 0 {
		wg.Wait()
		return &models.SSLCheckResponse{
			Hostname:       domain,
			IP:             ip,
			ServerType:     serverType,
			HandshakeError: fmt.Sprintf("Máy chủ %s không trả về bất kỳ chứng chỉ SSL nào.", domain),
			CheckTime:      now,
		}, nil
	}

	// Revocation check (OCSP + CRL) chạy song song
	var leaf, issuer *x509.Certificate
	if len(certs) >= 2 {
		leaf, issuer = certs[0], certs[1]
	} else if len(state.VerifiedChains) > 0 && len(state.VerifiedChains[0]) >= 2 {
		leaf, issuer = state.VerifiedChains[0][0], state.VerifiedChains[0][1]
	}

	if leaf != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// 1. Thử OCSP (Ưu tiên vì nhanh hơn)
			if issuer != nil && (len(leaf.OCSPServer) > 0 || len(state.OCSPResponse) > 0) {
				st, err := CheckOCSP(ctx, leaf, issuer, state.OCSPResponse)
				if err == nil && st == OCSPStatusRevoked {
					ocspStatus = OCSPStatusRevoked
					return
				}
			}

			// 2. Fallback sang CRL nếu OCSP không có hoặc không báo revoked
			if len(leaf.CRLDistributionPoints) > 0 {
				revoked, err := CheckCRL(ctx, leaf)
				if err == nil && revoked {
					ocspStatus = OCSPStatusRevoked
					return
				}
				if err != nil {
					log.Debug().Err(err).Str("domain", domain).Msg("CRL check failed")
				}
			}

			ocspStatus = OCSPStatusGood
		}()
	} else {
		ocspStatus = OCSPStatusUnknown
	}

	// 4. TLS version & Cipher Suite (ngay sau khi có connection state)
	tlsVersion := detectTLSVersion(state)
	cipherSuite := detectCipherSuite(state)

	// 5. Hostname match
	hostnameOK := certs[0].VerifyHostname(domain) == nil

	// 6. Trust analysis
	trust := analyzeTrust(certs, domain)

	// 7. Build certificate chain (với security metadata)
	chain := buildFullCertChain(certs, trust.Trusted)

	// 8. Validity & days left
	mainCert := certs[0]
	daysLeft := int64(time.Until(mainCert.NotAfter).Hours() / 24)
	isExpired := now.After(mainCert.NotAfter)
	valid := !isExpired && now.After(mainCert.NotBefore)

	// 9. Chờ cả 2 goroutine (serverType + OCSP) hoàn thành
	wg.Wait()

	log.Debug().Str("domain", domain).Str("ocspStatus", ocspStatus).Msg("SSL Scan: results merged")

	// 10. Nếu OCSP revoked, inject TrustIssue critical
	if ocspStatus == OCSPStatusRevoked {
		trust.Issues = append([]models.TrustIssue{{
			Code:    models.TrustCertRevoked,
			Level:   models.TrustLevelCritical,
			Message: "Chứng chỉ này đã bị thu hồi bởi nhà phát hành (CA). Trình duyệt sẽ hiển thị lỗi bảo mật nghiêm trọng khi truy cập website này.",
		}}, trust.Issues...)
		trust.Trusted = false
		log.Warn().Str("domain", domain).Msg("OCSP: certificate is REVOKED")
	}

	return &models.SSLCheckResponse{
		Hostname:           domain,
		IP:                 ip,
		ServerType:         serverType,
		Valid:              valid,
		IsExpired:          isExpired,
		DaysLeft:           daysLeft,
		TLSVersion:         tlsVersion,
		CipherSuite:        cipherSuite,
		InsecureConnection: insecureConn,
		HostnameOK:         hostnameOK,
		Trusted:            trust.Trusted,
		TrustIssues:        trust.Issues,
		CertChain:          chain,
		OCSPStatus:         ocspStatus,
		CheckTime:          now,
	}, nil
}
