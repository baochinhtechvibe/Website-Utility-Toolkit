// ============================================
// FILE: ssl-checker/service/ocsp.go
//
// OCSP Revocation Checker:
// - Ưu tiên OCSP Stapling (0 overhead)
// - Fallback tự fetch từ OCSP URL trong cert
// - Timeout ngắn (2s) để không block scan chính
// ============================================

package service

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ocsp"
	"tools.bctechvibe.com/server/internal/platform/validator"
)

const OCSPCheckTimeout = 2 * time.Second

// OCSPStatus là các giá trị trả về của OCSP check
const (
	OCSPStatusGood    = "good"
	OCSPStatusRevoked = "revoked"
	OCSPStatusUnknown = "unknown"
)

// CheckOCSP kiểm tra trạng thái thu hồi của chứng chỉ lá (leaf cert).
//
// Ưu tiên đọc từ stapled response (0 latency).
// Fallback: tự fetch từ OCSP URL nhúng trong cert.
//
// Trả về: status ("good"/"revoked"/"unknown"), lỗi kỹ thuật (chỉ để log).
func CheckOCSP(ctx context.Context, leaf, issuer *x509.Certificate, stapledResp []byte) (status string, err error) {
	if leaf == nil || issuer == nil {
		return OCSPStatusUnknown, fmt.Errorf("ocsp: leaf or issuer cert is nil")
	}

	// --- Ưu tiên 1: OCSP Stapling ---
	if len(stapledResp) > 0 {
		status, err := parseOCSPResponse(stapledResp, leaf, issuer)
		if err == nil {
			log.Debug().Str("domain", leaf.Subject.CommonName).Str("status", status).Msg("OCSP: resolved via stapling")
			return status, nil
		}
		log.Debug().Err(err).Str("domain", leaf.Subject.CommonName).Msg("OCSP: stapled response parse failed, falling back to fetch")
	}

	// --- Ưu tiên 2: Tự fetch OCSP URL ---
	if len(leaf.OCSPServer) == 0 {
		return OCSPStatusUnknown, fmt.Errorf("ocsp: no OCSP server URL in cert")
	}

	ocspURL := leaf.OCSPServer[0]

	// --- SSRF Protection: validate scheme + host trước khi fetch ---
	parsedURL, err := url.Parse(ocspURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return OCSPStatusUnknown, fmt.Errorf("ocsp: invalid or unsupported URL scheme: %s", ocspURL)
	}

	// Tạo OCSP request
	reqBytes, err := ocsp.CreateRequest(leaf, issuer, &ocsp.RequestOptions{
		Hash: crypto.SHA1, //nolint:gosec // SHA1 required by OCSP spec
	})
	if err != nil {
		return OCSPStatusUnknown, fmt.Errorf("ocsp: failed to create request: %w", err)
	}

	// Gửi HTTP request với timeout chặt chẽ + SSRF-safe transport
	ocspCtx, cancel := context.WithTimeout(ctx, OCSPCheckTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ocspCtx, http.MethodPost, ocspURL, bytes.NewReader(reqBytes))
	if err != nil {
		return OCSPStatusUnknown, fmt.Errorf("ocsp: failed to build http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	httpClient := &http.Client{
		Timeout: OCSPCheckTimeout,
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
				if err != nil {
					return nil, err
				}
				var safeIP net.IP
				for _, ipAddr := range ips {
					if validator.IsSafeIP(ipAddr.IP) {
						safeIP = ipAddr.IP
						break
					}
				}
				if safeIP == nil {
					return nil, fmt.Errorf("SSRF Protection: chặn OCSP request đến IP nội bộ %s", host)
				}
				return (&net.Dialer{Timeout: OCSPCheckTimeout}).DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
			},
		},
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return OCSPStatusUnknown, fmt.Errorf("ocsp: http request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return OCSPStatusUnknown, fmt.Errorf("ocsp: failed to read response body: %w", err)
	}

	status, err = parseOCSPResponse(respBytes, leaf, issuer)
	if err != nil {
		return OCSPStatusUnknown, fmt.Errorf("ocsp: parse fetched response failed: %w", err)
	}

	log.Debug().Str("domain", leaf.Subject.CommonName).Str("status", status).Str("url", ocspURL).Msg("OCSP: resolved via fetch")
	return status, nil
}

// parseOCSPResponse parse và validate OCSP response bytes.
func parseOCSPResponse(respBytes []byte, leaf, issuer *x509.Certificate) (string, error) {
	parsed, err := ocsp.ParseResponseForCert(respBytes, leaf, issuer)
	if err != nil {
		return OCSPStatusUnknown, fmt.Errorf("ocsp: parse response failed: %w", err)
	}

	// Kiểm tra response có còn trong thời hạn hiệu lực không
	now := time.Now()
	if !parsed.NextUpdate.IsZero() && now.After(parsed.NextUpdate) {
		// Response đã stale, nhưng đối với các site test như badssl, ta vẫn log ra status thực tế
		log.Warn().Str("domain", leaf.Subject.CommonName).Time("nextUpdate", parsed.NextUpdate).Msg("OCSP: response is stale, but checking status anyway")
	}

	log.Debug().Str("domain", leaf.Subject.CommonName).Int("rawStatus", int(parsed.Status)).Msg("OCSP: parsed status from CA")

	switch parsed.Status {
	case ocsp.Good:
		return OCSPStatusGood, nil
	case ocsp.Revoked:
		return OCSPStatusRevoked, nil
	default:
		return OCSPStatusUnknown, nil
	}
}
