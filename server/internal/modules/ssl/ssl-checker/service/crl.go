// ============================================
// FILE: ssl-checker/service/crl.go
//
// CRL Revocation Checker:
// - Kiểm tra danh sách thu hồi (CRL) nếu OCSP không có sẵn
// - Tải và parse file .crl từ CRLDistributionPoints
// - Cache CRL theo URL để tối ưu hiệu năng
// ============================================

package service

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/platform/validator"
)

const CRLDownloadTimeout = 5 * time.Second

// CRLCache lưu trữ dữ liệu CRL đã tải để dùng lại
var (
	crlCache = make(map[string]*crlEntry)
	crlMu    sync.RWMutex
)

type crlEntry struct {
	list      *x509.RevocationList
	expiresAt time.Time
}

// CheckCRL kiểm tra xem chứng chỉ có bị thu hồi trong danh sách CRL không.
func CheckCRL(ctx context.Context, cert *x509.Certificate) (revoked bool, err error) {
	if cert == nil || len(cert.CRLDistributionPoints) == 0 {
		return false, nil
	}

	url := cert.CRLDistributionPoints[0]
	list, err := getCRLList(ctx, url)
	if err != nil {
		return false, fmt.Errorf("crl: %w", err)
	}

	// Kiểm tra xem SerialNumber của cert có trong danh sách bị thu hồi không
	for _, revokedCert := range list.RevokedCertificates {
		if revokedCert.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			log.Info().Str("domain", cert.Subject.CommonName).Str("serial", cert.SerialNumber.String()).Msg("CRL: certificate is REVOKED")
			return true, nil
		}
	}

	return false, nil
}

func getCRLList(ctx context.Context, crlURL string) (*x509.RevocationList, error) {
	// 1. Kiểm tra Cache
	crlMu.RLock()
	entry, ok := crlCache[crlURL]
	crlMu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.list, nil
	}

	// 2. Tải mới
	log.Debug().Str("url", crlURL).Msg("CRL: downloading list")

	// --- SSRF Protection: validate scheme + host ---
	parsedURL, err := url.Parse(crlURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		return nil, fmt.Errorf("CRL URL không hợp lệ hoặc scheme không được hỗ trợ: %s", crlURL)
	}

	reqCtx, cancel := context.WithTimeout(ctx, CRLDownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, crlURL, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{
		Timeout: CRLDownloadTimeout,
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
					return nil, fmt.Errorf("SSRF Protection: chặn CRL request đến IP nội bộ %s", host)
				}
				return (&net.Dialer{Timeout: CRLDownloadTimeout}).DialContext(ctx, network, net.JoinHostPort(safeIP.String(), port))
			},
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http error: %d", resp.StatusCode)
	}

	// Giới hạn dung lượng tải 10MB để tránh OOM
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, err
	}

	list, err := x509.ParseRevocationList(data)
	if err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	// 3. Cập nhật Cache
	crlMu.Lock()
	crlCache[crlURL] = &crlEntry{
		list:      list,
		expiresAt: list.NextUpdate,
	}
	crlMu.Unlock()

	return list, nil
}
