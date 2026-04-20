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
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
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

func getCRLList(ctx context.Context, url string) (*x509.RevocationList, error) {
	// 1. Kiểm tra Cache
	crlMu.RLock()
	entry, ok := crlCache[url]
	crlMu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.list, nil
	}

	// 2. Tải mới
	log.Debug().Str("url", url).Msg("CRL: downloading list")
	reqCtx, cancel := context.WithTimeout(ctx, CRLDownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: CRLDownloadTimeout}
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
	crlCache[url] = &crlEntry{
		list:      list,
		expiresAt: list.NextUpdate,
	}
	crlMu.Unlock()

	return list, nil
}
