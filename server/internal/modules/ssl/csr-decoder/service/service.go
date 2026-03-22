// ============================================
// FILE: csr-decoder/service/service.go
//
// Core CSR Decoder:
// - PEM Decoding
// - x509 CSR Parsing
// - Info Extraction (Subject, SANs, Key)
// ============================================

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"tools.bctechvibe.com/server/internal/modules/ssl/csr-decoder/models"
)

var (
	ErrInvalidPEM = errors.New("PEM block không hợp lệ")
	ErrInvalidCSR = errors.New("CSR không thể parse được")
)

type Service struct{}

func New() *Service {
	return &Service{}
}

// Decode giải mã CSR từ chuỗi PEM
func (s *Service) Decode(ctx context.Context, csrPEM string) (*models.CSRDecodeResponse, error) {
	// 1. Preprocess
	csrPEM = strings.ReplaceAll(csrPEM, `\n`, "\n")
	csrPEM = strings.ReplaceAll(csrPEM, "\r\n", "\n")
	csrPEM = strings.TrimSpace(csrPEM)

	const maxCSRSize = 100 * 1024 // 100KB
	if len(csrPEM) > maxCSRSize {
		return nil, errors.New("CSR vượt quá kích thước cho phép")
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 2. Decode PEM
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: failed to decode PEM block", ErrInvalidPEM)
	}

	if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: invalid PEM type %s", ErrInvalidPEM, block.Type)
	}

	// 3. Parse CSR
	req, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, ErrInvalidCSR
	}

	// Check signature (đảm bảo CSR chưa bị can thiệp)
	if err := req.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: signature verification failed", ErrInvalidCSR)
	}

	// 4. SAN data presence
	hasSANData := len(req.DNSNames) > 0 ||
		len(req.IPAddresses) > 0 ||
		len(req.EmailAddresses) > 0 ||
		len(req.URIs) > 0

	// Aggregate SANs
	sans := make([]string, 0, len(req.DNSNames)+len(req.IPAddresses)+len(req.EmailAddresses)+len(req.URIs))
	sans = append(sans, req.DNSNames...)
	sans = append(sans, req.EmailAddresses...)

	for _, ip := range req.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range req.URIs {
		sans = append(sans, uri.String())
	}

	// 5. Build response
	resp := &models.CSRDecodeResponse{
		CommonName:         req.Subject.CommonName,
		Organization:       req.Subject.Organization,
		OrganizationalUnit: req.Subject.OrganizationalUnit,
		Country:            req.Subject.Country,
		State:              req.Subject.Province,
		Locality:           req.Subject.Locality,

		Sans:    sans,
		HasSANs: hasSANData,

		Algorithm: req.PublicKeyAlgorithm.String(),
	}

	// Key Size
	switch pub := req.PublicKey.(type) {
	case *rsa.PublicKey:
		resp.KeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		resp.KeySize = pub.Params().BitSize
	default:
		resp.KeySize = 0
	}

	return resp, nil
}
