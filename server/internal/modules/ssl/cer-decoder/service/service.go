// ============================================
// FILE: cer-decoder/service/service.go
//
// Core CER (Certificate) Decoder:
// - PEM Decoding
// - x509 Certificate Parsing
// - Info Extraction
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

	"github.com/rs/zerolog/log"

	"tools.bctechvibe.com/server/internal/modules/ssl/cer-decoder/models"
)

var (
	ErrInvalidPEM = errors.New("PEM block không hợp lệ")
	ErrInvalidCER = errors.New("Certificate không thể parse được")
)

type Service struct{}

func New() *Service {
	return &Service{}
}


// getKeySize determines the key size for RSA and ECDSA public keys.
func getKeySize(pubKey interface{}) int {
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Params().BitSize
	default:
		return 0
	}
}

// Decode giải mã Certificate từ chuỗi PEM
func (s *Service) Decode(ctx context.Context, certPEM string) (*models.CERDecodeResponse, error) {
	const maxCertSize = 100 * 1024 // 100KB
	// Pre-validate size before anything else
	if len(certPEM) > maxCertSize {
		return nil, errors.New("certificate vượt quá kích thước cho phép")
	}

	// 1. Preprocess
	// Phục hồi literal \n và chuẩn hóa
	certPEM = strings.ReplaceAll(certPEM, `\n`, "\n")
	certPEM = strings.ReplaceAll(certPEM, "\\n", "\n") // Handle escaped backslash n
	certPEM = strings.ReplaceAll(certPEM, "\r\n", "\n")
	certPEM = strings.TrimSpace(certPEM)

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 2. Decode PEM
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("%w: failed to decode PEM block", ErrInvalidPEM)
	}

	// Friendly block type mapping
	switch block.Type {
	case "CERTIFICATE":
		// This is the expected type, continue
	case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
		return nil, fmt.Errorf("%w: đây là Private Key, không phải Certificate", ErrInvalidPEM)
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		return nil, fmt.Errorf("%w: đây là CSR, không phải Certificate", ErrInvalidPEM)
	default:
		return nil, fmt.Errorf("%w: định dạng không được hỗ trợ (%s)", ErrInvalidPEM, block.Type)
	}

	// 3. Parse Certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Debug().Err(err).Msg("x509 parse certificate failed") // Keep debug log
		return nil, fmt.Errorf("%w: %v", ErrInvalidCER, err)     // Return specific error message
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 4. SAN data presence and aggregation
	sans := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses)+len(cert.EmailAddresses)+len(cert.URIs))
	sans = append(sans, cert.DNSNames...)
	sans = append(sans, cert.EmailAddresses...)

	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	for _, uri := range cert.URIs {
		sans = append(sans, uri.String())
	}

	var hasSANData bool
	if len(sans) > 0 {
		hasSANData = true
	}

	// Format serial numbers
	hexStr := fmt.Sprintf("%x", cert.SerialNumber)
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr
	}
	decStr := cert.SerialNumber.String()

	// 5. Build response
	resp := &models.CERDecodeResponse{
		CommonName:         cert.Subject.CommonName,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		Country:            cert.Subject.Country,
		State:              cert.Subject.Province,
		Locality:           cert.Subject.Locality,

		IssuerCommonName:   cert.Issuer.CommonName,
		IssuerOrganization: cert.Issuer.Organization,

		ValidFrom: cert.NotBefore, // Changed to time.Time
		ValidTo:   cert.NotAfter,  // Changed to time.Time

		SerialHex:          hexStr,
		SerialDec:          decStr,
		Algorithm:          cert.PublicKeyAlgorithm.String(), // Renamed back to Algorithm
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		KeySize:            getKeySize(cert.PublicKey), // Using new helper function

		Sans:    sans,
		HasSANs: hasSANData,
	}

	return resp, nil
}
