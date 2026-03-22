package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"

	"tools.bctechvibe.com/server/internal/modules/ssl/generator/models"
)

// GeneratorService là Interface để khởi tạo các Private Key và CSR Payload cho module Generator
type GeneratorService interface {
	GenerateCSR(ctx context.Context, req *models.GenerateCSRRequest) (*models.GenerateCSRResponse, error)
}

type generatorService struct{}

func NewGeneratorService() GeneratorService {
	return &generatorService{}
}

func (s *generatorService) GenerateCSR(ctx context.Context, req *models.GenerateCSRRequest) (*models.GenerateCSRResponse, error) {
	// 1. Kiểm tra Context Timeout ban đầu
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 2. Sinh Private Key (Mảng Bytes và Object PKI)
	var privateKey interface{}
	var keyPEM []byte

	switch req.KeyType {
	case "rsa":
		rsaKey, err := rsa.GenerateKey(rand.Reader, req.KeySize)
		if err != nil {
			return nil, errors.New("không thể sinh khóa RSA, vui lòng thử lại")
		}
		privateKey = rsaKey
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(rsaKey),
		})
	case "ecdsa":
		var curve elliptic.Curve
		switch req.KeySize {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, errors.New("kích thước khóa ECDSA không hợp lệ")
		}

		ecKey, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, errors.New("không thể sinh khóa ECDSA, vui lòng thử lại")
		}
		privateKey = ecKey
		ecBytes, err := x509.MarshalECPrivateKey(ecKey)
		if err != nil {
			return nil, errors.New("không thể mã hóa khóa ECDSA, vui lòng thử lại")
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: ecBytes,
		})
	default:
		return nil, errors.New("loại thuật toán khóa không hỗ trợ")
	}

	// 3. Kiểm tra Context Timeout sau quá trình sinh Key rất tốn phần cứng Server 
	// (đặc biệt là đối với RSA 4096-bit mất tới vài giây)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// 4. Setup Subject Names
	subject := pkix.Name{
		CommonName: req.DomainName,
	}
	if req.Country != "" {
		subject.Country = []string{req.Country}
	}
	if req.Organization != "" {
		subject.Organization = []string{req.Organization}
	}
	if req.OrganizationalUnit != "" {
		subject.OrganizationalUnit = []string{req.OrganizationalUnit}
	}
	if req.Locality != "" {
		subject.Locality = []string{req.Locality}
	}
	if req.State != "" {
		subject.Province = []string{req.State}
	}

	// 5. Setup DNS Names & IP Addresses dựa theo Payload gửi về
	var dnsNames []string
	var ipAddresses []net.IP

	// Function tự deduplicate tự nhét DNS và vòng lặp
	addSan := func(san string) {
		sanIP := net.ParseIP(san)
		if sanIP != nil {
			// Check trùng lặp IP Address
			for _, existingIP := range ipAddresses {
				if existingIP.Equal(sanIP) {
					return
				}
			}
			ipAddresses = append(ipAddresses, sanIP)
		} else {
			// Check trùng lặp Chuỗi Tên Miền
			for _, existingDNS := range dnsNames {
				if existingDNS == san {
					return
				}
			}
			dnsNames = append(dnsNames, san)
		}
	}

	// Tự động Add quy định luật CN vào Host SANs đầu tiên (Deduplication pattern)
	// Bắt buộc ở Browser ngày nay để tránh Invalid CA SSL Error (Do bỏ Standard CN cũ)
	addSan(req.DomainName)

	// Lặp duyệt cho các SANs khác còn lại vào mảng List chuẩn
	for _, san := range req.Sans {
		if san != "" {
			addSan(san)
		}
	}

	// 6. Khởi tạo CSR Request Template 
	template := x509.CertificateRequest{
		Subject:            subject,
		// Không set SignatureAlgorithm ở đây, Golang sẽ tự chọn thuật toán phù hợp nhất dựa vào cấu trúc PKI Key tương ứng.
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
	}

	// Create CSR bằng hàm nội bộ của Go sử dụng Cấp phát Random Data Block
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	if err != nil {
		return nil, errors.New("không thể tạo CSR, vui lòng kiểm tra lại thông tin")
	}

	// Định dạng Mảng Bytes thành PEM block tiêu chuẩn của Apache/Nginx
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	// SECURITY NOTE: Private key is generated in-memory and returned to client over HTTPS. 
	// It is never persisted to disk or logged. Client is responsible for securing the key after download.
	return &models.GenerateCSRResponse{
		CSR:        string(csrPEM),
		PrivateKey: string(keyPEM),
	}, nil
}
