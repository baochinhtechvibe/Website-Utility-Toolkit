package service_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"tools.bctechvibe.com/server/internal/modules/ssl/generator/models"
	"tools.bctechvibe.com/server/internal/modules/ssl/generator/service"
)

func newSvc() service.GeneratorService {
	return service.NewGeneratorService()
}

func parseCSR(t *testing.T, csrPEM string) *x509.CertificateRequest {
	t.Helper()
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("không decode được PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest([]byte(block.Bytes))
	if err != nil {
		t.Fatalf("ParseCertificateRequest lỗi: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CheckSignature lỗi: %v", err)
	}
	return csr
}

// ==========================
// Nhóm 1: Key hợp lệ
// ==========================

func TestGenerateCSR_RSA2048(t *testing.T) {
	res, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "example.com",
		KeyType:    "rsa",
		KeySize:    2048,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.PrivateKey == "" || res.CSR == "" {
		t.Fatal("PrivateKey hoặc CSR trống")
	}
	csr := parseCSR(t, res.CSR)
	if csr.Subject.CommonName != "example.com" {
		t.Errorf("CN sai: got %q", csr.Subject.CommonName)
	}
}

func TestGenerateCSR_RSA4096(t *testing.T) {
	res, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "example.com",
		KeyType:    "rsa",
		KeySize:    4096,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	parseCSR(t, res.CSR)
}

func TestGenerateCSR_ECDSA256(t *testing.T) {
	res, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "ec.example.com",
		KeyType:    "ecdsa",
		KeySize:    256,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	csr := parseCSR(t, res.CSR)
	if csr.Subject.CommonName != "ec.example.com" {
		t.Errorf("CN sai: got %q", csr.Subject.CommonName)
	}
}

func TestGenerateCSR_ECDSA384(t *testing.T) {
	_, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "example.com",
		KeyType:    "ecdsa",
		KeySize:    384,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGenerateCSR_ECDSA521(t *testing.T) {
	_, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "example.com",
		KeyType:    "ecdsa",
		KeySize:    521,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ==========================
// Nhóm 2: Key size sai
// ==========================

func TestGenerateCSR_InvalidRSAKeySize(t *testing.T) {
	_, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "example.com",
		KeyType:    "rsa",
		KeySize:    1024, // không hợp lệ
	})
	// Service không validate key size (handler làm), nhưng rsa.GenerateKey 1024 vẫn thành công
	// Test này kiểm tra service không panic
	if err != nil {
		t.Logf("service trả lỗi (expected nếu có validate): %v", err)
	}
}

func TestGenerateCSR_InvalidECDSAKeySize(t *testing.T) {
	_, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "example.com",
		KeyType:    "ecdsa",
		KeySize:    128, // không hợp lệ
	})
	if err == nil {
		t.Fatal("mong đợi lỗi khi key size ECDSA sai")
	}
}

func TestGenerateCSR_UnknownKeyType(t *testing.T) {
	_, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "example.com",
		KeyType:    "ed25519",
		KeySize:    256,
	})
	if err == nil {
		t.Fatal("mong đợi lỗi khi key type không hỗ trợ")
	}
}

// ==========================
// Nhóm 3: SAN dedup & CN auto-add
// ==========================

func TestGenerateCSR_SANDedupeCN(t *testing.T) {
	res, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "example.com",
		Sans:       []string{"example.com", "www.example.com", "example.com"}, // example.com lặp 2x
		KeyType:    "ecdsa",
		KeySize:    256,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	csr := parseCSR(t, res.CSR)

	count := 0
	for _, d := range csr.DNSNames {
		if d == "example.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("example.com xuất hiện %d lần trong DNSNames, mong đợi 1", count)
	}
}

func TestGenerateCSR_WildcardSAN(t *testing.T) {
	res, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "example.com",
		Sans:       []string{"*.example.com"},
		KeyType:    "ecdsa",
		KeySize:    256,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	csr := parseCSR(t, res.CSR)

	found := false
	for _, d := range csr.DNSNames {
		if d == "*.example.com" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("*.example.com không có trong DNSNames: %v", csr.DNSNames)
	}
}

func TestGenerateCSR_IPSAN(t *testing.T) {
	res, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "example.com",
		Sans:       []string{"192.168.1.1", "10.0.0.1"},
		KeyType:    "ecdsa",
		KeySize:    256,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	csr := parseCSR(t, res.CSR)
	if len(csr.IPAddresses) != 2 {
		t.Errorf("mong đợi 2 IP SAN, got %d: %v", len(csr.IPAddresses), csr.IPAddresses)
	}
}

// ==========================
// Nhóm 4: Subject fields
// ==========================

func TestGenerateCSR_FullSubject(t *testing.T) {
	res, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName:         "example.vn",
		Country:            "VN",
		State:              "Hồ Chí Minh",
		Locality:           "Quận 1",
		Organization:       "Công ty TNHH Test",
		OrganizationalUnit: "IT Department",
		KeyType:            "ecdsa",
		KeySize:            256,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	csr := parseCSR(t, res.CSR)

	if len(csr.Subject.Country) == 0 || csr.Subject.Country[0] != "VN" {
		t.Errorf("Country sai: %v", csr.Subject.Country)
	}
	if len(csr.Subject.Organization) == 0 {
		t.Error("Organization trống")
	}
}

func TestGenerateCSR_LongSubjectField(t *testing.T) {
	// Service không validate độ dài (handler làm), nhưng test để đảm bảo không panic
	longStr := strings.Repeat("A", 1000)
	_, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName:   "example.com",
		Organization: longStr,
		KeyType:      "ecdsa",
		KeySize:      256,
	})
	// Không panic là pass (handler sẽ block trước khi tới đây)
	_ = err
}

// ==========================
// Nhóm 5: Context cancel
// ==========================

func TestGenerateCSR_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel ngay lập tức

	_, err := newSvc().GenerateCSR(ctx, &models.GenerateCSRRequest{
		DomainName: "example.com",
		KeyType:    "ecdsa",
		KeySize:    256,
	})
	if err == nil {
		t.Fatal("mong đợi lỗi khi context đã bị cancel")
	}
}

// ==========================
// Nhóm 6: Verify CSR signature
// ==========================

func TestGenerateCSR_SignatureVerify_RSA(t *testing.T) {
	res, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "verify.example.com",
		KeyType:    "rsa",
		KeySize:    2048,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	csr := parseCSR(t, res.CSR) // parseCSR đã gọi CheckSignature
	if csr.Subject.CommonName != "verify.example.com" {
		t.Errorf("CN sai: %q", csr.Subject.CommonName)
	}
}

func TestGenerateCSR_SignatureVerify_ECDSA(t *testing.T) {
	res, err := newSvc().GenerateCSR(context.Background(), &models.GenerateCSRRequest{
		DomainName: "verify.ec.example.com",
		KeyType:    "ecdsa",
		KeySize:    384,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	parseCSR(t, res.CSR) // kiểm tra signature
}
