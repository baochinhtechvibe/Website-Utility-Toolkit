package service_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"testing"

	"tools.bctechvibe.com/server/internal/modules/ssl/csr-decoder/service"
)

// ─── Helpers ───────────────────────────────────────────────────────────────

func genRSACSR(t *testing.T, bits int, tmpl *x509.CertificateRequest) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("gen RSA key: %v", err)
	}
	return csrPEM(t, tmpl, key)
}

func genECDSACSR(t *testing.T, curve elliptic.Curve, tmpl *x509.CertificateRequest) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("gen ECDSA key: %v", err)
	}
	return csrPEM(t, tmpl, key)
}

func genEd25519CSR(t *testing.T, tmpl *x509.CertificateRequest) string {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen Ed25519 key: %v", err)
	}
	return csrPEM(t, tmpl, key)
}

func csrPEM(t *testing.T, tmpl *x509.CertificateRequest, key interface{}) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func svc() *service.Service { return service.New() }

func decode(t *testing.T, csrPEM string) (*service.Service, error) {
	t.Helper()
	return svc(), nil
}

// ─── Nhóm 1: CSR hợp lệ ───────────────────────────────────────────────────

func TestDecode_ValidRSA2048(t *testing.T) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	p := genRSACSR(t, 2048, tmpl)

	res, err := svc().Decode(context.Background(), p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.CommonName != "example.com" {
		t.Errorf("CN sai: %q", res.CommonName)
	}
	if res.KeySize != 2048 {
		t.Errorf("KeySize sai: got %d, want 2048", res.KeySize)
	}
	if res.Algorithm != "RSA" {
		t.Errorf("Algorithm sai: %q", res.Algorithm)
	}
}

func TestDecode_ValidECDSAP256(t *testing.T) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ec.example.com"}}
	p := genECDSACSR(t, elliptic.P256(), tmpl)

	res, err := svc().Decode(context.Background(), p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.KeySize != 256 {
		t.Errorf("ECDSA P-256 KeySize sai: %d", res.KeySize)
	}
}

func TestDecode_ValidECDSAP384(t *testing.T) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	p := genECDSACSR(t, elliptic.P384(), tmpl)

	res, err := svc().Decode(context.Background(), p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.KeySize != 384 {
		t.Errorf("ECDSA P-384 KeySize sai: %d", res.KeySize)
	}
}

// ─── Nhóm 2: Ed25519 key size ─────────────────────────────────────────────

func TestDecode_Ed25519KeySize(t *testing.T) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ed.example.com"}}
	p := genEd25519CSR(t, tmpl)

	res, err := svc().Decode(context.Background(), p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.KeySize != 256 {
		t.Errorf("Ed25519 KeySize phải là 256, got %d", res.KeySize)
	}
	if res.Algorithm != "Ed25519" {
		t.Errorf("Algorithm sai: %q", res.Algorithm)
	}
}

// ─── Nhóm 3: SAN types ────────────────────────────────────────────────────

func TestDecode_SANDNSAndIP(t *testing.T) {
	emailAddr, _ := mail.ParseAddress("admin@example.com")
	_ = emailAddr
	uri, _ := url.Parse("https://example.com/path")

	tmpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "example.com"},
		DNSNames:       []string{"example.com", "www.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1")},
		EmailAddresses: []string{"admin@example.com"},
		URIs:           []*url.URL{uri},
	}
	p := genRSACSR(t, 2048, tmpl)

	res, err := svc().Decode(context.Background(), p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.HasSANs {
		t.Error("HasSANs phải là true")
	}
	// Phải có DNS, IP, email, URI
	hasDNS, hasIP, hasEmail, hasURI := false, false, false, false
	for _, s := range res.Sans {
		if s == "www.example.com" {
			hasDNS = true
		}
		if s == "192.168.1.1" {
			hasIP = true
		}
		if s == "admin@example.com" {
			hasEmail = true
		}
		if strings.Contains(s, "https://") {
			hasURI = true
		}
	}
	if !hasDNS {
		t.Error("thiếu DNS SAN")
	}
	if !hasIP {
		t.Error("thiếu IP SAN")
	}
	if !hasEmail {
		t.Error("thiếu Email SAN")
	}
	if !hasURI {
		t.Error("thiếu URI SAN")
	}
}

// ─── Nhóm 4: Lỗi input ────────────────────────────────────────────────────

func TestDecode_InvalidPEM(t *testing.T) {
	_, err := svc().Decode(context.Background(), "this is not PEM at all")
	if !errors.Is(err, service.ErrInvalidPEM) {
		t.Errorf("mong đợi ErrInvalidPEM, got: %v", err)
	}
}

func TestDecode_WrongPEMType_Certificate(t *testing.T) {
	// Tạo self-signed cert thay vì CSR
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "example.com"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	_, err := svc().Decode(context.Background(), certPEM)
	if !errors.Is(err, service.ErrInvalidPEM) {
		t.Errorf("mong đợi ErrInvalidPEM khi gửi CERTIFICATE, got: %v", err)
	}
}

func TestDecode_WrongPEMType_PrivateKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}))

	_, err := svc().Decode(context.Background(), keyPEM)
	if !errors.Is(err, service.ErrInvalidPEM) {
		t.Errorf("mong đợi ErrInvalidPEM khi gửi private key, got: %v", err)
	}
}

func TestDecode_BadSignature(t *testing.T) {
	// Tạo CSR hợp lệ rồi tamper bytes
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "tamper.com"}}
	p := genRSACSR(t, 2048, tmpl)

	block, _ := pem.Decode([]byte(p))
	block.Bytes[len(block.Bytes)-1] ^= 0xFF // flip last byte

	tampered := string(pem.EncodeToMemory(block))
	_, err := svc().Decode(context.Background(), tampered)
	if err == nil {
		t.Fatal("mong đợi lỗi khi CSR bị tamper")
	}
}

// ─── Nhóm 5: [P1] Too large → ErrCSRTooLarge ─────────────────────────────

func TestDecode_TooLarge(t *testing.T) {
	huge := strings.Repeat("A", 101*1024) // 101KB
	_, err := svc().Decode(context.Background(), huge)
	if !errors.Is(err, service.ErrCSRTooLarge) {
		t.Errorf("mong đợi ErrCSRTooLarge, got: %v", err)
	}
}

// ─── Nhóm 6: [P2] Trailing PEM → ErrTrailingPEM ──────────────────────────

func TestDecode_TrailingPEM(t *testing.T) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	csrStr := genRSACSR(t, 2048, tmpl)

	// Gắn thêm private key vào sau CSR
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	combined := csrStr + "\n" + keyPEM

	_, err := svc().Decode(context.Background(), combined)
	if !errors.Is(err, service.ErrTrailingPEM) {
		t.Errorf("mong đợi ErrTrailingPEM, got: %v", err)
	}
}

func TestDecode_TrailingText(t *testing.T) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	csrStr := genRSACSR(t, 2048, tmpl)
	combined := csrStr + "\nsome random trailing text"

	_, err := svc().Decode(context.Background(), combined)
	if !errors.Is(err, service.ErrTrailingPEM) {
		t.Errorf("mong đợi ErrTrailingPEM khi có trailing text, got: %v", err)
	}
}

// ─── Nhóm 7: Context cancel ───────────────────────────────────────────────

func TestDecode_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	p := genRSACSR(t, 2048, tmpl)

	_, err := svc().Decode(ctx, p)
	if err == nil {
		t.Fatal("mong đợi lỗi khi context bị cancel")
	}
}

// ─── Nhóm 8: Full subject fields ─────────────────────────────────────────

func TestDecode_FullSubject(t *testing.T) {
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "example.vn",
			Organization:       []string{"Công ty Test"},
			OrganizationalUnit: []string{"IT"},
			Country:            []string{"VN"},
			Province:           []string{"Hồ Chí Minh"},
			Locality:           []string{"Quận 1"},
		},
	}
	p := genRSACSR(t, 2048, tmpl)

	res, err := svc().Decode(context.Background(), p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res.Country) == 0 || res.Country[0] != "VN" {
		t.Errorf("Country sai: %v", res.Country)
	}
	if len(res.Organization) == 0 {
		t.Error("Organization trống")
	}
	if res.CommonName != "example.vn" {
		t.Errorf("CN sai: %q", res.CommonName)
	}
}

func TestDecode_NoSANs(t *testing.T) {
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	p := genRSACSR(t, 2048, tmpl)

	res, err := svc().Decode(context.Background(), p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.HasSANs {
		t.Error("HasSANs phải là false khi không có SAN")
	}
}
