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
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"strings"
	"testing"
	"time"

	"tools.bctechvibe.com/server/internal/modules/ssl/cer-decoder/service"
)

// ─── Helpers ───────────────────────────────────────────────────────────────

func genRSACert(t *testing.T, bits int, tmpl *x509.Certificate) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("gen RSA key: %v", err)
	}
	return certPEM(t, tmpl, key.Public(), key)
}

func genECDSACert(t *testing.T, curve elliptic.Curve, tmpl *x509.Certificate) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("gen ECDSA key: %v", err)
	}
	return certPEM(t, tmpl, key.Public(), key)
}

func genEd25519Cert(t *testing.T, tmpl *x509.Certificate) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen Ed25519 key: %v", err)
	}
	return certPEM(t, tmpl, pub, priv)
}

func certPEM(t *testing.T, tmpl *x509.Certificate, pub interface{}, priv interface{}) string {
	t.Helper()
	if tmpl.SerialNumber == nil {
		tmpl.SerialNumber = big.NewInt(1)
	}
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now()
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(time.Hour)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func svc() *service.Service { return service.New() }

// ─── Nhóm 1: Certificate hợp lệ ───────────────────────────────────────────

func TestDecode_ValidRSA2048(t *testing.T) {
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "example.com"}}
	p := genRSACert(t, 2048, tmpl)

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
}

func TestDecode_ValidECDSAP256(t *testing.T) {
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "ec.example.com"}}
	p := genECDSACert(t, elliptic.P256(), tmpl)

	res, err := svc().Decode(context.Background(), p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.KeySize != 256 {
		t.Errorf("ECDSA P-256 KeySize sai: %d", res.KeySize)
	}
}

// ─── Nhóm 2: Ed25519 key size ─────────────────────────────────────────────

func TestDecode_Ed25519KeySize(t *testing.T) {
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "ed.example.com"}}
	p := genEd25519Cert(t, tmpl)

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

	tmpl := &x509.Certificate{
		Subject:        pkix.Name{CommonName: "example.com"},
		DNSNames:       []string{"example.com", "www.example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1")},
		EmailAddresses: []string{"admin@example.com"},
		URIs:           []*url.URL{uri},
	}
	p := genRSACert(t, 2048, tmpl)

	res, err := svc().Decode(context.Background(), p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.HasSANs {
		t.Error("HasSANs phải là true")
	}

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

func TestDecode_WrongPEMType_CSR(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	der, _ := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))

	_, err := svc().Decode(context.Background(), csrPEM)
	if !errors.Is(err, service.ErrInvalidPEM) {
		t.Errorf("mong đợi ErrInvalidPEM khi gửi CSR, got: %v", err)
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

// ─── Nhóm 5: [P1] Too large → ErrCertTooLarge ─────────────────────────────

func TestDecode_TooLarge(t *testing.T) {
	huge := strings.Repeat("A", 101*1024) // 101KB
	_, err := svc().Decode(context.Background(), huge)
	if !errors.Is(err, service.ErrCertTooLarge) {
		t.Errorf("mong đợi ErrCertTooLarge, got: %v", err)
	}
}

// ─── Nhóm 6: [P1] Trailing PEM → ErrTrailingPEM ──────────────────────────

func TestDecode_TrailingPEM(t *testing.T) {
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "example.com"}}
	certStr := genRSACert(t, 2048, tmpl)

	// Gắn thêm private key vào sau Certificate
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	combined := certStr + "\n" + keyPEM

	_, err := svc().Decode(context.Background(), combined)
	if !errors.Is(err, service.ErrTrailingPEM) {
		t.Errorf("mong đợi ErrTrailingPEM, got: %v", err)
	}
}

func TestDecode_TrailingText(t *testing.T) {
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "example.com"}}
	certStr := genRSACert(t, 2048, tmpl)
	combined := certStr + "\nsome random trailing text"

	_, err := svc().Decode(context.Background(), combined)
	if !errors.Is(err, service.ErrTrailingPEM) {
		t.Errorf("mong đợi ErrTrailingPEM khi có trailing text, got: %v", err)
	}
}

// ─── Nhóm 7: Context cancel ───────────────────────────────────────────────

func TestDecode_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "example.com"}}
	p := genRSACert(t, 2048, tmpl)

	_, err := svc().Decode(ctx, p)
	if err == nil {
		t.Fatal("mong đợi lỗi khi context bị cancel")
	}
}
