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
	"math/big"
	"strings"
	"testing"
	"time"

	"tools.bctechvibe.com/server/internal/modules/ssl/key-matcher/models"
	"tools.bctechvibe.com/server/internal/modules/ssl/key-matcher/service"
)

// ─── Helpers ───────────────────────────────────────────────────────────────

type keyPair struct {
	privPEM string
	pubPEM  string
	csrPEM  string
	certPEM string
}

func genRSA(t *testing.T, bits int) keyPair {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))

	return makeArtifacts(t, priv, priv.Public(), privPEM)
}

func genECDSA(t *testing.T, curve elliptic.Curve) keyPair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))

	return makeArtifacts(t, priv, priv.Public(), privPEM)
}

func genEd25519(t *testing.T) keyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	privDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	privPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}))

	return makeArtifacts(t, priv, pub, privPEM)
}

func makeArtifacts(t *testing.T, priv interface{}, pub interface{}, privPEM string) keyPair {
	t.Helper()
	// Public key
	pubDER, _ := x509.MarshalPKIXPublicKey(pub)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	// CSR
	csrTmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, priv)
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	// Cert
	certTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, certTmpl, certTmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCert: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	return keyPair{
		privPEM: privPEM,
		pubPEM:  pubPEM,
		csrPEM:  csrPEM,
		certPEM: certPEM,
	}
}

func svc() *service.Service { return service.New() }

// ─── Nhóm 1: Match ────────────────────────────────────────────────────────

func TestMatch_CertKey_Match(t *testing.T) {
	tests := []struct {
		name string
		kp   keyPair
	}{
		{"RSA_2048", genRSA(t, 2048)},
		{"ECDSA_P256", genECDSA(t, elliptic.P256())},
		{"Ed25519", genEd25519(t)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := models.MatchRequest{
				Type:   "cert_key",
				Input1: tt.kp.privPEM,
				Input2: tt.kp.certPEM,
			}
			res, err := svc().Match(context.Background(), req)
			if err != nil {
				t.Fatalf("lỗi bất ngờ: %v", err)
			}
			if res.InputErrors != nil {
				t.Fatalf("lỗi input: %+v", res.InputErrors)
			}
			if !res.Matched {
				t.Error("mong đợi khớp, nhưng kết quả không khớp")
			}
			if res.Hash1 == "" || res.Hash1 != res.Hash2 {
				t.Errorf("Hash không khớp hoặc rỗng: hash1=%s, hash2=%s", res.Hash1, res.Hash2)
			}
		})
	}
}

func TestMatch_CSRCERT_Match(t *testing.T) {
	kp := genRSA(t, 2048)
	req := models.MatchRequest{
		Type:   "csr_cert",
		Input1: kp.csrPEM,
		Input2: kp.certPEM,
	}
	res, err := svc().Match(context.Background(), req)
	if err != nil {
		t.Fatalf("lỗi bất ngờ: %v", err)
	}
	if !res.Matched {
		t.Error("mong đợi khớp, nhưng kết quả không khớp")
	}
}

func TestMatch_Mismatch(t *testing.T) {
	kp1 := genRSA(t, 2048)
	kp2 := genRSA(t, 2048) // Key khác

	req := models.MatchRequest{
		Type:   "cert_key",
		Input1: kp1.privPEM,
		Input2: kp2.certPEM,
	}
	res, err := svc().Match(context.Background(), req)
	if err != nil {
		t.Fatalf("lỗi bất ngờ: %v", err)
	}
	if res.InputErrors != nil {
		t.Fatalf("lỗi input: %+v", res.InputErrors)
	}
	if res.Matched {
		t.Error("mong đợi không khớp, nhưng kết quả báo khớp")
	}
}

// ─── Nhóm 2: Lỗi input ────────────────────────────────────────────────────

func TestMatch_WrongType(t *testing.T) {
	kp := genRSA(t, 2048)

	req := models.MatchRequest{
		Type:   "cert_key",
		Input1: kp.certPEM, // Input 1 đòi private key, nhưng đưa cert
		Input2: kp.privPEM, // Input 2 đòi cert, nhưng đưa private key
	}
	res, err := svc().Match(context.Background(), req)
	if err != nil {
		t.Fatalf("lỗi bất ngờ: %v", err)
	}
	if res.InputErrors == nil {
		t.Fatal("mong đợi InputErrors nhưng got nil")
	}
	if res.InputErrors.Input1 == "" || res.InputErrors.Input2 == "" {
		t.Errorf("phải có lỗi ở cả 2 input: %+v", res.InputErrors)
	}
}

func TestMatch_TrailingData(t *testing.T) {
	kp := genRSA(t, 2048)

	req := models.MatchRequest{
		Type:   "cert_key",
		Input1: kp.privPEM + "\n" + kp.certPEM, // Trailing cert sau private key
		Input2: kp.certPEM,
	}
	res, err := svc().Match(context.Background(), req)
	if err != nil {
		t.Fatalf("lỗi bất ngờ: %v", err)
	}
	if res.InputErrors == nil || res.InputErrors.Input1 == "" {
		t.Fatal("mong đợi InputErrors.Input1 khi có trailing data")
	}
}

func TestMatch_OversizedInput(t *testing.T) {
	kp := genRSA(t, 2048)
	huge := strings.Repeat("A", 101*1024)

	req := models.MatchRequest{
		Type:   "cert_key",
		Input1: kp.privPEM,
		Input2: huge,
	}
	res, err := svc().Match(context.Background(), req)
	if err != nil {
		t.Fatalf("lỗi bất ngờ: %v", err)
	}
	if res.InputErrors == nil || res.InputErrors.Input2 == "" {
		t.Fatal("mong đợi InputErrors.Input2 khi input quá lớn")
	}
}

func TestMatch_InvalidTypeMode(t *testing.T) {
	req := models.MatchRequest{
		Type:   "unknown_mode",
		Input1: "foo",
		Input2: "bar",
	}
	_, err := svc().Match(context.Background(), req)
	if err == nil {
		t.Fatal("mong đợi lỗi khi truyền type sai")
	}
}
