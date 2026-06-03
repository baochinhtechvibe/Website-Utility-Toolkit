package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func generateTestCertWithOCSP(ocspURL string) (*x509.Certificate, *x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Inc"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		OCSPServer:            []string{ocspURL},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, cert, nil // Self-signed for simplicity, leaf == issuer
}

func TestCRL_SSRFProtection(t *testing.T) {
	ctx := context.Background()

	// Test case 1: Private IP loopback
	_, err := getCRLList(ctx, "http://127.0.0.1:8080/crl")
	if err == nil {
		t.Fatal("Expected SSRF protection error for 127.0.0.1, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF Protection: chặn CRL request đến IP nội bộ") {
		t.Errorf("Expected SSRF error message for CRL, got: %v", err)
	}

	// Test case 2: Private IP Class C
	_, err = getCRLList(ctx, "http://192.168.1.1/crl")
	if err == nil {
		t.Fatal("Expected SSRF protection error for 192.168.1.1, got nil")
	}
	if !strings.Contains(err.Error(), "SSRF Protection: chặn CRL request đến IP nội bộ") {
		t.Errorf("Expected SSRF error message for CRL, got: %v", err)
	}
}

func TestOCSP_SSRFProtection(t *testing.T) {
	ctx := context.Background()

	leaf, issuer, err := generateTestCertWithOCSP("http://127.0.0.1:8080/ocsp")
	if err != nil {
		t.Fatalf("Failed to generate test certificates: %v", err)
	}

	status, err := CheckOCSP(ctx, leaf, issuer, nil)
	if err == nil {
		t.Fatal("Expected SSRF protection error for OCSP, got nil")
	}
	if status != OCSPStatusUnknown {
		t.Errorf("Expected status Unknown on error, got: %v", status)
	}
	if !strings.Contains(err.Error(), "SSRF Protection: chặn OCSP request đến IP nội bộ") {
		t.Errorf("Expected SSRF error message in OCSP, got: %v", err)
	}
}
