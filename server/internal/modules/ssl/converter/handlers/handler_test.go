package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/ssl/converter/service"
)

func TestHandleConvert_MultipartSizeLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.Default()

	// Khởi tạo handler với real service (tuy nhiên test sẽ fail trước khi gọi service)
	svc := service.New()
	handler := NewConvertHandler(svc)

	router.POST("/convert", handler.HandleConvert)

	// Tạo một request Multipart giả mạo lớn hơn giới hạn 2MB (VD: 3MB)
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Thêm 3MB dữ liệu vào form
	part, err := writer.CreateFormFile("certificate", "cert.pem")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}

	// Ghi 3MB chuỗi 'a'
	largeData := strings.Repeat("a", 3*1024*1024)
	part.Write([]byte(largeData))

	writer.WriteField("currentFormat", "pem")
	writer.WriteField("targetFormat", "der")
	writer.Close()

	req, _ := http.NewRequest(http.MethodPost, "/convert", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Nếu http.MaxBytesReader (2MB) hoạt động, ParseMultipartForm sẽ trả về lỗi HTTP 400 hoặc hệ thống chặn request
	// Error code sẽ phụ thuộc vào việc Gin xử lý EOF hoặc max bytes
	if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected 400 or 413 for multipart too large, got %v", w.Code)
	}
}

func generateTestCertPEM(t *testing.T) []byte {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test Co"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	pemBlock := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	return pem.EncodeToMemory(pemBlock)
}

func TestHandleConvert_HappyPath_PEM2DER(t *testing.T) {
	// Skip if openssl is not available
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL not installed, skipping happy path test")
	}

	gin.SetMode(gin.TestMode)
	router := gin.Default()
	svc := service.New()
	handler := NewConvertHandler(svc)
	router.POST("/convert", handler.HandleConvert)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	certPEM := generateTestCertPEM(t)
	part, err := writer.CreateFormFile("certificate", "cert.pem")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}
	part.Write(certPEM)

	writer.WriteField("currentFormat", "pem")
	writer.WriteField("targetFormat", "der")
	writer.Close()

	req, _ := http.NewRequest(http.MethodPost, "/convert", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for valid conversion, got %v", w.Code)
	}
}
