package handlers_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/ssl/converter/handlers"
	"tools.bctechvibe.com/server/internal/modules/ssl/converter/models"
)

// --- Mock Service ---
type mockService struct {
	convertFunc func(ctx context.Context, req *models.ConvertRequest) (*models.ConvertResponse, error)
}

func (m *mockService) Convert(ctx context.Context, req *models.ConvertRequest) (*models.ConvertResponse, error) {
	if m.convertFunc != nil {
		return m.convertFunc(ctx, req)
	}
	return &models.ConvertResponse{
		Filename:    "test.pem",
		Data:        "dGVzdA==",
		ContentType: "application/x-pem-file",
	}, nil
}

func init() {
	gin.SetMode(gin.TestMode)
}

func setupRouter(svc *mockService) *gin.Engine {
	router := gin.Default()
	handler := handlers.NewConvertHandler(svc)
	router.POST("/convert", handler.HandleConvert)
	return router
}

// ─── Helpers ───────────────────────────────────────────────────────────────

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

func createMultipartReq(t *testing.T, currentFormat, targetFormat string, certData []byte) (*http.Request, string) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	if certData != nil {
		part, err := writer.CreateFormFile("certificate", "cert.pem")
		if err != nil {
			t.Fatalf("Failed to create form file: %v", err)
		}
		part.Write(certData)
	}

	if currentFormat != "" {
		writer.WriteField("currentFormat", currentFormat)
	}
	if targetFormat != "" {
		writer.WriteField("targetFormat", targetFormat)
	}
	writer.Close()

	req, _ := http.NewRequest(http.MethodPost, "/convert", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req, writer.FormDataContentType()
}

// ─── Tests ────────────────────────────────────────────────────────────────

func TestHandleConvert_ValidRequest(t *testing.T) {
	svc := &mockService{}
	router := setupRouter(svc)
	certPEM := generateTestCertPEM(t)
	req, _ := createMultipartReq(t, "pem", "der", certPEM)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %v", w.Code)
	}

	// Đảm bảo có Cache-Control: no-store
	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("Expected Cache-Control: no-store in response, got %s", cc)
	}
}

func TestHandleConvert_InvalidFormat(t *testing.T) {
	svc := &mockService{}
	router := setupRouter(svc)
	certPEM := generateTestCertPEM(t)
	// 'txt' is invalid
	req, _ := createMultipartReq(t, "txt", "der", certPEM)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid format, got %v", w.Code)
	}
}

func TestHandleConvert_SameFormat(t *testing.T) {
	svc := &mockService{}
	router := setupRouter(svc)
	certPEM := generateTestCertPEM(t)
	// pem -> pem is invalid
	req, _ := createMultipartReq(t, "pem", "pem", certPEM)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for same format, got %v", w.Code)
	}
}

func TestHandleConvert_MissingCertificate(t *testing.T) {
	svc := &mockService{}
	router := setupRouter(svc)
	// certData = nil
	req, _ := createMultipartReq(t, "pem", "der", nil)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for missing certificate, got %v", w.Code)
	}
}

func TestHandleConvert_PerFileTooLarge(t *testing.T) {
	svc := &mockService{}
	router := setupRouter(svc)
	// 513KB file
	largeData := bytes.Repeat([]byte("A"), 513*1024)
	req, _ := createMultipartReq(t, "pem", "der", largeData)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for file too large, got %v", w.Code)
	}
}

func TestHandleConvert_ServiceTimeout(t *testing.T) {
	svc := &mockService{
		convertFunc: func(ctx context.Context, req *models.ConvertRequest) (*models.ConvertResponse, error) {
			return nil, context.DeadlineExceeded
		},
	}
	router := setupRouter(svc)
	certPEM := generateTestCertPEM(t)
	req, _ := createMultipartReq(t, "pem", "der", certPEM)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusGatewayTimeout {
		t.Errorf("Expected 504 for service timeout, got %v", w.Code)
	}
}

func TestHandleConvert_ServiceError(t *testing.T) {
	svc := &mockService{
		convertFunc: func(ctx context.Context, req *models.ConvertRequest) (*models.ConvertResponse, error) {
			return nil, errors.New("Mật khẩu PFX là bắt buộc để mã hóa/giải mã.")
		},
	}
	router := setupRouter(svc)
	certPEM := generateTestCertPEM(t)
	req, _ := createMultipartReq(t, "pem", "der", certPEM)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for service input error, got %v", w.Code)
	}
}
