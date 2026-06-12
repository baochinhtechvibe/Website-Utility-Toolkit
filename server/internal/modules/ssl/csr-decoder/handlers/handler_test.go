package handlers_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"tools.bctechvibe.com/server/internal/modules/ssl/csr-decoder/handlers"
	"tools.bctechvibe.com/server/internal/modules/ssl/csr-decoder/service"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// ─── Helpers ───────────────────────────────────────────────────────────────

func newRouter() *gin.Engine {
	r := gin.New()
	svc := service.New()
	h := handlers.NewCSRHandler(svc)
	r.POST("/ssl/csr/decode", h.HandleCSRDecode)
	return r
}

func postDecode(t *testing.T, router *gin.Engine, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/ssl/csr/decode", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func makeCSRPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "example.com"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// ─── [P1] Valid CSR → 200 ─────────────────────────────────────────────────

func TestHandler_ValidCSR_Returns200(t *testing.T) {
	r := newRouter()
	w := postDecode(t, r, map[string]string{"csr": makeCSRPEM(t)})

	if w.Code != http.StatusOK {
		t.Fatalf("mong đợi 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["success"] != true {
		t.Error("success phải là true")
	}
	data, _ := resp["data"].(map[string]interface{})
	if data["common_name"] == nil {
		t.Error("common_name trống trong response")
	}
}

// ─── [P1] CSR >100KB nhưng body <256KB → 400 (không phải 500) ─────────────

func TestHandler_CSRTooLarge_Returns400(t *testing.T) {
	r := newRouter()

	// Tạo body hợp lệ nhưng CSR field có size 101KB
	bigCSR := strings.Repeat("A", 101*1024)
	w := postDecode(t, r, map[string]string{"csr": bigCSR})

	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 khi CSR >100KB, got %d: %s", w.Code, w.Body.String())
	}

	// Đảm bảo không trả 500
	if w.Code == http.StatusInternalServerError {
		t.Error("CSR quá lớn không được phép trả 500 Internal Server Error")
	}
}

// ─── [P1] CSR + trailing private key → 400 ───────────────────────────────

func TestHandler_TrailingPrivateKey_Returns400(t *testing.T) {
	r := newRouter()
	csrPEM := makeCSRPEM(t)

	// Gắn thêm private key vào sau
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	combined := csrPEM + "\n" + keyPEM

	w := postDecode(t, r, map[string]string{"csr": combined})
	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 khi CSR có trailing private key, got %d: %s", w.Code, w.Body.String())
	}
}

// ─── [P1] CSR + trailing text → 400 ──────────────────────────────────────

func TestHandler_TrailingText_Returns400(t *testing.T) {
	r := newRouter()
	combined := makeCSRPEM(t) + "\nsome extra text"

	w := postDecode(t, r, map[string]string{"csr": combined})
	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 khi CSR có trailing text, got %d", w.Code)
	}
}

// ─── [P1] Invalid PEM → 400 ───────────────────────────────────────────────

func TestHandler_InvalidPEM_Returns400(t *testing.T) {
	r := newRouter()
	w := postDecode(t, r, map[string]string{"csr": "this is not PEM"})

	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 khi PEM không hợp lệ, got %d", w.Code)
	}
}

// ─── [P1] Certificate thay vì CSR → 400 ──────────────────────────────────

func TestHandler_CertificateInsteadOfCSR_Returns400(t *testing.T) {
	r := newRouter()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "example.com"}}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	w := postDecode(t, r, map[string]string{"csr": certPEM})
	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 khi gửi CERTIFICATE thay vì CSR, got %d", w.Code)
	}
}

// ─── [P1] Private key thay vì CSR → 400 ──────────────────────────────────

func TestHandler_PrivateKeyInsteadOfCSR_Returns400(t *testing.T) {
	r := newRouter()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))

	w := postDecode(t, r, map[string]string{"csr": keyPEM})
	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 khi gửi private key thay vì CSR, got %d", w.Code)
	}
}

// ─── Body rỗng → 400 ──────────────────────────────────────────────────────

func TestHandler_EmptyBody_Returns400(t *testing.T) {
	r := newRouter()
	req := httptest.NewRequest(http.MethodPost, "/ssl/csr/decode", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 khi body rỗng, got %d", w.Code)
	}
}

// ─── Body >256KB → 400 ────────────────────────────────────────────────────

func TestHandler_OversizedBody_Returns400(t *testing.T) {
	r := newRouter()

	// Body 260KB
	bigBody := `{"csr":"` + strings.Repeat("A", 260*1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/ssl/csr/decode", strings.NewReader(bigBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 khi body >256KB, got %d", w.Code)
	}
}
