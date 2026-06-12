package handlers_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"tools.bctechvibe.com/server/internal/modules/ssl/generator/handlers"
	"tools.bctechvibe.com/server/internal/modules/ssl/generator/models"
	"tools.bctechvibe.com/server/internal/modules/ssl/generator/service"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// mockService cho phép inject lỗi từ bên ngoài để test handler logic
type mockService struct {
	resp *models.GenerateCSRResponse
	err  error
}

func (m *mockService) GenerateCSR(_ context.Context, _ *models.GenerateCSRRequest) (*models.GenerateCSRResponse, error) {
	return m.resp, m.err
}

func newRouter(svc service.GeneratorService) *gin.Engine {
	r := gin.New()
	h := handlers.NewGeneratorHandler(svc)
	r.POST("/ssl/generator/csr", h.GenerateCSR)
	return r
}

func realRouter() *gin.Engine {
	return newRouter(service.NewGeneratorService())
}

func postCSR(t *testing.T, router *gin.Engine, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/ssl/generator/csr", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// ===========================
// [P1] Cache-Control header
// ===========================

func TestHandler_CacheControlNoStore(t *testing.T) {
	r := realRouter()
	w := postCSR(t, r, map[string]interface{}{
		"domainName": "example.com",
		"keyType":    "ecdsa",
		"keySize":    256,
	})

	if w.Code != http.StatusOK {
		t.Fatalf("mong đợi 200, got %d: %s", w.Code, w.Body.String())
	}

	cc := w.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control thiếu 'no-store': %q", cc)
	}
	pragma := w.Header().Get("Pragma")
	if pragma != "no-cache" {
		t.Errorf("Pragma sai: %q", pragma)
	}
}

// ===========================
// [P2] IDN Normalize → Punycode
// ===========================

// TestHandler_IDNDomainNormalized gửi domain Unicode (münchen.de),
// verify backend normalize sang punycode đúng (xn--mnchen-3ya.de) và CSR CN phải chứa punycode.
func TestHandler_IDNDomainNormalized(t *testing.T) {
	r := realRouter()
	w := postCSR(t, r, map[string]interface{}{
		"domainName": "münchen.de", // ü = U+00FC, hợp lệ IDNA2008 → xn--mnchen-3ya.de
		"keyType":    "ecdsa",
		"keySize":    256,
	})

	// Backend phải normalize thành công và trả 200
	if w.Code != http.StatusOK {
		t.Fatalf("backend phải chấp nhận domain IDN hợp lệ, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response không phải JSON: %v", err)
	}
	data, _ := resp["data"].(map[string]interface{})
	csrPEM, _ := data["csr"].(string)

	// Parse CSR để kiểm tra CN chứa punycode
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatal("không decode được PEM CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest lỗi: %v", err)
	}

	const wantCN = "xn--mnchen-3ya.de"
	if csr.Subject.CommonName != wantCN {
		t.Errorf("CN phải là punycode %q, got %q", wantCN, csr.Subject.CommonName)
	}
}

// ===========================
// [P2] Subject field quá dài → 400
// ===========================

func TestHandler_OrgTooLong_Returns400(t *testing.T) {
	r := realRouter()
	w := postCSR(t, r, map[string]interface{}{
		"domainName":   "example.com",
		"organization": strings.Repeat("A", 300), // vượt max=256
		"keyType":      "ecdsa",
		"keySize":      256,
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 khi organization quá dài, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_StateTooLong_Returns400(t *testing.T) {
	r := realRouter()
	w := postCSR(t, r, map[string]interface{}{
		"domainName": "example.com",
		"state":      strings.Repeat("B", 200), // vượt max=128
		"keyType":    "ecdsa",
		"keySize":    256,
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 khi state quá dài, got %d", w.Code)
	}
}

// ===========================
// [P2] Key size không hợp lệ → 400
// ===========================

func TestHandler_RSA1024_Returns400(t *testing.T) {
	r := realRouter()
	w := postCSR(t, r, map[string]interface{}{
		"domainName": "example.com",
		"keyType":    "rsa",
		"keySize":    1024,
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 cho RSA 1024, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandler_ECDSA128_Returns400(t *testing.T) {
	r := realRouter()
	w := postCSR(t, r, map[string]interface{}{
		"domainName": "example.com",
		"keyType":    "ecdsa",
		"keySize":    128,
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 cho ECDSA 128, got %d", w.Code)
	}
}


// ===========================
// Regression: success response format
// ===========================

func TestHandler_SuccessResponseFormat(t *testing.T) {
	r := realRouter()
	w := postCSR(t, r, map[string]interface{}{
		"domainName": "format-test.com",
		"keyType":    "ecdsa",
		"keySize":    256,
	})

	if w.Code != http.StatusOK {
		t.Fatalf("mong đợi 200, got %d: %s", w.Code, w.Body.String())
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response không phải JSON hợp lệ: %v", err)
	}
	if body["success"] != true {
		t.Errorf("success phải là true, got %v", body["success"])
	}
	data, ok := body["data"].(map[string]interface{})
	if !ok {
		t.Fatal("data field không phải object")
	}
	if data["csr"] == "" || data["csr"] == nil {
		t.Error("CSR trống trong response")
	}
	if data["privateKey"] == "" || data["privateKey"] == nil {
		t.Error("privateKey trống trong response")
	}
}

// ===========================
// Validation: domain sai định dạng → 400
// ===========================

func TestHandler_InvalidDomain_Returns400(t *testing.T) {
	r := realRouter()
	cases := []string{"not-a-domain", "has space.com", "double..dot.com"}
	for _, domain := range cases {
		w := postCSR(t, r, map[string]interface{}{
			"domainName": domain,
			"keyType":    "ecdsa",
			"keySize":    256,
		})
		if w.Code != http.StatusBadRequest {
			t.Errorf("domain %q: mong đợi 400, got %d", domain, w.Code)
		}
	}
}

// ===========================
// Validation: body quá lớn → 400
// ===========================

func TestHandler_OversizedBody_Returns400(t *testing.T) {
	r := realRouter()
	// Tạo body > 64KB
	bigSan := strings.Repeat("a", 70*1024) // 70KB
	req := httptest.NewRequest(http.MethodPost, "/ssl/generator/csr",
		strings.NewReader(`{"domainName":"example.com","keyType":"ecdsa","keySize":256,"organization":"`+bigSan+`"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("mong đợi 400 khi body > 64KB, got %d", w.Code)
	}
}
