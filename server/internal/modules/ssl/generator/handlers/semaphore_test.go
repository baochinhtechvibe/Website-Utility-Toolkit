// File này nằm trong package "handlers" (không phải handlers_test)
// để có thể truy cập trực tiếp biến package-level csrSemaphore.
package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"tools.bctechvibe.com/server/internal/modules/ssl/generator/service"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func buildRouter() *gin.Engine {
	r := gin.New()
	svc := service.NewGeneratorService()
	h := NewGeneratorHandler(svc)
	r.POST("/ssl/generator/csr", h.GenerateCSR)
	return r
}

func sendCSR(t *testing.T, router *gin.Engine, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/ssl/generator/csr", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestSemaphoreFull_Returns503 lấp đầy semaphore rồi kiểm tra request tiếp theo nhận 503
func TestSemaphoreFull_Returns503(t *testing.T) {
	// Fill toàn bộ semaphore (cap = 5)
	for i := 0; i < cap(csrSemaphore); i++ {
		csrSemaphore <- struct{}{}
	}
	// Đảm bảo drain sau test dù panic hay không
	t.Cleanup(func() {
		for len(csrSemaphore) > 0 {
			<-csrSemaphore
		}
	})

	r := buildRouter()
	w := sendCSR(t, r, map[string]interface{}{
		"domainName": "semaphore-test.com",
		"keyType":    "ecdsa",
		"keySize":    256,
	})

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("mong đợi 503 khi semaphore đầy, got %d: %s", w.Code, w.Body.String())
	}
}
