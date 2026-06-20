package handlers_test

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/handlers"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/models"
	"tools.bctechvibe.com/server/internal/modules/broken-link-scanner/service"
)

func TestHandleScan_URLNormalization(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Hermetic test setup
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><body>OK</body></html>"))
	}))
	defer ts.Close()

	// Mock SSRF checks to allow httptest local URL
	originalCheckHostname := service.CheckSafeHostname
	service.CheckSafeHostname = func(h string) bool { return true }
	defer func() { service.CheckSafeHostname = originalCheckHostname }()

	originalCheckIP := service.CheckSafeIP
	service.CheckSafeIP = func(ip net.IP) bool { return true }
	defer func() { service.CheckSafeIP = originalCheckIP }()

	urlWithoutScheme := strings.TrimPrefix(ts.URL, "https://")

	tests := []struct {
		name         string
		payload      models.ScanRequest
		expectedCode int
	}{
		{
			name: "URL hợp lệ chuẩn",
			payload: models.ScanRequest{
				URL:             ts.URL,
				Scope:           "same-host",
				MaxWorkers:      10,
				IgnoreTlsErrors: true,
				MaxDepth:        2,
				MaxPages:        10,
				MaxLinks:        100,
			},
			expectedCode: http.StatusOK, // Or InternalServerError if target fails, but at least not 400
		},
		{
			name: "URL trần (domain thuần) được thêm http/https",
			payload: models.ScanRequest{
				URL:             urlWithoutScheme,
				Scope:           "same-host",
				MaxWorkers:      10,
				IgnoreTlsErrors: true,
				MaxDepth:        2,
				MaxPages:        10,
				MaxLinks:        100,
			},
			expectedCode: http.StatusOK, // Or InternalServerError, not 400
		},
		{
			name: "URL chứa credentials bị reject",
			payload: models.ScanRequest{
				URL:             "https://user:pass@" + urlWithoutScheme,
				Scope:           "same-host",
				MaxWorkers:      10,
				IgnoreTlsErrors: true,
				MaxDepth:        2,
				MaxPages:        10,
				MaxLinks:        100,
			},
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Mocking request
			body, _ := json.Marshal(tt.payload)
			req, _ := http.NewRequest("POST", "/scan", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			c.Request = req

			handlers.HandleScan(c)

			assert.Equal(t, tt.expectedCode, w.Code)
		})
	}
}
