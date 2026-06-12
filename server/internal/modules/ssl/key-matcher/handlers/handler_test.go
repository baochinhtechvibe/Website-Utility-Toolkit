package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"tools.bctechvibe.com/server/internal/modules/ssl/key-matcher/handlers"
	"tools.bctechvibe.com/server/internal/modules/ssl/key-matcher/models"
	"tools.bctechvibe.com/server/internal/modules/ssl/key-matcher/service"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupRouter() *gin.Engine {
	router := gin.Default()
	handler := handlers.NewKeyMatchHandler(service.New())
	router.POST("/match", handler.HandleKeyMatch)
	return router
}

func TestHandleKeyMatch_ResponseShape(t *testing.T) {
	router := setupRouter()

	// Dùng chuỗi rác để trigger input_errors (đảm bảo code service.Match() trả về SuccessNoMeta với InputErrors)
	reqPayload := models.MatchRequest{
		Type:   "cert_key",
		Input1: "chuoi rác không phải cert",
		Input2: "chuoi rác không phải key",
	}
	body, _ := json.Marshal(reqPayload)

	req, _ := http.NewRequest(http.MethodPost, "/match", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 OK for logical parsing errors, got %v. Body: %s", w.Code, w.Body.String())
	}

	var respBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &respBody)
	if err != nil {
		t.Fatalf("Failed to parse response JSON: %v", err)
	}

	// Kiểm tra chuẩn Wrapper: { success: true, data: { ... } }
	if success, ok := respBody["success"].(bool); !ok || !success {
		t.Errorf("Expected response.success = true, got %v", respBody["success"])
	}

	dataMap, ok := respBody["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected response.data to be an object, got %v", respBody["data"])
	}

	// Kiểm tra trường con bên trong data.input_errors có tồn tại (để Frontend đọc đúng)
	if _, ok := dataMap["input_errors"]; !ok {
		t.Errorf("Expected data.input_errors in response, got missing")
	}
}

func TestHandleKeyMatch_PayloadLimit(t *testing.T) {
	router := setupRouter()

	// Tạo payload 600KB (vượt quá MaxBytesReader 512KB)
	largeInput := strings.Repeat("a", 600*1024)
	reqPayload := models.MatchRequest{
		Type:   "cert_key",
		Input1: largeInput,
		Input2: "short key",
	}
	body, _ := json.Marshal(reqPayload)

	req, _ := http.NewRequest(http.MethodPost, "/match", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// ShouldBindJSON khi gặp MaxBytesReader lỗi sẽ văng 400 Bad Request
	if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected 400 or 413 for payload too large, got %v. Body: %s", w.Code, w.Body.String())
	}
}

func TestHandleKeyMatch_InvalidMatchType(t *testing.T) {
	router := setupRouter()

	reqPayload := models.MatchRequest{
		Type:   "invalid_type",
		Input1: "valid_input",
		Input2: "valid_input",
	}
	body, _ := json.Marshal(reqPayload)

	req, _ := http.NewRequest(http.MethodPost, "/match", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for invalid match type, got %v", w.Code)
	}
}

func TestHandleKeyMatch_MalformedJSON(t *testing.T) {
	router := setupRouter()

	req, _ := http.NewRequest(http.MethodPost, "/match", strings.NewReader("{ invalid_json }"))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400 for malformed JSON, got %v", w.Code)
	}
}
