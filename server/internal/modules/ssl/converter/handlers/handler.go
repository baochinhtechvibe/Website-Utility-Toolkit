package handlers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"tools.bctechvibe.com/server/internal/modules/ssl/converter/models"
	"tools.bctechvibe.com/server/internal/modules/ssl/converter/service"
	"tools.bctechvibe.com/server/internal/platform/errutil"
	response "tools.bctechvibe.com/server/internal/response"
)

type ConvertHandler struct {
	svc service.ConverterService
}

func NewConvertHandler(svc service.ConverterService) *ConvertHandler {
	return &ConvertHandler{svc: svc}
}

var ErrFileTooLarge = errors.New("File vượt quá kích thước cho phép.")

// readFormFile is a helper to securely read bytes from a multipart file.
// Returns nil if the file is absent or empty.
func readFormFile(c *gin.Context, formKey string) ([]byte, error) {
	file, fileHeader, err := c.Request.FormFile(formKey)
	if err != nil {
		if err == http.ErrMissingFile {
			return nil, nil // Not provided
		}
		return nil, err
	}
	defer file.Close()

	if fileHeader.Size > (512 * 1024) { // 512KB for inputs
		return nil, ErrFileTooLarge
	}

	// Use LimitReader to prevent reading more than 512KB even if fileHeader.Size was spoofed
	limitReader := io.LimitReader(file, 512*1024+1)
	data, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, err
	}

	if len(data) > 512*1024 {
		return nil, ErrFileTooLarge
	}
	return data, nil
}

func (h *ConvertHandler) HandleConvert(c *gin.Context) {
	// Giới hạn tổng dung lượng request trước khi parse — tránh memory pressure
	// (Cert 512KB + Key 512KB + Chain1 512KB + Chain2 512KB + metadata ≈ 2MB)
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 2*1024*1024) // 2MB

	// 1. Phân tích MultiPart Form với max memory 2MB.
	if err := c.Request.ParseMultipartForm(2 << 20); err != nil {
		log.Warn().Err(err).Msg("Failed to parse multipart form for Converter (input quá lớn hoặc sai định dạng)")
		response.Error(c, http.StatusBadRequest, "Dữ liệu kích thước quá lớn hoặc không hợp lệ.")
		return
	}

	// 2. Rút trích Data
	currentFormat := c.PostForm("currentFormat")
	targetFormat := c.PostForm("targetFormat")
	pfxPassword := c.PostForm("pfxPassword")

	// Whitelist an toàn
	validFormats := map[string]bool{
		"pem": true, "der": true, "p7b": true, "pfx": true,
	}

	if !validFormats[currentFormat] || !validFormats[targetFormat] {
		response.Error(c, http.StatusBadRequest, "Định dạng không được hỗ trợ.")
		return
	}
	if currentFormat == targetFormat {
		response.Error(c, http.StatusBadRequest, "Định dạng nguồn và đích phải khác nhau.")
		return
	}

	certBytes, err := readFormFile(c, "certificate")
	if err != nil {
		if err == ErrFileTooLarge {
			response.Error(c, http.StatusBadRequest, "Kích thước Chứng chỉ không được vượt quá 512KB.")
			return
		}
		response.Error(c, http.StatusBadRequest, "Lỗi khi đọc file Chứng chỉ.")
		return
	}
	if len(certBytes) == 0 {
		response.Error(c, http.StatusBadRequest, "Yêu cầu tệp Chứng chỉ bắt buộc.")
		return
	}

	keyBytes, err := readFormFile(c, "privateKey")
	if err != nil {
		log.Warn().Err(err).Msg("Error reading privateKey")
		response.Error(c, http.StatusBadRequest, "Lỗi kích thước/định dạng khi đọc tệp Private Key.")
		return
	}

	chain1Bytes, err := readFormFile(c, "chain1")
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Lỗi kích thước/định dạng khi đọc tệp Chain 1.")
		return
	}

	chain2Bytes, err := readFormFile(c, "chain2")
	if err != nil {
		response.Error(c, http.StatusBadRequest, "Lỗi kích thước/định dạng khi đọc tệp Chain 2.")
		return
	}

	// 3. Mapping Models
	req := &models.ConvertRequest{
		CurrentFormat: currentFormat,
		TargetFormat:  targetFormat,
		Certificate:   certBytes,
		PrivateKey:    keyBytes,
		Chain1:        chain1Bytes,
		Chain2:        chain2Bytes,
		PfxPassword:   pfxPassword,
	}

	// 4. Bọc Context timeout cho cả chu trình
	ctx, cancel := context.WithTimeout(c.Request.Context(), 35*time.Second)
	defer cancel()

	// 5. Gọi Service
	res, err := h.svc.Convert(ctx, req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			response.Error(c, http.StatusGatewayTimeout, errutil.TranslateError(err))
			return
		}

		response.Error(c, http.StatusBadRequest, errutil.TranslateError(err))
		return
	}

	// 6. Trả response chuẩn API kèm Security Headers chống cache
	c.Header("Cache-Control", "no-store, no-cache, max-age=0, must-revalidate")
	c.Header("Pragma", "no-cache")
	response.SuccessNoMeta(c, res)
}
