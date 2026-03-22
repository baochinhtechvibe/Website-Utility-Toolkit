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

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (h *ConvertHandler) HandleConvert(c *gin.Context) {
	// 1. Phân tích MultiPart Form với max memory 20MB.
	if err := c.Request.ParseMultipartForm(20 << 20); err != nil {
		log.Error().Err(err).Msg("Failed to parse multipart form for Converter")
		response.Error(c, http.StatusBadRequest, "Dữ liệu kích thước quá lớn.")
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
			response.Error(c, http.StatusGatewayTimeout, "Quá thời gian xử lý, vui lòng thử lại.")
			return
		}

		// NOTE: Service errors đã được sanitize bằng tiếng Việt. 
		// Khi mở rộng service, đảm bảo mọi error path mới đều trả về message thân thiện, tuyệt đối không chứa OS paths.
		response.Error(c, http.StatusBadRequest, err.Error())
		return
	}

	// 6. Trả response trực tiếp JSON vì payload có cục Base64 lớn.
	c.JSON(http.StatusOK, res)
}
