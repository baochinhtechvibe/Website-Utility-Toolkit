package service

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/ssl/converter/models"
)

type ConverterService interface {
	Convert(ctx context.Context, req *models.ConvertRequest) (*models.ConvertResponse, error)
}

type serviceImpl struct{}

func New() ConverterService {
	return &serviceImpl{}
}

const maxOutputSize = 5 * 1024 * 1024 // 5MB limit for output files

func (s *serviceImpl) Convert(ctx context.Context, req *models.ConvertRequest) (*models.ConvertResponse, error) {
	// Kiểm tra tính hợp lệ của Password nếu đầu vào hoặc đầu ra là PFX
	if (req.TargetFormat == "pfx" || req.CurrentFormat == "pfx") && req.PfxPassword == "" {
		return nil, errors.New("Mật khẩu PFX là bắt buộc để mã hóa/giải mã.")
	}

	// 1. Tạo Context timeout riêng cho OpenSSL (tối đa 30s)
	execCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// 2. Tạo thư mục tạm thời
	tmpDir, err := os.MkdirTemp("", "ssl-converter-*")
	if err != nil {
		log.Error().Err(err).Msg("Failed to create temp directory")
		return nil, errors.New("Không thể cấp phát bộ nhớ tạm.")
	}
	defer os.RemoveAll(tmpDir) // Clean up luôn luôn chạy

	// 3. Ghi file đầu vào với tên cố định an toàn
	certPath := filepath.Join(tmpDir, "cert.in")
	if err := os.WriteFile(certPath, req.Certificate, 0600); err != nil {
		log.Error().Err(err).Msg("WriteFile cert failed")
		return nil, errors.New("Không thể khởi tạo tệp Chứng chỉ trên máy chủ.")
	}

	keyPath := filepath.Join(tmpDir, "key.in")
	if len(req.PrivateKey) > 0 {
		if err := os.WriteFile(keyPath, req.PrivateKey, 0600); err != nil {
			log.Error().Err(err).Msg("WriteFile key failed")
			return nil, errors.New("Không thể khởi tạo tệp Private Key trên máy chủ.")
		}
	}

	// Xử lý các file chain: Gộp chung vào 1 file chain.pem nếu cần bundle (PFX / P7B)
	chainPath := filepath.Join(tmpDir, "chain.in")
	var chainData []byte
	if len(req.Chain1) > 0 {
		chainData = append(chainData, req.Chain1...)
		chainData = append(chainData, '\n')
	}
	if len(req.Chain2) > 0 {
		chainData = append(chainData, req.Chain2...)
		chainData = append(chainData, '\n')
	}
	if len(chainData) > 0 {
		if err := os.WriteFile(chainPath, chainData, 0600); err != nil {
			log.Error().Err(err).Msg("WriteFile chain failed")
			return nil, errors.New("Không thể khởi tạo tệp Chain trên máy chủ.")
		}
	}

	// File chứa PFX password để tránh escape injection trong lệnh
	passPath := filepath.Join(tmpDir, "pass.txt")
	if req.PfxPassword != "" {
		if err := os.WriteFile(passPath, []byte(req.PfxPassword), 0600); err != nil {
			log.Error().Err(err).Msg("WriteFile pass failed")
			// Tránh leak error chi tiết hệ thống
			return nil, errors.New("Không thể khởi tạo tệp Mật khẩu trên máy chủ.")
		}
	}

	// Đường dẫn Ouput
	outPath := filepath.Join(tmpDir, "out.file")
	// Thêm Timestamp cho tên file để user down về không bị trùng
	outFilename := fmt.Sprintf("certificate_%s.%s", time.Now().Format("20060102_150405"), req.TargetFormat)
	contentType := "application/octet-stream"

	// 4. Ma trận cấu hình args cho lệnh OpenSSL
	var args []string

	// currentFormat: pem, der, p7b, pfx
	// targetFormat: pem, der, p7b, pfx
	switch req.CurrentFormat {
	case "pem":
		switch req.TargetFormat {
		case "der":
			args = []string{"x509", "-in", certPath, "-outform", "der", "-out", outPath}
			contentType = "application/x-x509-ca-cert"
		case "p7b":
			// Mặc định OpenSSL cho phép tạo P7B với 1 cert (không cần chain). Mặc định là chain optional.
			args = []string{"crl2pkcs7", "-nocrl", "-certfile", certPath, "-out", outPath}
			if len(chainData) > 0 {
				args = append(args, "-certfile", chainPath)
			}
			contentType = "application/x-pkcs7-certificates"
		case "pfx":
			if len(req.PrivateKey) == 0 {
				return nil, errors.New("Tệp Private Key là bắt buộc khi đóng gói sang định dạng PFX")
			}
			args = []string{"pkcs12", "-export", "-out", outPath, "-in", certPath, "-inkey", keyPath, "-passout", "file:" + passPath}
			if len(chainData) > 0 {
				args = append(args, "-certfile", chainPath)
			}
			contentType = "application/x-pkcs12"
		}
	case "der":
		if req.TargetFormat == "pem" {
			args = []string{"x509", "-inform", "der", "-in", certPath, "-out", outPath}
			contentType = "application/x-pem-file"
		}
	case "pfx":
		if req.TargetFormat == "pem" {
			args = []string{"pkcs12", "-in", certPath, "-out", outPath, "-nodes", "-passin", "file:" + passPath}
			contentType = "application/x-pem-file"
		}
	case "p7b":
		switch req.TargetFormat {
		case "pem":
			args = []string{"pkcs7", "-print_certs", "-in", certPath, "-out", outPath}
			contentType = "application/x-pem-file"
		case "pfx":
			if len(req.PrivateKey) == 0 {
				return nil, errors.New("Tệp Private Key là bắt buộc khi đóng gói sang định dạng PFX")
			}
			// Bước 1: p7b -> pem (lưu ra file trung gian)
			intermediatePath := filepath.Join(tmpDir, "intermediate.pem")
			args1 := []string{"pkcs7", "-print_certs", "-in", certPath, "-out", intermediatePath}
			if err := runOpenSSL(execCtx, args1); err != nil {
				return nil, err
			}
			// Bước 2: chuẩn bị lệnh pem -> pfx từ intermediate
			args = []string{"pkcs12", "-export", "-out", outPath, "-in", intermediatePath, "-inkey", keyPath, "-passout", "file:" + passPath}
			if len(chainData) > 0 {
				args = append(args, "-certfile", chainPath)
			}
			contentType = "application/x-pkcs12"
		}
	}

	if len(args) == 0 {
		return nil, errors.New("Định dạng chuyển đổi không được hỗ trợ (logic branch).")
	}

	// 5. Thực thi OpenSSL an toàn
	if err := runOpenSSL(execCtx, args); err != nil {
		return nil, err
	}

	// 6. Đọc kết quả và kiểm tra kích thước Output
	outBytes, err := os.ReadFile(outPath)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read openssl output mapped file")
		return nil, errors.New("Không thể đọc kết quả đầu ra (Có thể định dạng lỗi).")
	}

	if len(outBytes) > maxOutputSize {
		return nil, errors.New("Tệp chuyển đổi kết quả vượt quá kích thước cho phép (Max 5MB).")
	}

	// 7. Base64 Encode trả về Client (tiết kiệm không gian JSON)
	b64Data := base64.StdEncoding.EncodeToString(outBytes)

	return &models.ConvertResponse{
		Filename:    outFilename,
		Data:        b64Data,
		ContentType: contentType,
	}, nil
}

// runOpenSSL gom nhóm code gọi exec và bắt Stderr của os exec.
func runOpenSSL(ctx context.Context, args []string) error {
	cmd := exec.CommandContext(ctx, "openssl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Capture raw stderr ra log máy chủ để debug.
		// Context Err() != nil gom cả Deadline Exceeded (timeout) và Canceled (bị ngắt).
		if ctx.Err() != nil {
			log.Error().Err(ctx.Err()).Msg("OpenSSL command context cancelled or timed out")
			return errors.New("Quá thời gian xử lý định dạng. Xin thử lại.")
		}

		log.Error().Err(err).Str("stderr", stderr.String()).Msg("openssl command failed")

		// Client thấy câu thông báo thân thiện (tránh lộ thông tin nhạy cảm ở Stderr)
		return errors.New("Không thể xử lý tệp tin chứng chỉ - Vui lòng kiểm tra lại tính hợp lệ và mật khẩu (nếu có).")
	}
	return nil
}
