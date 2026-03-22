// ============================================
// FILE: key-matcher/service/service.go
//
// Logic so sánh SSL Key Matcher (Refactored)
// ============================================

package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"tools.bctechvibe.com/server/internal/modules/ssl/key-matcher/models"
)

// inputRole định nghĩa vai trò và PEM types hợp lệ của một input
type inputRole struct {
	Label        string   // Tên tiếng Việt hiển thị trong lỗi
	AllowedTypes []string // PEM block types được chấp nhận
}

// roleMap ánh xạ req.Type → [role input1, role input2]
var roleMap = map[string][2]inputRole{
	"cert_key": {
		{Label: "Private Key", AllowedTypes: []string{"RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY"}},
		{Label: "Certificate", AllowedTypes: []string{"CERTIFICATE"}},
	},
	"csr_cert": {
		{Label: "Certificate Signing Request", AllowedTypes: []string{"CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"}},
		{Label: "Certificate", AllowedTypes: []string{"CERTIFICATE"}},
	},
}

type Service struct{}

func New() *Service { return &Service{} }

func (s *Service) Match(ctx context.Context, req models.MatchRequest) (*models.MatchResponse, error) {
	// Thoát sớm nếu context đã bị huỷ
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	roles, ok := roleMap[req.Type]
	if !ok {
		// Không nên xảy ra nếu handler đã validate trước
		return nil, errors.New("loại đối soát không hợp lệ")
	}

	hash1, keyType, keySize, err1 := s.extractWithRole(req.Input1, roles[0])
	hash2, _, _, err2 := s.extractWithRole(req.Input2, roles[1])

	// Nếu có lỗi parse ở bất kỳ input nào → trả InputErrors
	if err1 != nil || err2 != nil {
		ie := &models.InputErrors{}
		if err1 != nil {
			ie.Input1 = err1.Error()
		}
		if err2 != nil {
			ie.Input2 = err2.Error()
		}
		return &models.MatchResponse{
			Matched:     false,
			Status:      "DỮ LIỆU KHÔNG THỂ XỬ LÝ",
			Message:     "Một hoặc nhiều thành phần bị lỗi, không thể đối soát.",
			InputErrors: ie,
		}, nil
	}

	// Check ctx trước khi trả kết quả
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	if hash1 == hash2 {
		return &models.MatchResponse{
			Matched: true,
			Status:  "KHỚP HOÀN TOÀN",
			Message: fmt.Sprintf("%s và %s hoàn toàn trùng khớp nhau.", roles[0].Label, roles[1].Label),
			Hash1:   hash1,
			Hash2:   hash2,
			KeyType: keyType,
			KeySize: keySize,
		}, nil
	}

	return &models.MatchResponse{
		Matched: false,
		Status:  "KHÔNG KHỚP",
		Message: fmt.Sprintf("%s và %s không thuộc về cùng một cặp khóa.", roles[0].Label, roles[1].Label),
		Hash1:   hash1,
		Hash2:   hash2,
	}, nil
}

// extractWithRole trích xuất public key hash và validate đúng PEM type theo role
func (s *Service) extractWithRole(pemStr string, role inputRole) (string, string, int, error) {
	const maxSize = 100 * 1024
	if len(pemStr) > maxSize {
		return "", "", 0, fmt.Errorf("%s vượt quá kích thước cho phép (tối đa 100KB)", role.Label)
	}

	pemStr = strings.ReplaceAll(pemStr, `\n`, "\n")
	pemStr = strings.ReplaceAll(pemStr, "\r\n", "\n")
	pemStr = strings.TrimSpace(pemStr)

	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", "", 0, fmt.Errorf("%s: không thể đọc khối PEM — dữ liệu có thể bị hỏng hoặc copy không đầy đủ", role.Label)
	}

	// Kiểm tra PEM block type có phù hợp với role không
	if !isAllowedType(block.Type, role.AllowedTypes) {
		actual := friendlyPEMType(block.Type)
		return "", "", 0, fmt.Errorf(
			"%s: nhận được %s — vui lòng kiểm tra lại đã dán đúng ô chưa",
			role.Label, actual,
		)
	}

	pub, err := extractPublicKey(block)
	if err != nil {
		// Log raw error server-side — không đưa error gốc ra client
		log.Warn().Err(err).Str("role", role.Label).Str("pem_type", block.Type).Msg("extractPublicKey failed")
		return "", "", 0, fmt.Errorf("%s: %s", role.Label, friendlyCryptoError(err))
	}

	keyType, keySize := describeKey(pub)

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", 0, fmt.Errorf("%s: không thể trích xuất public key — %s", role.Label, friendlyCryptoError(err))
	}

	hash := sha256.Sum256(der)
	return fmt.Sprintf("%x", hash), keyType, keySize, nil
}

func isAllowedType(blockType string, allowed []string) bool {
	for _, t := range allowed {
		if blockType == t {
			return true
		}
	}
	return false
}

// friendlyPEMType chuyển PEM block type sang tên tiếng Việt dễ hiểu
func friendlyPEMType(t string) string {
	switch t {
	case "CERTIFICATE":
		return "Certificate (chứng chỉ SSL)"
	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		return "CSR (Certificate Signing Request)"
	case "RSA PRIVATE KEY":
		return "RSA Private Key"
	case "EC PRIVATE KEY":
		return "EC Private Key"
	case "PRIVATE KEY":
		return "Private Key (PKCS#8)"
	case "PUBLIC KEY":
		return "Public Key (không hỗ trợ — cần dùng Private Key)"
	default:
		return fmt.Sprintf("'%s' (không được hỗ trợ)", t)
	}
}

// extractPublicKey parse PEM block và trả về public key interface
func extractPublicKey(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil

	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, err
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, fmt.Errorf("chữ ký CSR không hợp lệ: %w", err)
		}
		return csr.PublicKey, nil

	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if err := key.Validate(); err != nil {
			return nil, fmt.Errorf("khóa không hợp lệ về mặt toán học: %w", err)
		}
		return &key.PublicKey, nil

	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return &key.PublicKey, nil

	case "PRIVATE KEY": // PKCS#8
		rawKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		switch k := rawKey.(type) {
		case *rsa.PrivateKey:
			if err := k.Validate(); err != nil {
				return nil, fmt.Errorf("khóa RSA không hợp lệ về mặt toán học: %w", err)
			}
			return &k.PublicKey, nil
		case *ecdsa.PrivateKey:
			return &k.PublicKey, nil
		default:
			return nil, fmt.Errorf("loại Private Key không được hỗ trợ: %T", rawKey)
		}

	default:
		return nil, fmt.Errorf("PEM type '%s' không được hỗ trợ", block.Type)
	}
}

func describeKey(pub interface{}) (string, int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Params().BitSize
	default:
		return "Unknown", 0
	}
}

// friendlyCryptoError dịch lỗi crypto/x509 sang tiếng Việt.
// Dùng errors.As để type-safe trước, fallback sang string matching.
func friendlyCryptoError(err error) string {
	if err == nil {
		return ""
	}

	// Type-safe check trước
	var certErr x509.CertificateInvalidError
	if errors.As(err, &certErr) {
		return "chứng chỉ không hợp lệ hoặc bị hỏng"
	}

	// Fallback string matching cho các lỗi không có type riêng
	msg := err.Error()
	switch {
	case strings.Contains(msg, "asn1"),
		strings.Contains(msg, "malformed"),
		strings.Contains(msg, "structure error"),
		strings.Contains(msg, "truncated"),
		strings.Contains(msg, "trailing data"):
		return "cấu trúc dữ liệu bị hỏng (ASN.1) — có thể do copy thiếu hoặc ký tự bị chèn vào"

	case strings.Contains(msg, "invalid prime"),
		strings.Contains(msg, "toán học"):
		return "khóa bị hỏng về mặt toán học — nội dung khóa không nhất quán"

	case strings.Contains(msg, "pkcs8"), strings.Contains(msg, "PKCS"):
		return "không thể giải mã định dạng PKCS#8 — dữ liệu có thể bị sai hoặc hỏng"

	default:
		// Raw error đã được log ở extractWithRole — trả opaque message cho client
		return "dữ liệu không thể xử lý được — vui lòng kiểm tra lại nội dung"
	}
}
