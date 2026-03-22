// ============================================
// FILE: csr-decoder/models/models.go
//
// Cấu trúc dữ liệu cho CSR Decoder
// ============================================

package models

type DecodeRequest struct {
	CSR string `json:"csr" binding:"required"`
}

type CSRDecodeResponse struct {
	CommonName string `json:"common_name"`

	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	State              []string `json:"state,omitempty"`
	Locality           []string `json:"locality,omitempty"`

	Sans    []string `json:"sans,omitempty"`
	HasSANs bool     `json:"has_sans"`
	
	KeySize   int    `json:"key_size"`
	Algorithm string `json:"algorithm"`
}
