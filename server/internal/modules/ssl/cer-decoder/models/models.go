// ============================================
// FILE: cer-decoder/models/models.go
//
// Cấu trúc dữ liệu cho CER (Certificate) Decoder
// ============================================

package models

import "time"

type DecodeRequest struct {
	CERT string `json:"cert" binding:"required"`
}

type CERDecodeResponse struct {
	CommonName string `json:"common_name"`

	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Country            []string `json:"country,omitempty"`
	State              []string `json:"state,omitempty"`
	Locality           []string `json:"locality,omitempty"`

	IssuerCommonName   string   `json:"issuer_common_name"`
	IssuerOrganization []string `json:"issuer_organization,omitempty"`

	ValidFrom time.Time `json:"valid_from"`
	ValidTo   time.Time `json:"valid_to"`

	Sans    []string `json:"sans,omitempty"`
	HasSANs bool     `json:"has_sans"`

	KeySize            int    `json:"key_size"`
	Algorithm          string `json:"algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	SerialHex          string `json:"serial_hex"`
	SerialDec          string `json:"serial_dec"`
}
