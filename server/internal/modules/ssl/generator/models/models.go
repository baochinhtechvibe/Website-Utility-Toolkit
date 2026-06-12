package models

// GenerateCSRRequest định nghĩa cấu trúc JSON nhận từ Client cho tính năng khởi tạo CSR Generator.
type GenerateCSRRequest struct {
	DomainName         string   `json:"domainName" validate:"required,max=253"`
	Sans               []string `json:"sans"`
	Country            string   `json:"country" validate:"omitempty,len=2"`
	State              string   `json:"state" validate:"omitempty,max=128"`
	Locality           string   `json:"locality" validate:"omitempty,max=128"`
	Organization       string   `json:"organization" validate:"omitempty,max=256"`
	OrganizationalUnit string   `json:"organizationalUnit" validate:"omitempty,max=256"`
	KeyType            string   `json:"keyType" validate:"required,oneof=rsa ecdsa"`
	KeySize            int      `json:"keySize" validate:"required,min=1"`
}

// GenerateCSRResponse là cấu trúc phản hồi trả về gồm chuỗi PEM được Base64 thuần túy.
type GenerateCSRResponse struct {
	CSR        string `json:"csr"`
	PrivateKey string `json:"privateKey"`
}
