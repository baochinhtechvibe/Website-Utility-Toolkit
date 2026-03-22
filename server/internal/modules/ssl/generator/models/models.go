package models

// GenerateCSRRequest định nghĩa cấu trúc JSON nhận từ Client cho tính năng khởi tạo CSR Generator.
type GenerateCSRRequest struct {
	DomainName         string   `json:"domainName" validate:"required"`
	// Sans là danh sách tên miền phụ. Client phải gửi dạng JSON array ["www.ex.com"], không gửi comma-separated.
	Sans               []string `json:"sans"` 
	Country            string   `json:"country" validate:"omitempty,len=2"`
	State              string   `json:"state"`
	Locality           string   `json:"locality"`
	Organization       string   `json:"organization"`
	OrganizationalUnit string   `json:"organizationalUnit"`
	KeyType            string   `json:"keyType" validate:"required,oneof=rsa ecdsa"`
	KeySize            int      `json:"keySize" validate:"required,min=1"`
}

// GenerateCSRResponse là cấu trúc phản hồi trả về gồm chuỗi PEM được Base64 thuần túy.
type GenerateCSRResponse struct {
	CSR        string `json:"csr"`
	PrivateKey string `json:"privateKey"`
}
